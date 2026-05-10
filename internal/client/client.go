package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rselbach/rgrok/internal/httputil"
	"github.com/rselbach/rgrok/internal/protocol"
)

const (
	maxBodyBytesDefault = 32 << 20
	writeTimeout        = 10 * time.Second
	httpClientTimeout   = 2 * time.Minute
	readLimitOverhead   = 1 << 20
	sendChannelSize     = 64
)

type Config struct {
	ServerURL        string
	RequestedID      string
	AuthToken        string
	LocalHost        string
	LocalPort        int
	PreserveHost     bool
	MaxBodyBytes     int64
	Logger           *slog.Logger
	ReconnectTimeout time.Duration
}

type Client struct {
	cfg        Config
	httpClient *http.Client
}

func New(cfg Config) *Client {
	if cfg.ServerURL == "" {
		cfg.ServerURL = "ws://localhost:7000/api/connect"
	}
	if cfg.LocalHost == "" {
		cfg.LocalHost = "127.0.0.1"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = maxBodyBytesDefault
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ReconnectTimeout <= 0 {
		cfg.ReconnectTimeout = 30 * time.Second
	}

	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: httpClientTimeout,
		},
	}
}

var errTerminal = errors.New("terminal error")

func isTerminal(err error) bool {
	if errors.Is(err, errTerminal) {
		return true
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		switch closeErr.Code {
		case websocket.ClosePolicyViolation:
			return true
		}
	}
	return false
}

// Run connects to the rgrok server and forwards requests until the context is
// cancelled or a fatal error occurs. It automatically reconnects with
// exponential backoff on disconnect.
func (c *Client) Run(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	backoff := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := c.runOnce(ctx)
		if err == nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if isTerminal(err) {
			return fmt.Errorf("tunnel closed: %w", err)
		}

		backoff = nextBackoff(backoff, c.cfg.ReconnectTimeout)
		c.cfg.Logger.Info("disconnected, reconnecting", "error", err, "backoff", backoff)

		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

func nextBackoff(current, max time.Duration) time.Duration {
	if current == 0 {
		return time.Second
	}
	next := current * 2
	if next > max {
		return max
	}
	return next
}

func (c *Client) runOnce(ctx context.Context) error {
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, c.cfg.ServerURL, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetReadLimit(c.cfg.MaxBodyBytes + readLimitOverhead)

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-childCtx.Done()
		conn.Close()
	}()

	if err := conn.WriteJSON(protocol.Message{
		Type:        protocol.TypeRegisterTunnel,
		RequestedID: c.cfg.RequestedID,
		AuthToken:   c.cfg.AuthToken,
		LocalPort:   c.cfg.LocalPort,
	}); err != nil {
		return err
	}

	var registered protocol.Message
	if err := conn.ReadJSON(&registered); err != nil {
		return err
	}
	if registered.Type != protocol.TypeTunnelRegistered {
		return fmt.Errorf("%w: expected tunnel_registered, got %q", errTerminal, registered.Type)
	}

	fmt.Fprintf(os.Stdout, "Connected\nForwarding %s -> %s:%d\n", registered.PublicURL, c.cfg.LocalHost, c.cfg.LocalPort)

	send := make(chan protocol.Message, sendChannelSize)
	done := make(chan struct{})
	writerErr := make(chan error, 1)
	go writeLoop(conn, send, done, writerErr)

	for {
		select {
		case <-ctx.Done():
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(5*time.Second))
			close(done)
			return ctx.Err()
		default:
		}

		var msg protocol.Message
		if err := conn.ReadJSON(&msg); err != nil {
			close(done)
			select {
			case werr := <-writerErr:
				if werr != nil {
					return werr
				}
			default:
			}
			return err
		}

		switch msg.Type {
		case protocol.TypeRequest:
			go c.handleRequest(msg, send, done)
		case protocol.TypePing:
			select {
			case send <- protocol.Message{Type: protocol.TypePong}:
			case <-done:
			}
		default:
			c.cfg.Logger.Debug("ignoring server message", "type", msg.Type)
		}
	}
}

func writeLoop(conn *websocket.Conn, send <-chan protocol.Message, done <-chan struct{}, errCh chan<- error) {
	for {
		select {
		case msg := <-send:
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := conn.WriteJSON(msg); err != nil {
				errCh <- err
				_ = conn.Close()
				return
			}
		case <-done:
			return
		}
	}
}

func (c *Client) handleRequest(msg protocol.Message, send chan<- protocol.Message, done <-chan struct{}) {
	resp := protocol.Message{
		Type:     protocol.TypeResponse,
		StreamID: msg.StreamID,
	}

	localURL := "http://" + c.cfg.LocalHost + ":" + strconv.Itoa(c.cfg.LocalPort)
	path := msg.Path
	if path == "" {
		path = "/"
	}

	req, err := http.NewRequestWithContext(context.Background(), msg.Method, localURL+path, bytes.NewReader(msg.Body))
	if err != nil {
		c.cfg.Logger.Warn("local forward failed", "error", err)
		resp.Error = "failed to reach local application"
		select {
		case send <- resp:
		case <-done:
		}
		return
	}

	req.Header = httputil.CloneHeader(msg.Header)
	httputil.RemoveHopHeaders(req.Header)
	if c.cfg.PreserveHost {
		req.Host = msg.Host
	}

	localResp, err := c.httpClient.Do(req)
	if err != nil {
		c.cfg.Logger.Warn("local forward failed", "error", err)
		resp.Error = "failed to reach local application"
		select {
		case send <- resp:
		case <-done:
		}
		return
	}
	defer localResp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(localResp.Body, c.cfg.MaxBodyBytes+1))
	if err != nil {
		c.cfg.Logger.Warn("local forward failed", "error", err)
		resp.Error = "failed to read local response"
		select {
		case send <- resp:
		case <-done:
		}
		return
	}
	if int64(len(body)) > c.cfg.MaxBodyBytes {
		resp.Error = "local response body too large"
		select {
		case send <- resp:
		case <-done:
		}
		return
	}

	resp.StatusCode = localResp.StatusCode
	resp.Header = httputil.CloneHeader(localResp.Header)
	httputil.RemoveHopHeaders(resp.Header)
	resp.Body = body
	select {
	case send <- resp:
	case <-done:
	}
}
