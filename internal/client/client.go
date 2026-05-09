package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rselbach/rgrok/internal/protocol"
)

type Config struct {
	ServerURL    string
	RequestedID  string
	AuthToken    string
	LocalHost    string
	LocalPort    int
	PreserveHost bool
	MaxBodyBytes int64
	Logger       *slog.Logger
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
		cfg.MaxBodyBytes = 32 << 20
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 2 * time.Minute,
		},
	}
}

func (c *Client) Run() error {
	conn, _, err := websocket.DefaultDialer.Dial(c.cfg.ServerURL, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetReadLimit(c.cfg.MaxBodyBytes + (1 << 20))

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
		return fmt.Errorf("expected tunnel_registered, got %q", registered.Type)
	}

	fmt.Fprintf(os.Stdout, "Connected\nForwarding %s -> %s:%d\n", registered.PublicURL, c.cfg.LocalHost, c.cfg.LocalPort)

	send := make(chan protocol.Message, 64)
	done := make(chan struct{})
	writerErr := make(chan error, 1)
	go writeLoop(conn, send, done, writerErr)

	for {
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
			go c.handleRequest(msg, send)
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
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
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

func (c *Client) handleRequest(msg protocol.Message, send chan<- protocol.Message) {
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
		resp.Error = err.Error()
		send <- resp
		return
	}

	req.Header = cloneHeader(msg.Header)
	removeHopHeaders(req.Header)
	if c.cfg.PreserveHost {
		req.Host = msg.Host
	}

	localResp, err := c.httpClient.Do(req)
	if err != nil {
		resp.Error = err.Error()
		send <- resp
		return
	}
	defer localResp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(localResp.Body, c.cfg.MaxBodyBytes+1))
	if err != nil {
		resp.Error = err.Error()
		send <- resp
		return
	}
	if int64(len(body)) > c.cfg.MaxBodyBytes {
		resp.Error = "local response body too large"
		send <- resp
		return
	}

	resp.StatusCode = localResp.StatusCode
	resp.Header = cloneHeader(localResp.Header)
	removeHopHeaders(resp.Header)
	resp.Body = body
	send <- resp
}

var hopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for key, values := range h {
		cp := make([]string, len(values))
		copy(cp, values)
		out[key] = cp
	}
	return out
}

func removeHopHeaders(h http.Header) {
	for key := range hopHeaders {
		h.Del(key)
	}
}
