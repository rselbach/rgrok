package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rselbach/rgrok/internal/protocol"
)

type Config struct {
	Addr         string
	Domain       string
	PublicScheme string
	ConnectPath  string
	AuthToken    string
	MaxBodyBytes int64
	Logger       *slog.Logger
}

type Server struct {
	cfg Config

	mu      sync.RWMutex
	tunnels map[string]*tunnel

	nextStream atomic.Uint64
}

type tunnel struct {
	id        string
	host      string
	publicURL string
	conn      *websocket.Conn
	send      chan protocol.Message
	done      chan struct{}

	pendingMu sync.Mutex
	pending   map[uint64]chan protocol.Message
}

var (
	nameRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	hopHeaders = map[string]struct{}{
		"Connection":          {},
		"Keep-Alive":          {},
		"Proxy-Authenticate":  {},
		"Proxy-Authorization": {},
		"Te":                  {},
		"Trailer":             {},
		"Transfer-Encoding":   {},
		"Upgrade":             {},
	}
)

func New(cfg Config) *Server {
	if cfg.Addr == "" {
		cfg.Addr = ":7000"
	}
	if cfg.Domain == "" {
		cfg.Domain = "localhost:7000"
	}
	if cfg.PublicScheme == "" {
		cfg.PublicScheme = "http"
	}
	if cfg.ConnectPath == "" {
		cfg.ConnectPath = "/api/connect"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 32 << 20
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	cfg.Domain = strings.TrimPrefix(strings.TrimPrefix(cfg.Domain, "https://"), "http://")
	cfg.Domain = strings.TrimRight(cfg.Domain, "/")

	return &Server{
		cfg:     cfg,
		tunnels: make(map[string]*tunnel),
	}
}

func (s *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.ConnectPath, s.handleConnect)
	mux.HandleFunc("/", s.handlePublic)

	s.cfg.Logger.Info("rgrok server listening", "addr", s.cfg.Addr, "domain", s.cfg.Domain, "connect_path", s.cfg.ConnectPath)
	return http.ListenAndServe(s.cfg.Addr, mux)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.cfg.Logger.Warn("websocket upgrade failed", "err", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(s.cfg.MaxBodyBytes + (1 << 20))

	var reg protocol.Message
	if err := conn.ReadJSON(&reg); err != nil {
		s.cfg.Logger.Warn("registration read failed", "err", err)
		return
	}
	if reg.Type != protocol.TypeRegisterTunnel {
		writeClose(conn, websocket.CloseProtocolError, "expected register_tunnel")
		return
	}
	if !s.validToken(reg.AuthToken) {
		writeClose(conn, websocket.ClosePolicyViolation, "invalid auth token")
		return
	}

	id, err := s.chooseID(reg.RequestedID)
	if err != nil {
		writeClose(conn, websocket.ClosePolicyViolation, err.Error())
		return
	}

	host := id + "." + s.cfg.Domain
	t := &tunnel{
		id:        id,
		host:      host,
		publicURL: s.cfg.PublicScheme + "://" + host,
		conn:      conn,
		send:      make(chan protocol.Message, 64),
		done:      make(chan struct{}),
		pending:   make(map[uint64]chan protocol.Message),
	}

	if err := s.registerTunnel(t); err != nil {
		writeClose(conn, websocket.ClosePolicyViolation, err.Error())
		return
	}
	defer s.unregisterTunnel(t)

	s.cfg.Logger.Info("tunnel connected", "id", t.id, "host", t.host, "local_port", reg.LocalPort)

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		t.writeLoop()
	}()

	t.send <- protocol.Message{
		Type:      protocol.TypeTunnelRegistered,
		TunnelID:  t.id,
		PublicURL: t.publicURL,
	}

	for {
		var msg protocol.Message
		if err := conn.ReadJSON(&msg); err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				s.cfg.Logger.Warn("tunnel read failed", "id", t.id, "err", err)
			}
			break
		}
		switch msg.Type {
		case protocol.TypeResponse:
			t.dispatch(msg)
		case protocol.TypePong:
		default:
			s.cfg.Logger.Debug("ignoring tunnel message", "id", t.id, "type", msg.Type)
		}
	}

	close(t.done)
	t.failPending()
	<-writerDone
	s.cfg.Logger.Info("tunnel disconnected", "id", t.id)
}

func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == s.cfg.ConnectPath {
		http.NotFound(w, r)
		return
	}

	t := s.tunnelForHost(r.Host)
	if t == nil {
		s.writeIndexOrNotFound(w, r)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	defer r.Body.Close()

	streamID := s.nextStream.Add(1)
	respCh := t.addPending(streamID)
	defer t.removePending(streamID)

	headers := cloneHeader(r.Header)
	removeHopHeaders(headers)
	addForwardedHeaders(headers, r)

	req := protocol.Message{
		Type:     protocol.TypeRequest,
		StreamID: streamID,
		Method:   r.Method,
		Path:     r.URL.RequestURI(),
		Host:     r.Host,
		Scheme:   schemeFromRequest(r),
		Header:   headers,
		Body:     body,
	}

	select {
	case t.send <- req:
	case <-t.done:
		http.Error(w, "tunnel disconnected", http.StatusBadGateway)
		return
	case <-r.Context().Done():
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	var resp protocol.Message
	select {
	case resp = <-respCh:
	case <-t.done:
		http.Error(w, "tunnel disconnected", http.StatusBadGateway)
		return
	case <-ctx.Done():
		http.Error(w, "tunnel response timed out", http.StatusGatewayTimeout)
		return
	}

	if resp.Error != "" {
		http.Error(w, resp.Error, http.StatusBadGateway)
		return
	}

	respHeaders := cloneHeader(resp.Header)
	removeHopHeaders(respHeaders)
	for key, values := range respHeaders {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	status := resp.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(resp.Body)
}

func (s *Server) tunnelForHost(host string) *tunnel {
	host = strings.ToLower(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t := s.tunnels[host]; t != nil {
		return t
	}
	if withoutPort, _, err := net.SplitHostPort(host); err == nil {
		return s.tunnels[withoutPort]
	}
	return nil
}

func (s *Server) writeIndexOrNotFound(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if host != strings.ToLower(s.cfg.Domain) {
		if withoutPort, _, err := net.SplitHostPort(host); err == nil && withoutPort == strings.ToLower(s.cfg.Domain) {
			host = withoutPort
		}
	}
	if host != strings.ToLower(s.cfg.Domain) {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "Nothing to see here. The tunnels are doing tunnel things elsewhere.")
}

func (s *Server) validToken(token string) bool {
	if s.cfg.AuthToken == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.AuthToken)) == 1
}

func (s *Server) chooseID(requested string) (string, error) {
	if requested != "" {
		requested = strings.ToLower(requested)
		if !nameRE.MatchString(requested) {
			return "", errors.New("requested name must contain lowercase letters, numbers, or hyphens")
		}
		host := requested + "." + s.cfg.Domain
		s.mu.RLock()
		_, exists := s.tunnels[strings.ToLower(host)]
		s.mu.RUnlock()
		if exists {
			return "", fmt.Errorf("requested name %q is already connected", requested)
		}
		return requested, nil
	}

	for i := 0; i < 10; i++ {
		id := randomID()
		host := id + "." + s.cfg.Domain
		s.mu.RLock()
		_, exists := s.tunnels[strings.ToLower(host)]
		s.mu.RUnlock()
		if !exists {
			return id, nil
		}
	}
	return "", errors.New("could not allocate tunnel id")
}

func (s *Server) registerTunnel(t *tunnel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(t.host)
	if _, exists := s.tunnels[key]; exists {
		return fmt.Errorf("host %q is already connected", t.host)
	}
	s.tunnels[key] = t
	return nil
}

func (s *Server) unregisterTunnel(t *tunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tunnels, strings.ToLower(t.host))
}

func (t *tunnel) writeLoop() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case msg := <-t.send:
			_ = t.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := t.conn.WriteJSON(msg); err != nil {
				_ = t.conn.Close()
				return
			}
		case <-ticker.C:
			_ = t.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := t.conn.WriteJSON(protocol.Message{Type: protocol.TypePing}); err != nil {
				_ = t.conn.Close()
				return
			}
		case <-t.done:
			_ = t.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_ = t.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye"))
			return
		}
	}
}

func (t *tunnel) addPending(streamID uint64) chan protocol.Message {
	ch := make(chan protocol.Message, 1)
	t.pendingMu.Lock()
	t.pending[streamID] = ch
	t.pendingMu.Unlock()
	return ch
}

func (t *tunnel) removePending(streamID uint64) {
	t.pendingMu.Lock()
	delete(t.pending, streamID)
	t.pendingMu.Unlock()
}

func (t *tunnel) dispatch(msg protocol.Message) {
	t.pendingMu.Lock()
	ch := t.pending[msg.StreamID]
	t.pendingMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- msg:
	default:
	}
}

func (t *tunnel) failPending() {
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()
	for streamID, ch := range t.pending {
		ch <- protocol.Message{
			Type:     protocol.TypeResponse,
			StreamID: streamID,
			Error:    "tunnel disconnected",
		}
		delete(t.pending, streamID)
	}
}

func randomID() string {
	adjectives := []string{
		"airconditioned",
		"blanket",
		"campus",
		"chicken",
		"cosmic",
		"deans",
		"dreamatorium",
		"greendale",
		"human",
		"paintball",
		"pillow",
		"remedial",
		"study",
	}
	nouns := []string{
		"annex",
		"beetle",
		"changnesia",
		"dean",
		"diorama",
		"inspector",
		"meowmeow",
		"pelton",
		"popper",
		"room",
		"timeline",
		"troy",
		"winger",
	}
	suffixes := []string{
		"club",
		"college",
		"committee",
		"fort",
		"group",
		"heist",
		"night",
		"party",
		"quest",
		"semester",
		"table",
		"year",
	}

	name := strings.Join([]string{
		randomChoice(adjectives),
		randomChoice(nouns),
		randomChoice(suffixes),
	}, "-")
	if nameRE.MatchString(name) {
		return name
	}
	return fmt.Sprintf("greendale-%d", time.Now().UnixNano())
}

func randomChoice(values []string) string {
	if len(values) == 0 {
		return ""
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(values))))
	if err != nil {
		return values[time.Now().UnixNano()%int64(len(values))]
	}
	return values[n.Int64()]
}

func writeClose(conn *websocket.Conn, code int, text string) {
	_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(code, text))
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

func addForwardedHeaders(h http.Header, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if prior := h.Get("X-Forwarded-For"); prior != "" {
		h.Set("X-Forwarded-For", prior+", "+host)
	} else {
		h.Set("X-Forwarded-For", host)
	}
	h.Set("X-Forwarded-Host", r.Host)
	h.Set("X-Forwarded-Proto", schemeFromRequest(r))
}

func schemeFromRequest(r *http.Request) string {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
