package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rselbach/rgrok/internal/auth"
	"github.com/rselbach/rgrok/internal/httputil"
	"github.com/rselbach/rgrok/internal/protocol"
)

const (
	maxBodyBytesDefault   = 32 << 20
	pingInterval          = 25 * time.Second
	writeTimeout          = 10 * time.Second
	closeWriteTimeout     = 2 * time.Second
	tunnelResponseTimeout = 2 * time.Minute
	maxRandomIDAttempts   = 10
	readLimitOverhead     = 1 << 20
	sendChannelSize       = 64
)

type Config struct {
	Addr               string
	Domain             string
	PublicScheme       string
	ConnectPath        string
	DataPath           string
	GitHubClientID     string
	GitHubClientSecret string
	MaxBodyBytes       int64
	Logger             *slog.Logger
	ShutdownTimeout    time.Duration
	MaxTunnelsPerUser  int
}

type Server struct {
	cfg    Config
	store  *Store
	github auth.GitHubClient

	mu           sync.RWMutex
	tunnels      map[string]*tunnel
	deviceLogins map[string]*deviceLogin

	nextStream atomic.Uint64
}

type deviceLogin struct {
	ID         string
	DeviceCode string
	ExpiresAt  time.Time
	Interval   int
	LastPoll   time.Time
}

type tunnel struct {
	id        string
	host      string
	publicURL string
	owner     string
	conn      *websocket.Conn
	send      chan protocol.Message
	done      chan struct{}

	pendingMu sync.Mutex
	pending   map[uint64]chan protocol.Message
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func New(cfg Config) (*Server, error) {
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
	if cfg.DataPath == "" {
		cfg.DataPath = "rgrok.json"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = maxBodyBytesDefault
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	cfg.Domain = strings.TrimPrefix(strings.TrimPrefix(cfg.Domain, "https://"), "http://")
	cfg.Domain = strings.TrimRight(cfg.Domain, "/")

	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}
	if cfg.MaxTunnelsPerUser <= 0 {
		cfg.MaxTunnelsPerUser = 5
	}

	store, err := OpenStore(cfg.DataPath)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:          cfg,
		store:        store,
		github:       auth.GitHubClient{ClientID: cfg.GitHubClientID, ClientSecret: cfg.GitHubClientSecret},
		tunnels:      make(map[string]*tunnel),
		deviceLogins: make(map[string]*deviceLogin),
	}, nil
}

func (s *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.ConnectPath, s.baseHostOnly(s.handleConnect))
	mux.HandleFunc("/api/login/device/start", s.baseHostOnly(s.handleDeviceLoginStart))
	mux.HandleFunc("/api/login/device/poll", s.baseHostOnly(s.handleDeviceLoginPoll))
	mux.HandleFunc("/login/github", s.baseHostOnly(s.handleGitHubLogin))
	mux.HandleFunc("/auth/github/callback", s.baseHostOnly(s.handleGitHubCallback))
	mux.HandleFunc("/logout", s.baseHostOnly(s.handleLogout))
	mux.HandleFunc("/dashboard", s.baseHostOnly(s.handleDashboard))
	mux.HandleFunc("/dashboard/tunnels", s.baseHostOnly(s.handleDashboardTunnels))
	mux.HandleFunc("/dashboard/users/add", s.baseHostOnly(s.requirePost(s.handleAddUser)))
	mux.HandleFunc("/dashboard/users/delete", s.baseHostOnly(s.requirePost(s.handleDeleteUser)))
	mux.HandleFunc("/dashboard/tunnels/disconnect", s.baseHostOnly(s.requirePost(s.handleDisconnectTunnel)))
	mux.HandleFunc("/", s.handlePublic)

	handler := s.securityHeaders(s.logRequest(mux))

	srv := &http.Server{
		Addr:           s.cfg.Addr,
		Handler:        handler,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   tunnelResponseTimeout + 10*time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	s.cfg.Logger.Info("rgrok server listening", "addr", s.cfg.Addr, "domain", s.cfg.Domain, "connect_path", s.cfg.ConnectPath)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		s.cfg.Logger.Info("shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			s.cfg.Logger.Error("shutdown failed", "err", err)
			return err
		}
		s.cfg.Logger.Info("shutdown complete")
		return nil
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *responseWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.status = code
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (s *Server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w}
		next.ServeHTTP(rw, r)
		s.cfg.Logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"status", rw.status,
			"duration", time.Since(start),
		)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) baseHostOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameHost(r.Host, s.cfg.Domain) {
			s.handlePublic(w, r)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			origin = strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
			return sameHost(origin, s.cfg.Domain)
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.cfg.Logger.Warn("websocket upgrade failed", "err", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(s.cfg.MaxBodyBytes + readLimitOverhead)

	var reg protocol.Message
	if err := conn.ReadJSON(&reg); err != nil {
		s.cfg.Logger.Warn("registration read failed", "err", err)
		return
	}
	if reg.Type != protocol.TypeRegisterTunnel {
		writeClose(conn, websocket.CloseProtocolError, "expected register_tunnel")
		return
	}

	clientToken, ok := s.store.ClientToken(reg.AuthToken)
	if !ok {
		writeClose(conn, websocket.ClosePolicyViolation, "invalid rgrok login token")
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
		owner:     clientToken.Login,
		conn:      conn,
		send:      make(chan protocol.Message, sendChannelSize),
		done:      make(chan struct{}),
		pending:   make(map[uint64]chan protocol.Message),
	}

	if err := s.registerTunnel(t); err != nil {
		writeClose(conn, websocket.ClosePolicyViolation, err.Error())
		return
	}
	defer s.unregisterTunnel(t)

	s.cfg.Logger.Info("tunnel connected", "id", t.id, "host", t.host, "owner", t.owner, "local_port", reg.LocalPort)

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
	if r.URL.Path == s.cfg.ConnectPath && sameHost(r.Host, s.cfg.Domain) {
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

	headers := httputil.CloneHeader(r.Header)
	httputil.RemoveHopHeaders(headers)
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

	ctx, cancel := context.WithTimeout(r.Context(), tunnelResponseTimeout)
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

	respHeaders := httputil.CloneHeader(resp.Header)
	httputil.RemoveHopHeaders(respHeaders)
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
	if !sameHost(host, s.cfg.Domain) {
		http.NotFound(w, r)
		return
	}

	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if _, ok := s.store.Session(cookie.Value); ok {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		clearCookie(w, sessionCookieName, s.cfg.PublicScheme == "https")
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'")
	_ = landingTemplate.Execute(w, nil)
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

	for i := 0; i < maxRandomIDAttempts; i++ {
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

func (s *Server) countUserTunnels(login string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, t := range s.tunnels {
		if t.owner == login {
			count++
		}
	}
	return count
}

func (s *Server) registerTunnel(t *tunnel) error {
	if s.countUserTunnels(t.owner) >= s.cfg.MaxTunnelsPerUser {
		return fmt.Errorf("maximum number of tunnels (%d) reached for user %s", s.cfg.MaxTunnelsPerUser, t.owner)
	}

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
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case msg := <-t.send:
			_ = t.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := t.conn.WriteJSON(msg); err != nil {
				_ = t.conn.Close()
				return
			}
		case <-ticker.C:
			_ = t.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := t.conn.WriteJSON(protocol.Message{Type: protocol.TypePing}); err != nil {
				_ = t.conn.Close()
				return
			}
		case <-t.done:
			_ = t.conn.SetWriteDeadline(time.Now().Add(closeWriteTimeout))
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

func sameHost(a, b string) bool {
	a = strings.ToLower(a)
	b = strings.ToLower(b)
	if a == b {
		return true
	}
	if withoutPort, _, err := net.SplitHostPort(a); err == nil {
		return withoutPort == b
	}
	return false
}

var landingTemplate = template.Must(template.New("landing").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rgrok</title>
<style>
:root {
  color-scheme: light;
  --bg: #ffffff;
  --bg-soft: #f9fafb;
  --text: #1f2328;
  --text-strong: #0c0c0d;
  --muted: #6b7280;
  --accent: #1563ff;
  --accent-strong: #1051d8;
  --accent-soft: #e7eeff;
  --warn-text: #92400e;
  --warn-soft: #fef6e6;
  --line: #e5e7eb;
  --line-strong: #d1d5db;
  --radius: 8px;
  --radius-lg: 12px;
  --shadow: 0 1px 3px rgba(15, 23, 42, 0.08), 0 4px 12px rgba(15, 23, 42, 0.05);
  --shadow-lg: 0 20px 50px rgba(15, 23, 42, 0.12);
}
*, *::before, *::after { box-sizing: border-box; }
html, body { min-height: 100%; }
body {
  margin: 0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif;
  background: var(--bg-soft);
  color: var(--text);
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.card {
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: var(--radius-lg);
  padding: 48px;
  max-width: 440px;
  width: calc(100% - 48px);
  text-align: center;
  box-shadow: var(--shadow-lg);
}

.brand {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  margin-bottom: 24px;
}
.brand svg { color: var(--accent); }
.brand-name {
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text-strong);
  letter-spacing: -0.02em;
}

.tagline {
  color: var(--muted);
  margin: 0 0 32px;
  font-size: 1rem;
}

.notice {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 14px;
  border-radius: var(--radius);
  background: var(--warn-soft);
  border: 1px solid rgba(146, 64, 14, 0.15);
  color: var(--warn-text);
  font-size: 13px;
  line-height: 1.5;
  text-align: left;
  margin-bottom: 28px;
}
.notice svg { flex: 0 0 auto; margin-top: 1px; }
.notice strong { color: var(--warn-text); }

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  min-height: 40px;
  padding: 0 20px;
  border-radius: var(--radius);
  border: 1px solid var(--accent);
  background: var(--accent);
  color: #fff;
  text-decoration: none;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  transition: background 0.15s, border-color 0.15s;
}
.btn:hover {
  background: var(--accent-strong);
  border-color: var(--accent-strong);
  text-decoration: none;
}
.btn svg { width: 18px; height: 18px; }
</style>
</head>
<body>
<div class="card">
  <div class="brand">
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
    </svg>
    <span class="brand-name">rgrok</span>
  </div>
  <p class="tagline">Public tunnels for private ports.</p>
  <div class="notice">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
      <path d="M12 9v4"/>
      <path d="M12 17h.01"/>
    </svg>
    <span><strong>Private service.</strong> Only whitelisted GitHub accounts can sign in. If your account is not on the whitelist, access will be denied even after authorization.</span>
  </div>
  <a class="btn" href="/login/github">
    <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
    Sign in with GitHub
  </a>
</div>
</body>
</html>`))
