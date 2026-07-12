package server

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/json"
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
	maxBodyBytesDefault         = protocol.MaxBodyBytesDefault
	pingInterval                = 25 * time.Second
	registrationTimeout         = 30 * time.Second
	tunnelReadTimeout           = 3 * pingInterval
	writeTimeout                = 10 * time.Second
	closeWriteTimeout           = 2 * time.Second
	tunnelResponseTimeout       = 2 * time.Minute
	maxRandomIDAttempts         = 10
	readLimitOverhead           = 1 << 20
	sendChannelSize             = 64
	maxRequestsPerTunnelDefault = 64
	maxDeviceLogins             = 100
	deviceLoginRateLimit        = 10 * time.Second
	deviceLoginSweepInterval    = 1 * time.Minute
)

type Config struct {
	Addr                 string
	Domain               string
	PublicScheme         string
	ConnectPath          string
	DataPath             string
	GitHubClientID       string
	GitHubClientSecret   string
	MaxBodyBytes         int64
	Logger               *slog.Logger
	ShutdownTimeout      time.Duration
	MaxTunnelsPerUser    int
	MaxRequestsPerTunnel int
	BehindProxy          bool
	TrustedProxyCIDRs    []string
}

type Server struct {
	cfg              Config
	store            *Store
	github           auth.GitHubClient
	trustedProxyNets []*net.IPNet

	mu              sync.RWMutex
	tunnels         map[string]*tunnel
	deviceLogins    map[string]*deviceLogin
	deviceLoginLast map[string]time.Time

	nextStream    atomic.Uint64
	requestsTotal atomic.Uint64
	tunnelsActive atomic.Int64
	tunnelsTotal  atomic.Uint64
}

type deviceLogin struct {
	ID         string
	DeviceCode string
	ClientIP   string
	ExpiresAt  time.Time
	Interval   int
	LastPoll   time.Time
}

type tunnel struct {
	id                   string
	host                 string
	publicURL            string
	owner                string
	localPort            int
	connectedAt          time.Time
	requests             atomic.Int64
	applicationProfileID string
	instanceID           string
	routes               []StoredApplicationRoute
	rateLimiter          *applicationRateLimiter
	conn                 *websocket.Conn
	send                 chan protocol.Message
	done                 chan struct{}
	requestSlots         chan struct{}

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
	if cfg.PublicScheme == "https" || cfg.BehindProxy {
		cfg.PublicScheme = "https"
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
	trustedProxyNets, err := parseTrustedProxyCIDRs(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	cfg.Domain = strings.TrimPrefix(strings.TrimPrefix(cfg.Domain, "https://"), "http://")
	cfg.Domain = strings.TrimRight(cfg.Domain, "/")

	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}
	if cfg.MaxTunnelsPerUser <= 0 {
		cfg.MaxTunnelsPerUser = 5
	}
	if cfg.MaxRequestsPerTunnel <= 0 {
		cfg.MaxRequestsPerTunnel = maxRequestsPerTunnelDefault
	}

	store, err := OpenStore(cfg.DataPath)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:              cfg,
		store:            store,
		github:           auth.GitHubClient{ClientID: cfg.GitHubClientID, ClientSecret: cfg.GitHubClientSecret},
		trustedProxyNets: trustedProxyNets,
		tunnels:          make(map[string]*tunnel),
		deviceLogins:     make(map[string]*deviceLogin),
		deviceLoginLast:  make(map[string]time.Time),
	}, nil
}

func (s *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/ready", s.handleReady)
	mux.HandleFunc("/api/metrics", s.baseHostOnly(s.handleMetrics))
	mux.HandleFunc(s.cfg.ConnectPath, s.baseHostOnly(s.handleConnect))
	mux.HandleFunc("/api/login/device/start", s.baseHostOnly(s.handleDeviceLoginStart))
	mux.HandleFunc("/api/login/device/poll", s.baseHostOnly(s.handleDeviceLoginPoll))
	mux.HandleFunc("/login/github", s.baseHostOnly(s.handleGitHubLogin))
	mux.HandleFunc("/auth/github/callback", s.baseHostOnly(s.handleGitHubCallback))
	mux.HandleFunc("/logout", s.baseHostOnly(s.handleLogout))
	mux.HandleFunc("/dashboard", s.baseHostOnly(s.handleDashboard))
	mux.HandleFunc("/dashboard/app.js", s.baseHostOnly(s.handleDashboardJS))
	mux.HandleFunc("/dashboard/tunnels", s.baseHostOnly(s.handleDashboardTunnels))
	mux.HandleFunc("/dashboard/api-tokens/create", s.baseHostOnly(s.requirePost(s.handleCreateAPIToken)))
	mux.HandleFunc("/dashboard/api-tokens/delete", s.baseHostOnly(s.requirePost(s.handleDeleteAPIToken)))
	mux.HandleFunc("/dashboard/applications/create", s.baseHostOnly(s.requirePost(s.handleCreateApplication)))
	mux.HandleFunc("/dashboard/applications/update", s.baseHostOnly(s.requirePost(s.handleUpdateApplication)))
	mux.HandleFunc("/dashboard/applications/delete", s.baseHostOnly(s.requirePost(s.handleDeleteApplication)))
	mux.HandleFunc("/dashboard/applications/reservations/delete", s.baseHostOnly(s.requirePost(s.handleUnreserveApplicationTunnel)))
	mux.HandleFunc("/dashboard/users/add", s.baseHostOnly(s.requirePost(s.handleAddUser)))
	mux.HandleFunc("/dashboard/users/delete", s.baseHostOnly(s.requirePost(s.handleDeleteUser)))
	mux.HandleFunc("/dashboard/tunnels/disconnect", s.baseHostOnly(s.requirePost(s.handleDisconnectTunnel)))
	mux.HandleFunc("/dashboard/sessions/revoke", s.baseHostOnly(s.requirePost(s.handleRevokeSessions)))
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

	go s.sweepDeviceLoginsLoop()

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

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	return h.Hijack()
}

func (w *responseWriter) Flush() {
	f, ok := w.ResponseWriter.(http.Flusher)
	if ok {
		f.Flush()
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"requests_total": s.requestsTotal.Load(),
		"tunnels_active": s.tunnelsActive.Load(),
		"tunnels_total":  s.tunnelsTotal.Load(),
	})
}

func (s *Server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w}
		next.ServeHTTP(rw, r)
		s.requestsTotal.Add(1)
		s.cfg.Logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"status", rw.status,
			"duration", time.Since(start),
		)
	})
}

func (s *Server) cookieSecure() bool {
	return s.cfg.PublicScheme == "https" || s.cfg.BehindProxy
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
		if s.cfg.PublicScheme == "https" || s.cfg.BehindProxy {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
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

	// Bound the whole registration handshake, including the application
	// challenge exchange, so unauthenticated connections cannot idle.
	_ = conn.SetReadDeadline(time.Now().Add(registrationTimeout))

	var reg protocol.Message
	if err := conn.ReadJSON(&reg); err != nil {
		s.cfg.Logger.Warn("registration read failed", "err", err)
		return
	}
	if reg.Type != protocol.TypeRegisterTunnel {
		writeClose(conn, websocket.CloseProtocolError, "expected register_tunnel")
		return
	}

	owner, profile, err := s.authenticateTunnelRegistration(conn, reg)
	if err != nil {
		writeClose(conn, websocket.ClosePolicyViolation, err.Error())
		return
	}

	var id string
	if profile == nil {
		id, err = s.chooseID(reg.RequestedID)
	} else {
		id, err = s.chooseApplicationID(profile.ID, reg.InstanceID)
	}
	if err != nil {
		writeClose(conn, websocket.ClosePolicyViolation, err.Error())
		return
	}

	host := id + "." + s.cfg.Domain
	t := &tunnel{
		id:          id,
		host:        host,
		publicURL:   s.cfg.PublicScheme + "://" + host,
		owner:       owner,
		localPort:   reg.LocalPort,
		connectedAt: time.Now().UTC(),
		conn:        conn,
		send:        make(chan protocol.Message, sendChannelSize),
		done:        make(chan struct{}),
		pending:     make(map[uint64]chan protocol.Message),
	}
	if profile == nil {
		t.requestSlots = make(chan struct{}, s.maxRequestsPerTunnel())
	} else {
		t.applicationProfileID = profile.ID
		t.instanceID = reg.InstanceID
		t.routes = profile.Routes
		t.rateLimiter = newApplicationRateLimiter(profile.RequestsPerMinute, profile.RequestBurst)
		t.requestSlots = make(chan struct{}, profile.ConcurrentRequests)
	}

	if err := s.registerTunnel(t); err != nil {
		writeClose(conn, websocket.ClosePolicyViolation, err.Error())
		return
	}
	if profile != nil {
		if err := s.store.RememberApplicationTunnel(profile.ID, reg.InstanceID, id); err != nil {
			s.unregisterTunnel(t)
			writeClose(conn, websocket.CloseInternalServerErr, "could not remember application tunnel")
			return
		}
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

	// The client answers every ping, so a healthy tunnel delivers a message
	// at least once per ping interval; refreshing the read deadline on each
	// message tears down dead connections instead of holding their names.
	for {
		_ = conn.SetReadDeadline(time.Now().Add(tunnelReadTimeout))
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
	if t.applicationProfileID != "" {
		if !applicationRequestAllowed(t.routes, r) {
			http.NotFound(w, r)
			return
		}
		if !t.rateLimiter.allow() {
			http.Error(w, "tunnel rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}
	if !t.acquireRequestSlot() {
		status := http.StatusServiceUnavailable
		if t.applicationProfileID != "" {
			status = http.StatusTooManyRequests
		}
		http.Error(w, "tunnel busy", status)
		return
	}
	defer t.releaseRequestSlot()
	t.requests.Add(1)

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
	s.addForwardedHeaders(headers, r)

	req := protocol.Message{
		Type:     protocol.TypeRequest,
		StreamID: streamID,
		Method:   r.Method,
		Path:     r.URL.RequestURI(),
		Host:     r.Host,
		Scheme:   s.schemeFromRequest(r),
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

func (s *Server) authenticateTunnelRegistration(conn *websocket.Conn, reg protocol.Message) (string, *StoredApplicationProfile, error) {
	if reg.AuthToken != "" {
		if reg.ApplicationProfileID != "" || reg.InstanceID != "" {
			return "", nil, errors.New("registration cannot use both token and application authentication")
		}
		clientToken, ok := s.store.ClientToken(reg.AuthToken)
		if !ok {
			return "", nil, errors.New("invalid rgrok login token")
		}
		return clientToken.Login, nil, nil
	}
	if reg.RequestedID != "" {
		return "", nil, errors.New("application tunnels cannot request a name")
	}
	if !applicationIDRE.MatchString(reg.ApplicationProfileID) || !instanceIDRE.MatchString(reg.InstanceID) {
		return "", nil, errors.New("invalid application profile or instance id")
	}
	profile, ok := s.store.ApplicationProfile(reg.ApplicationProfileID)
	if !ok {
		return "", nil, errors.New("invalid application profile")
	}
	challenge, err := randomHex(32)
	if err != nil {
		return "", nil, errors.New("could not create application challenge")
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := conn.WriteJSON(protocol.Message{
		Type:      protocol.TypeApplicationChallenge,
		Challenge: challenge,
	}); err != nil {
		return "", nil, fmt.Errorf("write application challenge: %w", err)
	}
	var response protocol.Message
	if err := conn.ReadJSON(&response); err != nil {
		return "", nil, fmt.Errorf("read application signature: %w", err)
	}
	if response.Type != protocol.TypeApplicationSignature {
		return "", nil, errors.New("expected application signature")
	}
	_, publicKey, _, err := parseEd25519PublicKey(profile.PublicKey)
	if err != nil {
		return "", nil, errors.New("application profile has an invalid public key")
	}
	payload := protocol.ApplicationChallengePayload(profile.ID, reg.InstanceID, challenge)
	if !ed25519.Verify(publicKey, payload, response.Signature) {
		return "", nil, errors.New("invalid application signature")
	}
	return "application:" + profile.Name, &profile, nil
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
		clearCookie(w, sessionCookieName, s.cookieSecure())
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

func (s *Server) chooseApplicationID(profileID, instanceID string) (string, error) {
	s.mu.RLock()
	for _, existing := range s.tunnels {
		if existing.applicationProfileID == profileID && existing.instanceID == instanceID {
			s.mu.RUnlock()
			return "", errors.New("application instance already has an active tunnel")
		}
	}
	s.mu.RUnlock()

	remembered := s.store.ApplicationTunnelID(profileID, instanceID)
	if remembered != "" {
		host := remembered + "." + s.cfg.Domain
		s.mu.RLock()
		_, exists := s.tunnels[strings.ToLower(host)]
		s.mu.RUnlock()
		if !exists {
			return remembered, nil
		}
	}
	return s.chooseID("")
}

func (s *Server) maxRequestsPerTunnel() int {
	if s.cfg.MaxRequestsPerTunnel > 0 {
		return s.cfg.MaxRequestsPerTunnel
	}
	return maxRequestsPerTunnelDefault
}

func (s *Server) registerTunnel(t *tunnel) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, existing := range s.tunnels {
		if t.applicationProfileID != "" && existing.applicationProfileID == t.applicationProfileID && existing.instanceID == t.instanceID {
			return errors.New("application instance already has an active tunnel")
		}
		if t.applicationProfileID != "" && existing.applicationProfileID == t.applicationProfileID {
			count++
			continue
		}
		if t.applicationProfileID == "" && existing.owner == t.owner {
			count++
		}
	}
	if count >= s.cfg.MaxTunnelsPerUser {
		return fmt.Errorf("maximum number of tunnels (%d) reached for user %s", s.cfg.MaxTunnelsPerUser, t.owner)
	}

	if t.requestSlots == nil {
		t.requestSlots = make(chan struct{}, s.maxRequestsPerTunnel())
	}

	key := strings.ToLower(t.host)
	if _, exists := s.tunnels[key]; exists {
		return fmt.Errorf("host %q is already connected", t.host)
	}
	s.tunnels[key] = t
	s.tunnelsActive.Add(1)
	s.tunnelsTotal.Add(1)
	return nil
}

func (s *Server) unregisterTunnel(t *tunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tunnels, strings.ToLower(t.host))
	s.tunnelsActive.Add(-1)
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

func (t *tunnel) acquireRequestSlot() bool {
	select {
	case t.requestSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (t *tunnel) releaseRequestSlot() {
	select {
	case <-t.requestSlots:
	default:
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
		msg := protocol.Message{
			Type:     protocol.TypeResponse,
			StreamID: streamID,
			Error:    "tunnel disconnected",
		}
		select {
		case ch <- msg:
		default:
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
	return name
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

// clientIP returns the address of the closest untrusted hop. Behind a
// trusted proxy that is the rightmost X-Forwarded-For entry not itself a
// trusted proxy; leftmost entries are client-supplied and spoofable.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !s.requestFromTrustedProxy(r) {
		return host
	}
	entries := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(entries) - 1; i >= 0; i-- {
		entry := strings.TrimSpace(entries[i])
		if entry == "" {
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return host
		}
		if !s.trustedProxyIP(ip) {
			return entry
		}
	}
	return host
}

func (s *Server) addForwardedHeaders(h http.Header, r *http.Request) {
	h.Del("X-Forwarded-For")
	h.Del("X-Forwarded-Host")
	h.Del("X-Forwarded-Proto")

	h.Set("X-Forwarded-For", s.clientIP(r))
	h.Set("X-Forwarded-Host", r.Host)
	h.Set("X-Forwarded-Proto", s.schemeFromRequest(r))
}

func (s *Server) schemeFromRequest(r *http.Request) string {
	if s.requestFromTrustedProxy(r) {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			return proto
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func parseTrustedProxyCIDRs(raw []string) ([]*net.IPNet, error) {
	if len(raw) == 0 {
		raw = []string{"127.0.0.0/8", "::1/128"}
	}
	nets := make([]*net.IPNet, 0, len(raw))
	for _, value := range raw {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			_, ipNet, err := net.ParseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", part, err)
			}
			nets = append(nets, ipNet)
		}
	}
	return nets, nil
}

func (s *Server) requestFromTrustedProxy(r *http.Request) bool {
	if !s.cfg.BehindProxy {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return s.trustedProxyIP(ip)
}

func (s *Server) trustedProxyIP(ip net.IP) bool {
	for _, ipNet := range s.trustedProxyNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
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

//go:embed templates/landing.html
var landingHTML string

var landingTemplate = template.Must(template.New("landing").Parse(landingHTML))
