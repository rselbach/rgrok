package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rselbach/rgrok/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestRandomIDIsCommunityPhrase(t *testing.T) {
	for range 100 {
		id := randomID()
		if !nameRE.MatchString(id) {
			t.Fatalf("randomID generated invalid DNS label %q", id)
		}
		if strings.Count(id, "-") < 2 {
			t.Fatalf("randomID should be a hyphenated phrase, got %q", id)
		}
	}
}

func TestLandingPage(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
		},
		store:   store,
		tunnels: make(map[string]*tunnel),
	}

	// Unauthenticated request should return landing page HTML.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "localhost:7000"
	rec := httptest.NewRecorder()
	s.writeIndexOrNotFound(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, "Sign in with GitHub")
	r.Contains(body, `href="/login/github"`)

	// Authenticated request should redirect to dashboard.
	session, err := store.CreateSession("troy", false)
	r.NoError(err)

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Host = "localhost:7000"
	req2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	rec2 := httptest.NewRecorder()
	s.writeIndexOrNotFound(rec2, req2)

	r.Equal(http.StatusFound, rec2.Code)
	r.Equal("/dashboard", rec2.Header().Get("Location"))

	// Expired/invalid cookie should be cleared and landing page shown.
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Host = "localhost:7000"
	req3.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "invalid-token"})
	rec3 := httptest.NewRecorder()
	s.writeIndexOrNotFound(rec3, req3)

	r.Equal(http.StatusOK, rec3.Code)
	var cleared bool
	for _, c := range rec3.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge == -1 {
			cleared = true
			break
		}
	}
	r.True(cleared, "expected invalid session cookie to be cleared")
}

func TestOriginCheck_Passes(t *testing.T) {
	r := require.New(t)

	s, err := New(Config{
		Addr:         "127.0.0.1:0",
		Domain:       "localhost:7000",
		PublicScheme: "http",
		DataPath:     t.TempDir() + "/test.json",
	})
	r.NoError(err)

	tests := map[string]struct {
		origin     string
		wantAccept bool
	}{
		"matching origin with http scheme": {
			origin:     "http://localhost:7000",
			wantAccept: true,
		},
		"matching origin with https scheme": {
			origin:     "https://localhost:7000",
			wantAccept: true,
		},
		"bad origin": {
			origin:     "https://evil.com",
			wantAccept: false,
		},
		"empty origin": {
			origin:     "",
			wantAccept: true,
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(s.handleConnect))
	defer srv.Close()

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
			dialer := websocket.Dialer{}
			headers := http.Header{}
			if tc.origin != "" {
				headers.Set("Origin", tc.origin)
			}
			conn, resp, err := dialer.Dial(wsURL, headers)
			if tc.wantAccept {
				r.NoError(err)
				if conn != nil {
					_ = conn.Close()
				}
				return
			}
			r.Error(err)
			r.NotNil(resp)
			r.Equal(http.StatusForbidden, resp.StatusCode)
		})
	}
}

func TestMaxTunnelsPerUser(t *testing.T) {
	r := require.New(t)

	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:            "localhost:7000",
			PublicScheme:      "http",
			MaxTunnelsPerUser: 2,
		},
		store:   store,
		tunnels: make(map[string]*tunnel),
	}

	login := "abed"

	r.NoError(s.registerTunnel(&tunnel{id: "t1", host: "t1.localhost:7000", owner: login}))
	r.NoError(s.registerTunnel(&tunnel{id: "t2", host: "t2.localhost:7000", owner: login}))

	err = s.registerTunnel(&tunnel{id: "t3", host: "t3.localhost:7000", owner: login})
	r.Error(err)
	r.Contains(err.Error(), "maximum number of tunnels")

	r.NoError(s.registerTunnel(&tunnel{id: "t4", host: "t4.localhost:7000", owner: "troy"}))
}

func TestTunnelRequestSlots(t *testing.T) {
	r := require.New(t)
	tun := &tunnel{requestSlots: make(chan struct{}, 1)}

	r.True(tun.acquireRequestSlot())
	r.False(tun.acquireRequestSlot())
	tun.releaseRequestSlot()
	r.True(tun.acquireRequestSlot())
}

func TestHandlePublicRejectsWhenTunnelBusy(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	tun := &tunnel{
		id:           "demo",
		host:         "demo.localhost:7000",
		requestSlots: make(chan struct{}, 1),
	}
	r.True(tun.acquireRequestSlot())

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store: store,
		tunnels: map[string]*tunnel{
			"demo.localhost:7000": tun,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://demo.localhost:7000/", nil)
	req.Host = "demo.localhost:7000"
	rec := httptest.NewRecorder()

	s.handlePublic(rec, req)
	r.Equal(http.StatusServiceUnavailable, rec.Code)
	r.Contains(rec.Body.String(), "tunnel busy")
}

func TestFailPendingDoesNotBlockWhenResponseQueued(t *testing.T) {
	r := require.New(t)

	ch := make(chan protocol.Message, 1)
	ch <- protocol.Message{Type: protocol.TypeResponse, StreamID: 1, StatusCode: http.StatusOK}
	tun := &tunnel{
		pending: map[uint64]chan protocol.Message{1: ch},
	}

	done := make(chan struct{})
	go func() {
		tun.failPending()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failPending blocked on a full response channel")
	}

	r.Empty(tun.pending)
}

func TestDeviceLoginReturnsSnapshot(t *testing.T) {
	r := require.New(t)
	s := &Server{
		deviceLogins: map[string]*deviceLogin{
			"login-id": {
				ID:        "login-id",
				ExpiresAt: time.Now().UTC().Add(time.Hour),
				Interval:  5,
			},
		},
	}

	login, ok := s.deviceLogin("login-id")
	r.True(ok)
	login.Interval = 99

	s.mu.Lock()
	stored := s.deviceLogins["login-id"].Interval
	s.mu.Unlock()
	r.Equal(5, stored)
}

func TestDashboardMutationsRequirePostAndCSRF(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store:   store,
		tunnels: make(map[string]*tunnel),
	}

	r.NoError(store.UpsertUser("abed", true))
	session, err := store.CreateSession("abed", true)
	r.NoError(err)

	// Compose the same middleware stack used in production routes.
	handler := s.baseHostOnly(s.requirePost(s.handleAddUser))

	run := func(method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/dashboard/users/add", strings.NewReader(body))
		req.Host = "localhost:7000"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// GET -> 405 Method Not Allowed
	rec := run(http.MethodGet, "login=troy&admin=on")
	r.Equal(http.StatusMethodNotAllowed, rec.Code)

	// POST without csrf_token -> 403 Forbidden
	rec = run(http.MethodPost, "login=troy&admin=on")
	r.Equal(http.StatusForbidden, rec.Code)

	// POST with wrong csrf_token -> 403 Forbidden
	rec = run(http.MethodPost, "login=troy&admin=on&csrf_token=bad")
	r.Equal(http.StatusForbidden, rec.Code)

	// POST with correct csrf_token -> 302 Redirect
	rec = run(http.MethodPost, "login=troy&admin=on&csrf_token="+session.CSRFToken)
	r.Equal(http.StatusFound, rec.Code)
	r.Equal("/dashboard", rec.Header().Get("Location"))

	// Verify user was actually created.
	user, ok := store.IsAllowed("troy")
	r.True(ok)
	r.True(user.Admin)
}

func TestDashboardRejectsSessionMissingCSRFToken(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store: store,
	}

	session := StoredSession{
		ID:        "legacy-session",
		Login:     "abed",
		Admin:     true,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/users/add", strings.NewReader("login=troy"))
	req.Host = "localhost:7000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	ok := s.requireCSRF(rec, req, session)
	r.False(ok)
	r.Equal(http.StatusForbidden, rec.Code)
}

func TestDashboardCreateAPIToken(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store:   store,
		tunnels: make(map[string]*tunnel),
	}

	r.NoError(store.UpsertUser("abed", false))
	session, err := store.CreateSession("abed", false)
	r.NoError(err)

	body := "csrf_token=" + session.CSRFToken + "&name=workstation&expires_in_days=30"
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api-tokens/create", strings.NewReader(body))
	req.Host = "localhost:7000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	rec := httptest.NewRecorder()

	s.requirePost(s.handleCreateAPIToken).ServeHTTP(rec, req)
	r.Equal(http.StatusOK, rec.Code)
	r.Contains(rec.Body.String(), "RGROK_API_TOKEN")
	tokenMatch := regexp.MustCompile(`id="created-api-token" type="text" readonly value="([^"]+)"`).FindStringSubmatch(rec.Body.String())
	r.Len(tokenMatch, 2)
	plainToken := tokenMatch[1]
	r.NotEmpty(plainToken)

	store.mu.Lock()
	r.Len(store.data.ClientTokens, 1)
	var created StoredClientToken
	for _, token := range store.data.ClientTokens {
		created = token
	}
	store.mu.Unlock()

	r.Equal("abed", created.Login)
	r.Equal("workstation", created.Name)
	r.Empty(created.PlainToken)
	r.NotEmpty(created.TokenHash)
	r.Empty(created.Token)
	r.WithinDuration(time.Now().UTC().Add(30*24*time.Hour), created.ExpiresAt, time.Minute)

	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Host = "localhost:7000"
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	rec = httptest.NewRecorder()
	s.handleDashboard(rec, req)
	r.Equal(http.StatusOK, rec.Code)
	r.Contains(rec.Body.String(), "workstation")
	r.NotContains(rec.Body.String(), plainToken)
}

func TestDashboardCreateAPITokenRejectsLongExpiry(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store: store,
	}

	r.NoError(store.UpsertUser("abed", false))
	session, err := store.CreateSession("abed", false)
	r.NoError(err)

	body := "csrf_token=" + session.CSRFToken + "&name=workstation&expires_in_days=365"
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api-tokens/create", strings.NewReader(body))
	req.Host = "localhost:7000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	rec := httptest.NewRecorder()

	s.requirePost(s.handleCreateAPIToken).ServeHTTP(rec, req)
	r.Equal(http.StatusBadRequest, rec.Code)

	store.mu.Lock()
	r.Empty(store.data.ClientTokens)
	store.mu.Unlock()
}

func TestDashboardDeleteAPIToken(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store: store,
	}

	r.NoError(store.UpsertUser("abed", false))
	session, err := store.CreateSession("abed", false)
	r.NoError(err)
	token, err := store.CreateClientTokenWithNameAndLifetime("abed", false, "workstation", 30*24*time.Hour)
	r.NoError(err)

	body := "csrf_token=" + session.CSRFToken + "&token_hash=" + token.TokenHash
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api-tokens/delete", strings.NewReader(body))
	req.Host = "localhost:7000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	rec := httptest.NewRecorder()

	s.requirePost(s.handleDeleteAPIToken).ServeHTTP(rec, req)
	r.Equal(http.StatusFound, rec.Code)
	r.Equal("/dashboard#api-tokens", rec.Header().Get("Location"))

	_, ok := store.ClientToken(token.PlainToken)
	r.False(ok)
}

func TestDashboardDeleteAPITokenRejectsOtherUserToken(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store: store,
	}

	r.NoError(store.UpsertUser("abed", false))
	session, err := store.CreateSession("abed", false)
	r.NoError(err)
	token, err := store.CreateClientTokenWithNameAndLifetime("troy", false, "deploy", 30*24*time.Hour)
	r.NoError(err)

	body := "csrf_token=" + session.CSRFToken + "&token_hash=" + token.TokenHash
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api-tokens/delete", strings.NewReader(body))
	req.Host = "localhost:7000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	rec := httptest.NewRecorder()

	s.requirePost(s.handleDeleteAPIToken).ServeHTTP(rec, req)
	r.Equal(http.StatusNotFound, rec.Code)

	_, ok := store.ClientToken(token.PlainToken)
	r.True(ok)
}

func TestSchemeFromRequest(t *testing.T) {
	tests := map[string]struct {
		behindProxy bool
		tls         bool
		fwdProto    string
		want        string
	}{
		"direct http":                    {behindProxy: false, tls: false, fwdProto: "", want: "http"},
		"direct https":                   {behindProxy: false, tls: true, fwdProto: "", want: "https"},
		"direct ignores forwarded proto": {behindProxy: false, tls: false, fwdProto: "https", want: "http"},
		"behind proxy trusts forwarded proto from loopback": {behindProxy: true, tls: false, fwdProto: "https", want: "https"},
		"behind proxy falls back to remote":                 {behindProxy: true, tls: true, fwdProto: "", want: "https"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			s := &Server{cfg: Config{BehindProxy: tc.behindProxy}}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.behindProxy {
				req.RemoteAddr = "127.0.0.1:12345"
				nets, err := parseTrustedProxyCIDRs(nil)
				r.NoError(err)
				s.trustedProxyNets = nets
			}
			if tc.fwdProto != "" {
				req.Header.Set("X-Forwarded-Proto", tc.fwdProto)
			}
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}

			r.Equal(tc.want, s.schemeFromRequest(req))
		})
	}
}

func TestAddForwardedHeadersStripsUntrusted(t *testing.T) {
	r := require.New(t)

	s := &Server{cfg: Config{BehindProxy: false}}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "evil.com")

	h := make(http.Header)
	h.Set("X-Forwarded-For", "5.6.7.8")
	s.addForwardedHeaders(h, req)

	// The original spoofed header on h should be replaced.
	r.Equal("192.0.2.1", h.Get("X-Forwarded-For"))
	r.Equal("example.com", h.Get("X-Forwarded-Host"))
	r.Equal("http", h.Get("X-Forwarded-Proto"))
}

func TestAddForwardedHeadersTrustsProxy(t *testing.T) {
	r := require.New(t)

	s := &Server{cfg: Config{BehindProxy: true}}
	var err error
	s.trustedProxyNets, err = parseTrustedProxyCIDRs(nil)
	r.NoError(err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	req.Header.Set("X-Forwarded-Proto", "https")

	h := make(http.Header)
	s.addForwardedHeaders(h, req)

	r.Equal("203.0.113.1", h.Get("X-Forwarded-For"))
	r.Equal("https", h.Get("X-Forwarded-Proto"))
}

func TestAddForwardedHeadersRejectsUntrustedProxyHeaders(t *testing.T) {
	r := require.New(t)

	s := &Server{cfg: Config{BehindProxy: true}}
	s.trustedProxyNets = []*net.IPNet{}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	req.Header.Set("X-Forwarded-Proto", "https")

	h := make(http.Header)
	s.addForwardedHeaders(h, req)

	r.Equal("198.51.100.10", h.Get("X-Forwarded-For"))
	r.Equal("http", h.Get("X-Forwarded-Proto"))
}

func TestClientIPIgnoresSpoofedForwardedPrefix(t *testing.T) {
	r := require.New(t)

	s := &Server{cfg: Config{BehindProxy: true}}
	var err error
	s.trustedProxyNets, err = parseTrustedProxyCIDRs(nil)
	r.NoError(err)

	tests := map[string]struct {
		forwarded string
		want      string
	}{
		"spoofed prefix":        {forwarded: "6.6.6.6, 203.0.113.1", want: "203.0.113.1"},
		"chained trusted proxy": {forwarded: "6.6.6.6, 203.0.113.1, 127.0.0.2", want: "203.0.113.1"},
		"single entry":          {forwarded: "203.0.113.1", want: "203.0.113.1"},
		"all trusted":           {forwarded: "127.0.0.2", want: "127.0.0.1"},
		"unparsable entry":      {forwarded: "not-an-ip", want: "127.0.0.1"},
		"empty header":          {forwarded: "", want: "127.0.0.1"},
		"spoofed then garbage":  {forwarded: "6.6.6.6, not-an-ip, 127.0.0.2", want: "127.0.0.1"},
		"whitespace only entry": {forwarded: " , 203.0.113.1", want: "203.0.113.1"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "127.0.0.1:12345"
			if tc.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tc.forwarded)
			}
			r.Equal(tc.want, s.clientIP(req))
		})
	}
}

func TestAddForwardedHeadersDropsSpoofedPrefix(t *testing.T) {
	r := require.New(t)

	s := &Server{cfg: Config{BehindProxy: true}}
	var err error
	s.trustedProxyNets, err = parseTrustedProxyCIDRs(nil)
	r.NoError(err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.1")

	h := make(http.Header)
	s.addForwardedHeaders(h, req)

	r.Equal("203.0.113.1", h.Get("X-Forwarded-For"))
}

func TestSecurityHeadersWithHSTS(t *testing.T) {
	r := require.New(t)

	s := &Server{cfg: Config{PublicScheme: "https", BehindProxy: false, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	r.NotEmpty(rec.Header().Get("Strict-Transport-Security"))
	r.NotEmpty(rec.Header().Get("Permissions-Policy"))
}

func TestCookieSecureBehindProxy(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			BehindProxy:  true,
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store: store,
	}

	r.NoError(store.UpsertUser("abed", false))
	session, err := store.CreateSession("abed", false)
	r.NoError(err)

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.Host = "localhost:7000"
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	rec := httptest.NewRecorder()

	s.handleLogout(rec, req)

	// When behind proxy, cookies should be Secure even if PublicScheme is http.
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			found = true
			r.True(c.Secure)
		}
	}
	r.True(found, "expected session cookie to be cleared with Secure flag")
}

func TestClientTokenExpiry(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	token, err := store.CreateClientToken("abed", false)
	r.NoError(err)
	r.False(token.ExpiresAt.IsZero())

	// Fresh token is valid.
	ct, ok := store.ClientToken(token.PlainToken)
	r.True(ok)
	r.Equal("abed", ct.Login)

	// Manually expire the token in the store.
	store.mu.Lock()
	expired := store.data.ClientTokens[token.TokenHash]
	expired.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	store.data.ClientTokens[token.TokenHash] = expired
	store.mu.Unlock()

	_, ok = store.ClientToken(token.PlainToken)
	r.False(ok, "expired token should be rejected")
}

func TestRevokeSessions(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store: store,
	}

	r.NoError(store.UpsertUser("abed", false))
	token1, err := store.CreateClientToken("abed", false)
	r.NoError(err)
	token2, err := store.CreateClientToken("abed", false)
	r.NoError(err)
	token3, err := store.CreateClientToken("troy", false)
	r.NoError(err)

	session, err := store.CreateSession("abed", false)
	r.NoError(err)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/sessions/revoke", strings.NewReader("csrf_token="+session.CSRFToken))
	req.Host = "localhost:7000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	rec := httptest.NewRecorder()

	s.handleRevokeSessions(rec, req)
	r.Equal(http.StatusFound, rec.Code)

	// abed's tokens should be gone.
	_, ok := store.ClientToken(token1.PlainToken)
	r.False(ok)
	_, ok = store.ClientToken(token2.PlainToken)
	r.False(ok)

	// troy's token should remain.
	_, ok = store.ClientToken(token3.PlainToken)
	r.True(ok)

	// Session should be deleted too.
	_, ok = store.Session(session.ID)
	r.False(ok)
}

func TestDeviceLoginRateLimit(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store:           store,
		tunnels:         make(map[string]*tunnel),
		deviceLogins:    make(map[string]*deviceLogin),
		deviceLoginLast: make(map[string]time.Time),
	}

	// Manually record a recent attempt from the test request's IP.
	// httptest.NewRequest uses 192.0.2.1 as the default RemoteAddr.
	s.deviceLoginLast["192.0.2.1"] = time.Now().UTC()

	req := httptest.NewRequest(http.MethodPost, "/api/login/device/start", nil)
	req.Host = "localhost:7000"
	rec := httptest.NewRecorder()
	s.handleDeviceLoginStart(rec, req)
	r.Equal(http.StatusTooManyRequests, rec.Code)
}

func TestDeviceLoginGlobalCap(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store:           store,
		tunnels:         make(map[string]*tunnel),
		deviceLogins:    make(map[string]*deviceLogin),
		deviceLoginLast: make(map[string]time.Time),
	}

	// Fill to capacity.
	for i := range maxDeviceLogins {
		key := fmt.Sprintf("login-%d", i)
		s.deviceLogins[key] = &deviceLogin{
			ID:        key,
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/login/device/start", nil)
	req.Host = "localhost:7000"
	rec := httptest.NewRecorder()
	s.handleDeviceLoginStart(rec, req)
	r.Equal(http.StatusTooManyRequests, rec.Code)
}

func TestDeviceLoginSweeper(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store:           store,
		tunnels:         make(map[string]*tunnel),
		deviceLogins:    make(map[string]*deviceLogin),
		deviceLoginLast: make(map[string]time.Time),
	}

	s.deviceLogins["expired"] = &deviceLogin{
		ID:        "expired",
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}
	s.deviceLoginLast["1.2.3.4"] = time.Now().UTC().Add(-time.Hour)

	s.sweepExpiredDeviceLogins()

	_, ok := s.deviceLogins["expired"]
	r.False(ok)
	r.Empty(s.deviceLoginLast)
}

func TestTemplatesParse(t *testing.T) {
	r := require.New(t)
	r.NotNil(landingTemplate)
	r.NotNil(dashboardTemplate)
	r.NotNil(tunnelTablePartial)
}

func TestProtocolTypesUnified(t *testing.T) {
	// Ensure the server and client packages use protocol.DeviceStartResponse
	// and protocol.DevicePollResponse by verifying they compile correctly.
	_ = protocol.DeviceStartResponse{ID: "test"}
	_ = protocol.DevicePollResponse{Status: "pending"}
}

func TestResponseWriterImplementsHijackerAndFlusher(t *testing.T) {
	r := require.New(t)

	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec}

	_, ok := interface{}(rw).(http.Hijacker)
	r.True(ok, "responseWriter should implement http.Hijacker")

	_, ok = interface{}(rw).(http.Flusher)
	r.True(ok, "responseWriter should implement http.Flusher")
}

func TestRandomIDIsAlwaysValid(t *testing.T) {
	for range 200 {
		id := randomID()
		if !nameRE.MatchString(id) {
			t.Fatalf("randomID generated invalid DNS label %q", id)
		}
	}
}

func TestEndToEndTunnel(t *testing.T) {
	r := require.New(t)

	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:            "localhost:7000",
			PublicScheme:      "http",
			MaxTunnelsPerUser: 5,
			Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store:   store,
		tunnels: make(map[string]*tunnel),
	}

	// Create a user and client token.
	r.NoError(store.UpsertUser("abed", false))
	ct, err := store.CreateClientToken("abed", false)
	r.NoError(err)

	// Start the server in the background.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/connect" {
			s.handleConnect(w, req)
			return
		}
		s.handlePublic(w, req)
	}))
	defer srv.Close()

	// Dial the WebSocket.
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/connect"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	r.NoError(err)
	defer conn.Close()

	// Register the tunnel.
	err = conn.WriteJSON(struct {
		Type        string `json:"type"`
		RequestedID string `json:"requested_id"`
		AuthToken   string `json:"auth_token"`
		LocalPort   int    `json:"local_port"`
	}{
		Type:      "register_tunnel",
		AuthToken: ct.PlainToken,
		LocalPort: 1234,
	})
	r.NoError(err)

	var reg struct {
		Type      string `json:"type"`
		TunnelID  string `json:"tunnel_id"`
		PublicURL string `json:"public_url"`
	}
	err = conn.ReadJSON(&reg)
	r.NoError(err)
	r.Equal("tunnel_registered", reg.Type)
	r.NotEmpty(reg.TunnelID)
	r.NotEmpty(reg.PublicURL)

	// Run the tunnel message loop in the background so handlePublic can get responses.
	tunnelDone := make(chan struct{})
	go func() {
		defer close(tunnelDone)
		for {
			var msg protocol.Message
			err := conn.ReadJSON(&msg)
			if err != nil {
				return
			}
			switch msg.Type {
			case protocol.TypeRequest:
				// Echo back a synthetic response.
				_ = conn.WriteJSON(protocol.Message{
					Type:       protocol.TypeResponse,
					StreamID:   msg.StreamID,
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"text/plain"}},
					Body:       []byte("hello from tunnel"),
				})
			case protocol.TypePing:
				_ = conn.WriteJSON(protocol.Message{Type: protocol.TypePong})
			}
		}
	}()

	// Make an HTTP request through the tunnel.
	host := reg.TunnelID + ".localhost:7000"
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/test-path", nil)
	req.Host = host
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	r.Equal("hello from tunnel", rec.Body.String())
}

func TestHealthAndReady(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store:   store,
		tunnels: make(map[string]*tunnel),
	}

	for _, path := range []string{"/healthz", "/ready"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		if path == "/healthz" {
			s.handleHealthz(rec, req)
		} else {
			s.handleReady(rec, req)
		}
		r.Equal(http.StatusOK, rec.Code)
		r.Contains(rec.Body.String(), "ok")
	}
}

func TestMetrics(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	s := &Server{
		cfg: Config{
			Domain:            "localhost:7000",
			PublicScheme:      "http",
			MaxTunnelsPerUser: 5,
			Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store:   store,
		tunnels: make(map[string]*tunnel),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	req.Host = "localhost:7000"
	rec := httptest.NewRecorder()
	s.handleMetrics(rec, req)
	r.Equal(http.StatusOK, rec.Code)
	r.Contains(rec.Body.String(), "tunnels_active")
	r.Contains(rec.Body.String(), "tunnels_total")
	r.Contains(rec.Body.String(), "requests_total")

	// Connect a tunnel and verify metrics update.
	r.NoError(s.registerTunnel(&tunnel{id: "m1", host: "m1.localhost:7000", owner: "abed"}))

	rec = httptest.NewRecorder()
	s.handleMetrics(rec, req)
	r.Equal(http.StatusOK, rec.Code)
	r.Contains(rec.Body.String(), `"tunnels_active":1`)
	r.Contains(rec.Body.String(), `"tunnels_total":1`)

	s.unregisterTunnel(&tunnel{id: "m1", host: "m1.localhost:7000", owner: "abed"})

	rec = httptest.NewRecorder()
	s.handleMetrics(rec, req)
	r.Equal(http.StatusOK, rec.Code)
	r.Contains(rec.Body.String(), `"tunnels_active":0`)
	r.Contains(rec.Body.String(), `"tunnels_total":1`)
}
