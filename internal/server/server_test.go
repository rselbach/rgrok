package server

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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
