package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rselbach/rgrok/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestParseApplicationRoutes(t *testing.T) {
	tests := map[string]struct {
		raw     string
		want    []StoredApplicationRoute
		wantErr string
	}{
		"method groups and templates": {
			raw: "GET,POST /oidc/{slug}/authorize\nPOST /oidc/{slug}/token",
			want: []StoredApplicationRoute{
				{Methods: []string{"GET", "POST"}, Path: "/oidc/{slug}/authorize"},
				{Methods: []string{"POST"}, Path: "/oidc/{slug}/token"},
			},
		},
		"method wildcard": {
			raw:  "* /saml/{slug}/sso",
			want: []StoredApplicationRoute{{Methods: []string{"*"}, Path: "/saml/{slug}/sso"}},
		},
		"missing method": {
			raw:     "/oidc/{slug}/jwks",
			wantErr: "METHODS PATH",
		},
		"partial parameter": {
			raw:     "GET /oidc/user-{slug}",
			wantErr: "invalid path parameter",
		},
		"subtree wildcard": {
			raw:     "GET /oidc/*",
			wantErr: "wildcards are not allowed",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			got, err := parseApplicationRoutes(tc.raw)
			if tc.wantErr != "" {
				r.ErrorContains(err, tc.wantErr)
				return
			}
			r.NoError(err)
			r.Equal(tc.want, got)
		})
	}
}

func TestApplicationRequestAllowed(t *testing.T) {
	routes := []StoredApplicationRoute{
		{Methods: []string{http.MethodGet}, Path: "/oidc/{slug}/jwks"},
		{Methods: []string{http.MethodGet, http.MethodPost}, Path: "/saml/{slug}/sso"},
	}
	tests := map[string]struct {
		method string
		path   string
		want   bool
	}{
		"matching segment":         {method: http.MethodGet, path: "/oidc/greendale/jwks", want: true},
		"query ignored":            {method: http.MethodGet, path: "/oidc/greendale/jwks?use=signing", want: true},
		"wrong method":             {method: http.MethodPost, path: "/oidc/greendale/jwks"},
		"multiple segments":        {method: http.MethodGet, path: "/oidc/green/dale/jwks"},
		"empty segment":            {method: http.MethodGet, path: "/oidc//jwks"},
		"encoded slash":            {method: http.MethodGet, path: "/oidc/green%2Fdale/jwks"},
		"dot segment":              {method: http.MethodGet, path: "/oidc/../jwks"},
		"trailing slash":           {method: http.MethodGet, path: "/oidc/greendale/jwks/"},
		"explicit second method":   {method: http.MethodPost, path: "/saml/greendale/sso", want: true},
		"head is not implicit get": {method: http.MethodHead, path: "/oidc/greendale/jwks"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			require.Equal(t, tc.want, applicationRequestAllowed(routes, req))
		})
	}
}

func TestApplicationProfileStorage(t *testing.T) {
	r := require.New(t)
	publicKey, _, publicKeyText := testEd25519Key(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	profile, err := store.CreateApplicationProfile(
		"Greendale Identity",
		publicKeyText+" comment is discarded",
		[]StoredApplicationRoute{{Methods: []string{"GET"}, Path: "/oidc/{slug}/jwks"}},
		30,
		10,
		4,
	)
	r.NoError(err)
	r.Len(profile.ID, 32)
	r.NotEmpty(profile.PublicKeyFingerprint)
	r.NotContains(profile.PublicKey, "comment")
	r.Equal(publicKey, mustApplicationPublicKey(t, profile.PublicKey))

	r.NoError(store.RememberApplicationTunnel(profile.ID, "installation-1", "human-timeline-club"))
	r.Equal("human-timeline-club", store.ApplicationTunnelID(profile.ID, "installation-1"))
	firstReservation, ok := store.ApplicationProfile(profile.ID)
	r.True(ok)
	firstRequestedAt := firstReservation.Instances["installation-1"].CreatedAt
	firstLastUsedAt := firstReservation.Instances["installation-1"].LastUsedAt
	r.False(firstRequestedAt.IsZero())
	r.Equal(firstRequestedAt, firstLastUsedAt)
	time.Sleep(time.Millisecond)
	r.NoError(store.RememberApplicationTunnel(profile.ID, "installation-1", "human-timeline-club"))
	secondReservation, ok := store.ApplicationProfile(profile.ID)
	r.True(ok)
	r.Equal(firstRequestedAt, secondReservation.Instances["installation-1"].CreatedAt)
	r.True(secondReservation.Instances["installation-1"].LastUsedAt.After(firstLastUsedAt))
	store.mu.Lock()
	storedProfile := store.data.ApplicationProfiles[profile.ID]
	storedProfile.Instances["expired-installation"] = StoredApplicationInstance{
		TunnelID:   "expired-tunnel",
		LastUsedAt: time.Now().UTC().Add(-applicationInstanceMaxIdle - time.Hour),
	}
	store.data.ApplicationProfiles[profile.ID] = storedProfile
	store.mu.Unlock()
	r.NoError(store.RememberApplicationTunnel(profile.ID, "installation-2", "study-room-club"))
	r.Empty(store.ApplicationTunnelID(profile.ID, "expired-installation"))

	reopened, err := OpenStore(store.path)
	r.NoError(err)
	got, ok := reopened.ApplicationProfile(profile.ID)
	r.True(ok)
	r.Equal(profile.Name, got.Name)
	r.Equal("human-timeline-club", reopened.ApplicationTunnelID(profile.ID, "installation-1"))

	_, err = reopened.CreateApplicationProfile(
		"Duplicate",
		publicKeyText,
		profile.Routes,
		30,
		10,
		4,
	)
	r.ErrorContains(err, "already used")
}

func TestApplicationInstanceTimestampMigration(t *testing.T) {
	r := require.New(t)
	_, _, publicKeyText := testEd25519Key(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	profile, err := store.CreateApplicationProfile(
		"Greendale Identity",
		publicKeyText,
		[]StoredApplicationRoute{{Methods: []string{"GET"}, Path: "/oidc/{slug}/jwks"}},
		30,
		10,
		4,
	)
	r.NoError(err)
	r.NoError(store.RememberApplicationTunnel(profile.ID, "legacy-installation", "study-room-club"))

	store.mu.Lock()
	storedProfile := store.data.ApplicationProfiles[profile.ID]
	instance := storedProfile.Instances["legacy-installation"]
	instance.CreatedAt = time.Time{}
	storedProfile.Instances["legacy-installation"] = instance
	store.data.ApplicationProfiles[profile.ID] = storedProfile
	saveErr := store.saveLocked()
	store.mu.Unlock()
	r.NoError(saveErr)

	reopened, err := OpenStore(store.path)
	r.NoError(err)
	migrated, ok := reopened.ApplicationProfile(profile.ID)
	r.True(ok)
	migratedInstance := migrated.Instances["legacy-installation"]
	r.Equal(migratedInstance.LastUsedAt, migratedInstance.CreatedAt)
}

func TestUpdateApplicationProfile(t *testing.T) {
	r := require.New(t)
	_, _, originalKey := testEd25519Key(t)
	_, _, replacementKey := testEd25519Key(t)
	_, _, otherKey := testEd25519Key(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	profile, err := store.CreateApplicationProfile(
		"Greendale Identity",
		originalKey,
		[]StoredApplicationRoute{{Methods: []string{"GET"}, Path: "/oidc/{slug}/jwks"}},
		30,
		10,
		4,
	)
	r.NoError(err)
	other, err := store.CreateApplicationProfile(
		"Other Application",
		otherKey,
		[]StoredApplicationRoute{{Methods: []string{"GET"}, Path: "/other/{slug}"}},
		20,
		5,
		2,
	)
	r.NoError(err)
	r.NoError(store.RememberApplicationTunnel(profile.ID, "installation-1", "human-timeline-club"))

	updated, err := store.UpdateApplicationProfile(
		profile.ID,
		"Greendale Login",
		replacementKey,
		[]StoredApplicationRoute{{Methods: []string{"GET", "POST"}, Path: "/login/{slug}"}},
		60,
		15,
		6,
	)
	r.NoError(err)
	r.Equal(profile.ID, updated.ID)
	r.Equal(profile.CreatedAt, updated.CreatedAt)
	r.Equal("Greendale Login", updated.Name)
	r.Equal([]StoredApplicationRoute{{Methods: []string{"GET", "POST"}, Path: "/login/{slug}"}}, updated.Routes)
	r.Equal(60, updated.RequestsPerMinute)
	r.Equal(15, updated.RequestBurst)
	r.Equal(6, updated.ConcurrentRequests)
	r.Equal("human-timeline-club", updated.Instances["installation-1"].TunnelID)

	_, err = store.UpdateApplicationProfile(
		profile.ID,
		"Duplicate Key",
		otherKey,
		updated.Routes,
		60,
		15,
		6,
	)
	r.ErrorContains(err, "already used")
	unchanged, ok := store.ApplicationProfile(profile.ID)
	r.True(ok)
	r.Equal("Greendale Login", unchanged.Name)
	r.Equal(updated.PublicKey, unchanged.PublicKey)
	otherUnchanged, ok := store.ApplicationProfile(other.ID)
	r.True(ok)
	r.Equal(other.PublicKey, otherUnchanged.PublicKey)
}

func TestApplicationRateLimiter(t *testing.T) {
	r := require.New(t)
	limiter := newApplicationRateLimiter(1, 2)
	r.True(limiter.allow())
	r.True(limiter.allow())
	r.False(limiter.allow())
}

func TestDashboardCreatesApplicationProfile(t *testing.T) {
	r := require.New(t)
	_, _, publicKeyText := testEd25519Key(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	session, err := store.CreateSession("rselbach", true)
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
	form := url.Values{
		"csrf_token":          {session.CSRFToken},
		"name":                {"Greendale Identity"},
		"public_key":          {publicKeyText},
		"routes":              {"GET /oidc/{slug}/jwks\nGET,POST /saml/{slug}/sso"},
		"requests_per_minute": {"30"},
		"request_burst":       {"10"},
		"concurrent_requests": {"4"},
	}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/applications/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	rec := httptest.NewRecorder()
	s.handleCreateApplication(rec, req)
	r.Equal(http.StatusFound, rec.Code)
	r.Equal("/dashboard#applications", rec.Header().Get("Location"))

	profiles := store.ListApplicationProfiles()
	r.Len(profiles, 1)
	r.Equal("Greendale Identity", profiles[0].Name)

	dashboardRequest := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	dashboardRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	dashboardResponse := httptest.NewRecorder()
	s.handleDashboard(dashboardResponse, dashboardRequest)
	r.Equal(http.StatusOK, dashboardResponse.Code)
	r.Contains(dashboardResponse.Body.String(), "SHA256:")
	r.Contains(dashboardResponse.Body.String(), profiles[0].ID)
	r.Contains(dashboardResponse.Body.String(), "/oidc/{slug}/jwks")
	r.Contains(dashboardResponse.Body.String(), "#edit-application-"+profiles[0].ID)
	r.Contains(dashboardResponse.Body.String(), "GET,POST /saml/{slug}/sso")

	updateForm := url.Values{
		"csrf_token":          {session.CSRFToken},
		"id":                  {profiles[0].ID},
		"name":                {"Greendale Login"},
		"public_key":          {publicKeyText},
		"routes":              {"GET,POST /login/{slug}"},
		"requests_per_minute": {"60"},
		"request_burst":       {"15"},
		"concurrent_requests": {"6"},
	}
	updateRequest := httptest.NewRequest(http.MethodPost, "/dashboard/applications/update", strings.NewReader(updateForm.Encode()))
	updateRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	updateRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	updateResponse := httptest.NewRecorder()
	s.handleUpdateApplication(updateResponse, updateRequest)
	r.Equal(http.StatusFound, updateResponse.Code)
	r.Equal("/dashboard#applications", updateResponse.Header().Get("Location"))
	updated, ok := store.ApplicationProfile(profiles[0].ID)
	r.True(ok)
	r.Equal("Greendale Login", updated.Name)
	r.Equal([]StoredApplicationRoute{{Methods: []string{"GET", "POST"}, Path: "/login/{slug}"}}, updated.Routes)
	r.Equal(60, updated.RequestsPerMinute)

	r.NoError(store.RememberApplicationTunnel(updated.ID, "installation-1", "human-timeline-club"))
	reservationDashboardRequest := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	reservationDashboardRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	reservationDashboardResponse := httptest.NewRecorder()
	s.handleDashboard(reservationDashboardResponse, reservationDashboardRequest)
	r.Equal(http.StatusOK, reservationDashboardResponse.Code)
	r.Contains(reservationDashboardResponse.Body.String(), "Reserved names")
	r.Contains(reservationDashboardResponse.Body.String(), "human-timeline-club")
	r.Contains(reservationDashboardResponse.Body.String(), "installation-1")
	r.Contains(reservationDashboardResponse.Body.String(), "Originally requested")

	unreserveForm := url.Values{
		"csrf_token":  {session.CSRFToken},
		"profile_id":  {updated.ID},
		"instance_id": {"installation-1"},
	}
	unreserveRequest := httptest.NewRequest(http.MethodPost, "/dashboard/applications/reservations/delete", strings.NewReader(unreserveForm.Encode()))
	unreserveRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	unreserveRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	unreserveResponse := httptest.NewRecorder()
	s.handleUnreserveApplicationTunnel(unreserveResponse, unreserveRequest)
	r.Equal(http.StatusFound, unreserveResponse.Code)
	r.Equal("/dashboard#reserved-names", unreserveResponse.Header().Get("Location"))
	r.Empty(store.ApplicationTunnelID(updated.ID, "installation-1"))
}

func TestEndToEndApplicationTunnel(t *testing.T) {
	r := require.New(t)
	_, privateKey, publicKeyText := testEd25519Key(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	profile, err := store.CreateApplicationProfile(
		"Greendale Identity",
		publicKeyText,
		[]StoredApplicationRoute{{Methods: []string{http.MethodGet}, Path: "/oidc/{slug}/jwks"}},
		1,
		1,
		1,
	)
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/connect" {
			s.handleConnect(w, req)
			return
		}
		s.handlePublic(w, req)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/connect"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	r.NoError(err)
	defer func() { r.NoError(conn.Close()) }()
	r.NoError(conn.WriteJSON(protocol.Message{
		Type:                 protocol.TypeRegisterTunnel,
		ApplicationProfileID: profile.ID,
		InstanceID:           "installation-1",
		LocalPort:            1234,
	}))
	var challenge protocol.Message
	r.NoError(conn.ReadJSON(&challenge))
	r.Equal(protocol.TypeApplicationChallenge, challenge.Type)
	payload := protocol.ApplicationChallengePayload(profile.ID, "installation-1", challenge.Challenge)
	r.NoError(conn.WriteJSON(protocol.Message{
		Type:      protocol.TypeApplicationSignature,
		Signature: ed25519.Sign(privateKey, payload),
	}))
	var registration protocol.Message
	r.NoError(conn.ReadJSON(&registration))
	r.Equal(protocol.TypeTunnelRegistered, registration.Type)
	r.Equal(registration.TunnelID, store.ApplicationTunnelID(profile.ID, "installation-1"))

	requestSeen := make(chan protocol.Message, 1)
	go func() {
		for {
			var msg protocol.Message
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			switch msg.Type {
			case protocol.TypeRequest:
				requestSeen <- msg
				if err := conn.WriteJSON(protocol.Message{
					Type:       protocol.TypeResponse,
					StreamID:   msg.StreamID,
					StatusCode: http.StatusOK,
					Body:       []byte("jwks"),
				}); err != nil {
					return
				}
			case protocol.TypePing:
				if err := conn.WriteJSON(protocol.Message{Type: protocol.TypePong}); err != nil {
					return
				}
			}
		}
	}()

	host := registration.TunnelID + ".localhost:7000"
	allowed := httptest.NewRequest(http.MethodGet, "http://"+host+"/oidc/greendale/jwks", nil)
	allowed.Host = host
	allowedResponse := httptest.NewRecorder()
	s.handlePublic(allowedResponse, allowed)
	r.Equal(http.StatusOK, allowedResponse.Code)
	r.Equal("jwks", allowedResponse.Body.String())
	r.Equal("/oidc/greendale/jwks", (<-requestSeen).Path)

	wrongMethod := httptest.NewRequest(http.MethodPost, "http://"+host+"/oidc/greendale/jwks", nil)
	wrongMethod.Host = host
	wrongMethodResponse := httptest.NewRecorder()
	s.handlePublic(wrongMethodResponse, wrongMethod)
	r.Equal(http.StatusNotFound, wrongMethodResponse.Code)

	rateLimited := httptest.NewRequest(http.MethodGet, "http://"+host+"/oidc/greendale/jwks", nil)
	rateLimited.Host = host
	rateLimitedResponse := httptest.NewRecorder()
	s.handlePublic(rateLimitedResponse, rateLimited)
	r.Equal(http.StatusTooManyRequests, rateLimitedResponse.Code)
}

func testEd25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyType := []byte("ssh-ed25519")
	blob := make([]byte, 4+len(keyType)+4+len(publicKey))
	binary.BigEndian.PutUint32(blob[:4], uint32(len(keyType)))
	copy(blob[4:], keyType)
	offset := 4 + len(keyType)
	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(len(publicKey)))
	copy(blob[offset+4:], publicKey)
	return publicKey, privateKey, "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
}

func mustApplicationPublicKey(t *testing.T, value string) ed25519.PublicKey {
	t.Helper()
	_, publicKey, _, err := parseEd25519PublicKey(value)
	require.NoError(t, err)
	return publicKey
}
