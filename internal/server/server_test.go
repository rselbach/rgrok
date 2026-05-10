package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	tmp := t.TempDir()
	store, err := OpenStore(tmp + "/test.json")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

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

	if rec.Code != http.StatusOK {
		t.Fatalf("want status %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Sign in with GitHub") {
		t.Fatal("landing page missing sign-in text")
	}
	if !strings.Contains(body, `href="/login/github"`) {
		t.Fatal("landing page missing login link")
	}

	// Authenticated request should redirect to dashboard.
	session, err := store.CreateSession("troy", false)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Host = "localhost:7000"
	req2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	rec2 := httptest.NewRecorder()
	s.writeIndexOrNotFound(rec2, req2)

	if rec2.Code != http.StatusFound {
		t.Fatalf("want status %d, got %d", http.StatusFound, rec2.Code)
	}
	if loc := rec2.Header().Get("Location"); loc != "/dashboard" {
		t.Fatalf("want redirect to /dashboard, got %s", loc)
	}

	// Expired/invalid cookie should be cleared and landing page shown.
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Host = "localhost:7000"
	req3.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "invalid-token"})
	rec3 := httptest.NewRecorder()
	s.writeIndexOrNotFound(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Fatalf("want status %d, got %d", http.StatusOK, rec3.Code)
	}
	var cleared bool
	for _, c := range rec3.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge == -1 {
			cleared = true
			break
		}
	}
	if !cleared {
		t.Fatal("expected invalid session cookie to be cleared")
	}
}
