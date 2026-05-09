package server

import (
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"
)

const sessionCookieName = "rgrok_session"
const stateCookieName = "rgrok_oauth_state"

type dashboardTunnel struct {
	ID        string
	PublicURL string
	Owner     string
}

func (s *Server) handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.GitHubClientID == "" || s.cfg.GitHubClientSecret == "" {
		http.Error(w, "GitHub OAuth is not configured", http.StatusServiceUnavailable)
		return
	}

	state, err := randomHex(24)
	if err != nil {
		http.Error(w, "could not create login state", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.PublicScheme == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	http.Redirect(w, r, s.github.AuthorizeURL(state, s.callbackURL()), http.StatusFound)
}

func (s *Server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil || stateCookie.Value == "" || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	clearCookie(w, stateCookieName, s.cfg.PublicScheme == "https")

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	token, err := s.github.ExchangeWebCode(r.Context(), code, s.callbackURL())
	if err != nil {
		http.Error(w, "GitHub token exchange failed", http.StatusBadGateway)
		return
	}
	ghUser, err := s.github.User(r.Context(), token.AccessToken)
	if err != nil {
		http.Error(w, "GitHub user lookup failed", http.StatusBadGateway)
		return
	}
	storedUser, ok := s.store.IsAllowed(ghUser.Login)
	if !ok {
		http.Error(w, "Your GitHub user is not whitelisted for rgrok.", http.StatusForbidden)
		return
	}

	session, err := s.store.CreateSession(storedUser.Login, storedUser.Admin)
	if err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.PublicScheme == "https",
		SameSite: http.SameSiteLaxMode,
		Expires:  session.ExpiresAt,
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		_ = s.store.DeleteSession(cookie.Value)
	}
	clearCookie(w, sessionCookieName, s.cfg.PublicScheme == "https")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r)
	if !ok {
		return
	}

	data := struct {
		Session StoredSession
		Tunnels []dashboardTunnel
		Users   []StoredUser
	}{
		Session: session,
		Tunnels: s.visibleTunnels(session),
	}
	if session.Admin {
		data.Users = s.store.ListUsers()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTemplate.Execute(w, data); err != nil {
		s.cfg.Logger.Error("dashboard render failed", "err", err)
	}
}

func (s *Server) handleAddUser(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	login := strings.TrimSpace(r.Form.Get("login"))
	admin := r.Form.Get("admin") == "on"
	if err := s.store.UpsertUser(login, admin); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.cfg.Logger.Info("whitelist user updated", "actor", session.Login, "login", normalizeLogin(login), "admin", admin)
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	login := r.Form.Get("login")
	if err := s.store.DeleteUser(login); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.cfg.Logger.Info("whitelist user removed", "actor", session.Login, "login", normalizeLogin(login))
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (s *Server) handleDisconnectTunnel(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	id := r.Form.Get("id")
	if !s.disconnectTunnel(id, session) {
		http.NotFound(w, r)
		return
	}
	s.cfg.Logger.Info("tunnel disconnected from dashboard", "actor", session.Login, "id", id)
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (StoredSession, bool) {
	session, ok := s.requireSession(w, r)
	if !ok {
		return StoredSession{}, false
	}
	if !session.Admin {
		http.Error(w, "admin access required", http.StatusForbidden)
		return StoredSession{}, false
	}
	return session, true
}

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) (StoredSession, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		http.Redirect(w, r, "/login/github", http.StatusFound)
		return StoredSession{}, false
	}
	session, ok := s.store.Session(cookie.Value)
	if !ok {
		clearCookie(w, sessionCookieName, s.cfg.PublicScheme == "https")
		http.Redirect(w, r, "/login/github", http.StatusFound)
		return StoredSession{}, false
	}
	return session, true
}

func (s *Server) visibleTunnels(session StoredSession) []dashboardTunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tunnels := make([]dashboardTunnel, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		if !session.Admin && t.owner != session.Login {
			continue
		}
		tunnels = append(tunnels, dashboardTunnel{
			ID:        t.id,
			PublicURL: t.publicURL,
			Owner:     t.owner,
		})
	}
	sort.Slice(tunnels, func(i, j int) bool {
		return tunnels[i].ID < tunnels[j].ID
	})
	return tunnels
}

func (s *Server) disconnectTunnel(id string, session StoredSession) bool {
	s.mu.RLock()
	var target *tunnel
	for _, t := range s.tunnels {
		if t.id == id {
			target = t
			break
		}
	}
	s.mu.RUnlock()

	if target == nil {
		return false
	}
	if !session.Admin && target.owner != session.Login {
		return false
	}
	_ = target.conn.Close()
	return true
}

func (s *Server) callbackURL() string {
	return s.cfg.PublicScheme + "://" + s.cfg.Domain + "/auth/github/callback"
}

func clearCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

var dashboardTemplate = template.Must(template.New("dashboard").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rgrok dashboard</title>
<style>
:root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }
body { margin: 0; padding: 32px; line-height: 1.45; }
main { max-width: 920px; margin: 0 auto; }
header { display: flex; justify-content: space-between; gap: 16px; align-items: center; margin-bottom: 28px; }
h1, h2 { margin: 0 0 12px; }
section { margin-top: 28px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 10px 8px; border-bottom: 1px solid color-mix(in srgb, CanvasText 18%, transparent); text-align: left; }
form { display: inline; }
.panel { border: 1px solid color-mix(in srgb, CanvasText 18%, transparent); border-radius: 8px; padding: 16px; }
.muted { color: color-mix(in srgb, CanvasText 65%, transparent); }
input[type=text] { padding: 8px; min-width: 220px; }
button, .button { padding: 8px 10px; border: 1px solid color-mix(in srgb, CanvasText 24%, transparent); border-radius: 6px; background: Canvas; color: CanvasText; text-decoration: none; cursor: pointer; }
</style>
</head>
<body>
<main>
<header>
<div>
<h1>rgrok</h1>
<div class="muted">Signed in as {{.Session.Login}}{{if .Session.Admin}} · admin{{end}}</div>
</div>
<a class="button" href="/logout">Sign out</a>
</header>

<section>
<h2>Active tunnels</h2>
{{if .Tunnels}}
<table>
<thead><tr><th>Name</th><th>URL</th>{{if .Session.Admin}}<th>Owner</th>{{end}}<th></th></tr></thead>
<tbody>
{{range .Tunnels}}
<tr>
<td>{{.ID}}</td>
<td><a href="{{.PublicURL}}">{{.PublicURL}}</a></td>
{{if $.Session.Admin}}<td>{{.Owner}}</td>{{end}}
<td>
<form method="post" action="/dashboard/tunnels/disconnect">
<input type="hidden" name="id" value="{{.ID}}">
<button type="submit">Disconnect</button>
</form>
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p class="muted">No active tunnels.</p>
{{end}}
</section>

{{if .Session.Admin}}
<section class="panel">
<h2>Whitelist</h2>
<form method="post" action="/dashboard/users/add">
<input type="text" name="login" placeholder="GitHub username" required>
<label><input type="checkbox" name="admin"> Admin</label>
<button type="submit">Add user</button>
</form>
{{if .Users}}
<table>
<thead><tr><th>User</th><th>Role</th><th></th></tr></thead>
<tbody>
{{range .Users}}
<tr>
<td>{{.Login}}</td>
<td>{{if .Admin}}Admin{{else}}User{{end}}</td>
<td>
{{if ne .Login "rselbach"}}
<form method="post" action="/dashboard/users/delete">
<input type="hidden" name="login" value="{{.Login}}">
<button type="submit">Remove</button>
</form>
{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{end}}
</section>
{{end}}
</main>
</body>
</html>`))
