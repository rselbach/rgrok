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
		BaseURL string
	}{
		Session: session,
		Tunnels: s.visibleTunnels(session),
		BaseURL: s.cfg.PublicScheme + "://" + s.cfg.Domain,
	}
	if session.Admin {
		data.Users = s.store.ListUsers()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'")
	if err := dashboardTemplate.Execute(w, data); err != nil {
		s.cfg.Logger.Error("dashboard render failed", "err", err)
	}
}

func (s *Server) handleAddUser(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.requireCSRF(w, r, session) {
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
	if !s.requireCSRF(w, r, session) {
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
	if !s.requireCSRF(w, r, session) {
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

func (s *Server) requirePost(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

func (s *Server) requireCSRF(w http.ResponseWriter, r *http.Request, session StoredSession) bool {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return false
	}
	if r.PostForm.Get("csrf_token") != session.CSRFToken {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return false
	}
	return true
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
:root {
  color-scheme: light;
  --bg: #ffffff;
  --bg-soft: #f9fafb;
  --sidebar-bg: #f4f5f7;
  --card: #ffffff;
  --line: #e5e7eb;
  --line-soft: #eef0f3;
  --line-strong: #d1d5db;
  --text: #1f2328;
  --text-strong: #0c0c0d;
  --muted: #6b7280;
  --muted-2: #9ca3af;
  --accent: #1563ff;
  --accent-strong: #1051d8;
  --accent-soft: #e7eeff;
  --success: #00853e;
  --success-soft: #dcefe2;
  --danger: #c73444;
  --danger-soft: #fdecec;
  --topbar-bg: #0c0c0d;
  --topbar-fg: #ffffff;
  --topbar-muted: #9ca3af;
  --topbar-pill: #1c1d22;
  --topbar-pill-line: #2a2c33;
  --radius: 6px;
  --radius-lg: 8px;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --shadow-sm: 0 1px 2px rgba(15, 23, 42, 0.04);
}
*, *::before, *::after { box-sizing: border-box; }
html, body { min-height: 100%; }
body {
  margin: 0;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  font: 13.5px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
}
button, input { font: inherit; color: inherit; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.topbar {
  position: sticky;
  top: 0;
  z-index: 20;
  height: 52px;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0 16px;
  background: var(--topbar-bg);
  color: var(--topbar-fg);
  border-bottom: 1px solid #16171b;
}
.brand {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  color: var(--topbar-fg);
  font-weight: 600;
  font-size: 14px;
}
.brand:hover { text-decoration: none; }
.brand-glyph {
  width: 26px;
  height: 26px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}
.topbar-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  height: 30px;
  padding: 0 10px;
  border-radius: var(--radius);
  background: var(--topbar-pill);
  border: 1px solid var(--topbar-pill-line);
  color: var(--topbar-fg);
  font-size: 12.5px;
  max-width: min(560px, 52vw);
}
.topbar-pill .k { color: var(--topbar-muted); font-size: 11.5px; letter-spacing: .02em; }
.topbar-pill .v {
  font-family: var(--mono);
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.topbar-spacer { flex: 1; }
.topbar-meta { color: var(--topbar-muted); font-size: 12px; }
.topbar-meta b { color: var(--topbar-fg); font-weight: 500; }

.app {
  flex: 1;
  display: grid;
  grid-template-columns: 240px minmax(0, 1fr);
}
.sidebar {
  border-right: 1px solid var(--line);
  padding: 14px 8px;
  background: var(--sidebar-bg);
}
.side-section + .side-section { margin-top: 14px; }
.side-label {
  padding: 6px 10px 4px;
  font-size: 11.5px;
  font-weight: 600;
  color: var(--muted);
}
.side-item {
  display: flex;
  align-items: center;
  gap: 9px;
  min-height: 30px;
  padding: 6px 10px;
  border-radius: 5px;
  color: var(--text);
  font-size: 13px;
  line-height: 1;
}
.side-item:hover { background: rgba(15, 23, 42, 0.05); text-decoration: none; }
.side-item.active {
  color: var(--accent);
  background: var(--accent-soft);
  font-weight: 500;
}
.side-item .icon { width: 16px; height: 16px; color: var(--muted); flex: 0 0 auto; }
.side-item.active .icon { color: var(--accent); }
.side-item .badge {
  margin-left: auto;
  min-width: 22px;
  text-align: center;
  font-size: 11px;
  padding: 1px 7px;
  border-radius: 999px;
  background: rgba(15, 23, 42, 0.08);
  color: var(--muted);
  font-weight: 500;
}

.content {
  padding: 28px 32px;
  max-width: 1360px;
  width: 100%;
}

.page-header {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  margin-bottom: 20px;
}
.page-icon {
  width: 40px;
  height: 40px;
  border-radius: var(--radius-lg);
  background: var(--card);
  border: 1px solid var(--line);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--text-strong);
  box-shadow: var(--shadow-sm);
  flex: 0 0 auto;
}
.page-header-text { flex: 1; min-width: 0; }
.page-header h1 {
  margin: 0 0 4px;
  color: var(--text-strong);
  font-size: 24px;
  line-height: 1.15;
  font-weight: 700;
}
.page-header .lede {
  margin: 0;
  max-width: 76ch;
  color: var(--muted);
  font-size: 13.5px;
}

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  min-height: 32px;
  padding: 0 12px;
  border-radius: var(--radius);
  border: 1px solid var(--line-strong);
  background: var(--card);
  color: var(--text);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  white-space: nowrap;
}
.btn:hover { background: var(--bg-soft); text-decoration: none; }
.btn-primary { background: var(--accent); color: #fff; border-color: var(--accent); }
.btn-primary:hover { background: var(--accent-strong); border-color: var(--accent-strong); color: #fff; }
.btn-danger { color: var(--danger); border-color: rgba(199, 52, 68, .35); background: var(--card); }
.btn-danger:hover { background: var(--danger-soft); }
.btn-ghost { background: transparent; border-color: transparent; }
.btn-ghost:hover { background: rgba(15, 23, 42, .06); }
.btn-sm { min-height: 28px; padding: 0 10px; font-size: 12.5px; }
.plus { font-size: 14px; line-height: 1; }

.summary-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}
.summary-tile {
  border: 1px solid var(--line);
  border-radius: var(--radius-lg);
  padding: 12px 14px;
  background: var(--card);
  box-shadow: var(--shadow-sm);
}
.summary-tile .k { color: var(--muted); font-size: 12px; }
.summary-tile .v { color: var(--text-strong); font-size: 22px; line-height: 1.1; font-weight: 700; }

.card {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  overflow: hidden;
}
.card + .card { margin-top: 14px; }
.table-wrap { overflow-x: auto; }
table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
}
thead th {
  background: var(--bg-soft);
  text-align: left;
  padding: 10px 14px;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-strong);
  border-bottom: 1px solid var(--line);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
tbody td {
  padding: 12px 14px;
  border-bottom: 1px solid var(--line-soft);
  font-size: 13px;
  color: var(--text);
  vertical-align: middle;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: #fafbfc; }
.row-title { font-weight: 500; color: var(--text-strong); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.col-actions { text-align: right; }
td.cell-widget { overflow: visible; }
.row-actions { display: inline-flex; gap: 4px; justify-content: flex-end; }
.row-actions form { margin: 0; }
.icon-btn {
  width: 28px;
  height: 28px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 5px;
  border: 1px solid transparent;
  background: transparent;
  color: var(--muted);
  cursor: pointer;
  padding: 0;
}
.icon-btn:hover { color: var(--text-strong); background: var(--bg-soft); border-color: var(--line); text-decoration: none; }
.icon-btn.danger:hover { color: var(--danger); background: var(--danger-soft); border-color: rgba(199, 52, 68, .35); }
.icon-btn svg { width: 14px; height: 14px; display: block; }

.status {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11.5px;
  font-weight: 500;
  background: rgba(15, 23, 42, .05);
  color: var(--muted);
  white-space: nowrap;
  min-width: 72px;
}
.status::before {
  content: "";
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
}
.status.active { background: var(--success-soft); color: var(--success); }

.card-header {
  padding: 16px 14px;
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.card-header h2 {
  margin: 0;
  font-size: 16px;
  font-weight: 700;
  color: var(--text-strong);
}
.form-inline {
  display: flex;
  gap: 8px;
  align-items: center;
  margin: 0;
}
.form-inline input[type="text"] {
  padding: 6px 10px;
  border: 1px solid var(--line-strong);
  border-radius: var(--radius);
  font-size: 13px;
  min-width: 180px;
}
.form-inline label {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
  color: var(--muted);
  white-space: nowrap;
}

@media (max-width: 768px) {
  .app { grid-template-columns: 1fr; }
  .sidebar { display: none; }
}
</style>
</head>
<body>
<header class="topbar">
  <a class="brand" href="/dashboard">
    <span class="brand-glyph" aria-hidden="true">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
        <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
      </svg>
    </span>
    rgrok
  </a>
  <span class="topbar-pill" title="Configured public base URL">
    <span class="k">BASE</span>
    <span class="v">{{.BaseURL}}</span>
  </span>
  <span class="topbar-spacer"></span>
  <span class="topbar-meta">Signed in as <b>{{.Session.Login}}</b>{{if .Session.Admin}} · admin{{end}}</span>
  <a class="btn btn-sm btn-ghost" href="/logout" style="color:var(--topbar-fg);margin-left:4px;">Sign out</a>
</header>

<div class="app">
  <aside class="sidebar">
    <nav class="side-section" aria-label="Main">
      <div class="side-label">Main</div>
      <a class="side-item active" href="/dashboard">
        <span class="icon" aria-hidden="true">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="8" cy="8" r="6.5"/>
            <path d="M1.5 8h13"/>
            <path d="M8 1.5c2.5 2 3.5 4.5 3.5 6.5s-1 4.5-3.5 6.5"/>
            <path d="M8 1.5c-2.5 2-3.5 4.5-3.5 6.5s1 4.5 3.5 6.5"/>
          </svg>
        </span>
        Tunnels
        <span class="badge">{{len .Tunnels}}</span>
      </a>
      {{if .Session.Admin}}
      <a class="side-item" href="#users">
        <span class="icon" aria-hidden="true">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="8" cy="5.5" r="2.5"/>
            <path d="M3.5 13.5c0-2.5 2-4.5 4.5-4.5s4.5 2 4.5 4.5"/>
          </svg>
        </span>
        Users
        <span class="badge">{{len .Users}}</span>
      </a>
      {{end}}
    </nav>
    <nav class="side-section" aria-label="Account">
      <div class="side-label">Account</div>
      <a class="side-item" href="/logout">
        <span class="icon" aria-hidden="true">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
            <path d="M6 3L2 8l4 5"/>
            <path d="M2 8h9"/>
            <path d="M10 3v10"/>
          </svg>
        </span>
        Sign out
      </a>
    </nav>
  </aside>

  <main class="content">
    <header class="page-header">
      <div class="page-icon" aria-hidden="true">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <path d="M2 12h20"/>
          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
        </svg>
      </div>
      <div class="page-header-text">
        <h1>Tunnels</h1>
        <p class="lede">Active public tunnels and their endpoints.</p>
      </div>
    </header>

    <div class="summary-grid">
      <div class="summary-tile">
        <div class="k">Active Tunnels</div>
        <div class="v" id="tunnel-count">{{len .Tunnels}}</div>
      </div>
      {{if .Session.Admin}}
      <div class="summary-tile">
        <div class="k">Whitelisted Users</div>
        <div class="v">{{len .Users}}</div>
      </div>
      {{end}}
    </div>

    <section class="card">
      <div class="table-wrap" id="tunnel-list" hx-get="/dashboard/tunnels" hx-trigger="every 5s" hx-swap="innerHTML">
        {{if .Tunnels}}
        <table>
          <colgroup>
            <col>
            <col>
            {{if .Session.Admin}}<col>{{end}}
            <col style="width: 100px">
            <col style="width: 100px">
          </colgroup>
          <thead>
            <tr>
              <th>Name</th>
              <th>Public URL</th>
              {{if .Session.Admin}}<th>Owner</th>{{end}}
              <th>Status</th>
              <th class="col-actions">Actions</th>
            </tr>
          </thead>
          <tbody>
            {{range .Tunnels}}
            <tr>
              <td><div class="row-title">{{.ID}}</div></td>
              <td><a href="{{.PublicURL}}">{{.PublicURL}}</a></td>
              {{if $.Session.Admin}}<td>{{.Owner}}</td>{{end}}
              <td class="cell-widget"><span class="status active">active</span></td>
              <td class="col-actions cell-widget">
                <div class="row-actions">
                  <form method="post" action="/dashboard/tunnels/disconnect">
                    <input type="hidden" name="csrf_token" value="{{$.Session.CSRFToken}}">
                    <input type="hidden" name="id" value="{{.ID}}">
                    <button class="icon-btn danger" type="submit" title="Disconnect" aria-label="Disconnect">
                      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M2 4h12"/>
                        <path d="M5 4V2.5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1V4"/>
                        <path d="M4.5 4l.6 8a1 1 0 0 0 1 1h4.8a1 1 0 0 0 1-1l.6-8"/>
                      </svg>
                    </button>
                  </form>
                </div>
              </td>
            </tr>
            {{end}}
          </tbody>
        </table>
        {{else}}
        <div style="padding: 32px 14px; text-align: center; color: var(--muted);">
          No active tunnels.
        </div>
        {{end}}
      </div>
    </section>

    {{if .Session.Admin}}
    <section class="card" id="users">
      <div class="card-header">
        <h2>Whitelist</h2>
        <form method="post" action="/dashboard/users/add" class="form-inline">
          <input type="hidden" name="csrf_token" value="{{.Session.CSRFToken}}">
          <input type="text" name="login" placeholder="GitHub username" required>
          <label><input type="checkbox" name="admin"> Admin</label>
          <button type="submit" class="btn btn-primary btn-sm"><span class="plus">+</span> Add user</button>
        </form>
      </div>
      <div class="table-wrap">
        {{if .Users}}
        <table>
          <colgroup><col><col style="width: 120px"><col style="width: 100px"></colgroup>
          <thead>
            <tr><th>User</th><th>Role</th><th class="col-actions">Actions</th></tr>
          </thead>
          <tbody>
            {{range .Users}}
            <tr>
              <td><div class="row-title">{{.Login}}</div></td>
              <td class="cell-widget">
                {{if .Admin}}
                <span class="status" style="background:var(--accent-soft); color:var(--accent);">admin</span>
                {{else}}
                <span class="status" style="background:rgba(15,23,42,.05); color:var(--muted-2);">user</span>
                {{end}}
              </td>
              <td class="col-actions cell-widget">
                <div class="row-actions">
                  {{if ne .Login "rselbach"}}
                  <form method="post" action="/dashboard/users/delete">
                    <input type="hidden" name="csrf_token" value="{{$.Session.CSRFToken}}">
                    <input type="hidden" name="login" value="{{.Login}}">
                    <button class="icon-btn danger" type="submit" title="Remove" aria-label="Remove">
                      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M2 4h12"/>
                        <path d="M5 4V2.5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1V4"/>
                        <path d="M4.5 4l.6 8a1 1 0 0 0 1 1h4.8a1 1 0 0 0 1-1l.6-8"/>
                      </svg>
                    </button>
                  </form>
                  {{end}}
                </div>
              </td>
            </tr>
            {{end}}
          </tbody>
        </table>
        {{else}}
        <div style="padding: 32px 14px; text-align: center; color: var(--muted);">
          No whitelisted users.
        </div>
        {{end}}
      </div>
    </section>
    {{end}}
  </main>
</div>
<script src="https://unpkg.com/htmx.org@2"></script>
</body>
</html>`))

var tunnelTablePartial = template.Must(template.New("tunnelTable").Parse(`{{if .Tunnels}}
<table>
  <colgroup>
    <col>
    <col>
    {{if .Session.Admin}}<col>{{end}}
    <col style="width: 100px">
    <col style="width: 100px">
  </colgroup>
  <thead>
    <tr>
      <th>Name</th>
      <th>Public URL</th>
      {{if .Session.Admin}}<th>Owner</th>{{end}}
      <th>Status</th>
      <th class="col-actions">Actions</th>
    </tr>
  </thead>
  <tbody>
    {{range .Tunnels}}
    <tr>
      <td><div class="row-title">{{.ID}}</div></td>
      <td><a href="{{.PublicURL}}">{{.PublicURL}}</a></td>
      {{if $.Session.Admin}}<td>{{.Owner}}</td>{{end}}
      <td class="cell-widget"><span class="status active">active</span></td>
      <td class="col-actions cell-widget">
        <div class="row-actions">
          <form method="post" action="/dashboard/tunnels/disconnect">
            <input type="hidden" name="csrf_token" value="{{$.Session.CSRFToken}}">
            <input type="hidden" name="id" value="{{.ID}}">
            <button class="icon-btn danger" type="submit" title="Disconnect" aria-label="Disconnect">
              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
                <path d="M2 4h12"/>
                <path d="M5 4V2.5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1V4"/>
                <path d="M4.5 4l.6 8a1 1 0 0 0 1 1h4.8a1 1 0 0 0 1-1l.6-8"/>
              </svg>
            </button>
          </form>
        </div>
      </td>
    </tr>
    {{end}}
  </tbody>
</table>
{{else}}
<div style="padding: 32px 14px; text-align: center; color: var(--muted);">
  No active tunnels.
</div>
{{end}}
<div id="tunnel-count" hx-swap-oob="innerHTML">{{len .Tunnels}}</div>`))

func (s *Server) handleDashboardTunnels(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r)
	if !ok {
		return
	}

	data := struct {
		Session StoredSession
		Tunnels []dashboardTunnel
	}{
		Session: session,
		Tunnels: s.visibleTunnels(session),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'")
	if err := tunnelTablePartial.Execute(w, data); err != nil {
		s.cfg.Logger.Error("tunnel table partial render failed", "err", err)
	}
}
