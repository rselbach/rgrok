package server

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const sessionCookieName = "rgrok_session"
const stateCookieName = "rgrok_oauth_state"

type dashboardTunnel struct {
	ID          string
	PublicURL   string
	Owner       string
	LocalPort   int
	ConnectedAt int64
	Uptime      string
	Requests    int64
}

type dashboardAPITokenOption struct {
	Days    int
	Label   string
	Default bool
}

type dashboardApplication struct {
	StoredApplicationProfile
	RoutesText string
}

type dashboardReservation struct {
	ProfileID   string
	ProfileName string
	InstanceID  string
	TunnelID    string
	PublicURL   string
	CreatedAt   time.Time
	LastUsedAt  time.Time
}

type dashboardViewData struct {
	Session                StoredSession
	Tunnels                []dashboardTunnel
	TotalRequests          int64
	Users                  []StoredUser
	APITokens              []StoredClientToken
	BaseURL                string
	Domain                 string
	APITokenOptions        []dashboardAPITokenOption
	CreatedAPIToken        string
	CreatedAPITokenName    string
	CreatedAPITokenExpires time.Time
	Applications           []dashboardApplication
	Reservations           []dashboardReservation
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
		Secure:   s.cookieSecure(),
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
	clearCookie(w, stateCookieName, s.cookieSecure())

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
		Secure:   s.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
		Expires:  session.ExpiresAt,
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		_ = s.store.DeleteSession(cookie.Value)
	}
	clearCookie(w, sessionCookieName, s.cookieSecure())
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	s.renderDashboard(w, session, "", "", time.Time{})
}

func (s *Server) renderDashboard(w http.ResponseWriter, session StoredSession, createdAPIToken string, createdAPITokenName string, createdAPITokenExpires time.Time) {
	tunnels := s.visibleTunnels(session)
	data := dashboardViewData{
		Session:                session,
		Tunnels:                tunnels,
		TotalRequests:          totalRequests(tunnels),
		APITokens:              s.store.ListClientTokensForUser(session.Login),
		BaseURL:                s.cfg.PublicScheme + "://" + s.cfg.Domain,
		Domain:                 s.cfg.Domain,
		APITokenOptions:        apiTokenExpirationOptions(),
		CreatedAPIToken:        createdAPIToken,
		CreatedAPITokenName:    createdAPITokenName,
		CreatedAPITokenExpires: createdAPITokenExpires,
	}
	if session.Admin {
		data.Users = s.store.ListUsers()
		for _, profile := range s.store.ListApplicationProfiles() {
			lines := make([]string, 0, len(profile.Routes))
			for _, route := range profile.Routes {
				lines = append(lines, strings.Join(route.Methods, ",")+" "+route.Path)
			}
			data.Applications = append(data.Applications, dashboardApplication{
				StoredApplicationProfile: profile,
				RoutesText:               strings.Join(lines, "\n"),
			})
			for instanceID, instance := range profile.Instances {
				data.Reservations = append(data.Reservations, dashboardReservation{
					ProfileID:   profile.ID,
					ProfileName: profile.Name,
					InstanceID:  instanceID,
					TunnelID:    instance.TunnelID,
					PublicURL:   s.cfg.PublicScheme + "://" + instance.TunnelID + "." + s.cfg.Domain,
					CreatedAt:   instance.CreatedAt,
					LastUsedAt:  instance.LastUsedAt,
				})
			}
		}
		sort.Slice(data.Reservations, func(i, j int) bool {
			if data.Reservations[i].ProfileName == data.Reservations[j].ProfileName {
				return data.Reservations[i].TunnelID < data.Reservations[j].TunnelID
			}
			return data.Reservations[i].ProfileName < data.Reservations[j].ProfileName
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'")
	if err := dashboardTemplate.Execute(w, data); err != nil {
		s.cfg.Logger.Error("dashboard render failed", "err", err)
	}
}

type applicationProfileForm struct {
	name               string
	publicKey          string
	routes             []StoredApplicationRoute
	requestsPerMinute  int
	requestBurst       int
	concurrentRequests int
}

func parseApplicationProfileForm(r *http.Request) (applicationProfileForm, error) {
	routes, err := parseApplicationRoutes(r.PostForm.Get("routes"))
	if err != nil {
		return applicationProfileForm{}, err
	}
	requestsPerMinute, err := positiveFormInt(r.PostForm.Get("requests_per_minute"), "requests per minute")
	if err != nil {
		return applicationProfileForm{}, err
	}
	requestBurst, err := positiveFormInt(r.PostForm.Get("request_burst"), "request burst")
	if err != nil {
		return applicationProfileForm{}, err
	}
	concurrentRequests, err := positiveFormInt(r.PostForm.Get("concurrent_requests"), "concurrent requests")
	if err != nil {
		return applicationProfileForm{}, err
	}
	return applicationProfileForm{
		name:               r.PostForm.Get("name"),
		publicKey:          r.PostForm.Get("public_key"),
		routes:             routes,
		requestsPerMinute:  requestsPerMinute,
		requestBurst:       requestBurst,
		concurrentRequests: concurrentRequests,
	}, nil
}

func (s *Server) handleCreateApplication(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.requireCSRF(w, r, session) {
		return
	}
	form, err := parseApplicationProfileForm(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	profile, err := s.store.CreateApplicationProfile(
		form.name,
		form.publicKey,
		form.routes,
		form.requestsPerMinute,
		form.requestBurst,
		form.concurrentRequests,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.cfg.Logger.Info("application profile created", "actor", session.Login, "id", profile.ID, "name", profile.Name)
	http.Redirect(w, r, "/dashboard#applications", http.StatusFound)
}

func (s *Server) handleUpdateApplication(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.requireCSRF(w, r, session) {
		return
	}
	id := r.PostForm.Get("id")
	if _, ok := s.store.ApplicationProfile(id); !ok {
		http.NotFound(w, r)
		return
	}
	form, err := parseApplicationProfileForm(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	profile, err := s.store.UpdateApplicationProfile(
		id,
		form.name,
		form.publicKey,
		form.routes,
		form.requestsPerMinute,
		form.requestBurst,
		form.concurrentRequests,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.disconnectApplicationTunnels(id)
	s.cfg.Logger.Info("application profile updated", "actor", session.Login, "id", id, "name", profile.Name)
	http.Redirect(w, r, "/dashboard#applications", http.StatusFound)
}

func (s *Server) handleDeleteApplication(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.requireCSRF(w, r, session) {
		return
	}
	id := r.PostForm.Get("id")
	if err := s.store.DeleteApplicationProfile(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.disconnectApplicationTunnels(id)
	s.cfg.Logger.Info("application profile deleted", "actor", session.Login, "id", id)
	http.Redirect(w, r, "/dashboard#applications", http.StatusFound)
}

func (s *Server) handleUnreserveApplicationTunnel(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.requireCSRF(w, r, session) {
		return
	}
	profileID := r.PostForm.Get("profile_id")
	instanceID := r.PostForm.Get("instance_id")
	deleted, err := s.store.UnreserveApplicationTunnel(profileID, instanceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !deleted {
		http.NotFound(w, r)
		return
	}
	s.cfg.Logger.Info("application tunnel unreserved", "actor", session.Login, "profile_id", profileID, "instance_id", instanceID)
	http.Redirect(w, r, "/dashboard#reserved-names", http.StatusFound)
}

func positiveFormInt(raw, name string) (int, error) {
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}

func (s *Server) handleCreateAPIToken(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if !s.requireCSRF(w, r, session) {
		return
	}

	name := strings.TrimSpace(r.PostForm.Get("name"))
	days, ok := allowedAPITokenExpirationDays(r.PostForm.Get("expires_in_days"))
	if !ok {
		http.Error(w, "invalid token expiration", http.StatusBadRequest)
		return
	}
	clientToken, err := s.store.CreateClientTokenWithNameAndLifetime(session.Login, session.Admin, name, time.Duration(days)*24*time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.cfg.Logger.Info("api token created", "login", session.Login, "name", clientToken.Name, "expires_at", clientToken.ExpiresAt)
	s.renderDashboard(w, session, clientToken.PlainToken, clientToken.Name, clientToken.ExpiresAt)
}

func (s *Server) handleDeleteAPIToken(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if !s.requireCSRF(w, r, session) {
		return
	}
	deleted, err := s.store.RevokeClientTokenForUser(session.Login, r.PostForm.Get("token_hash"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !deleted {
		http.NotFound(w, r)
		return
	}
	s.cfg.Logger.Info("api token revoked", "login", session.Login)
	http.Redirect(w, r, "/dashboard#api-tokens", http.StatusFound)
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

func (s *Server) handleRevokeSessions(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if !s.requireCSRF(w, r, session) {
		return
	}
	if err := s.store.RevokeClientTokensForUser(session.Login); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.store.DeleteSession(session.ID)
	clearCookie(w, sessionCookieName, s.cookieSecure())
	s.cfg.Logger.Info("sessions revoked", "login", session.Login)
	http.Redirect(w, r, "/", http.StatusFound)
}

func apiTokenExpirationOptions() []dashboardAPITokenOption {
	return []dashboardAPITokenOption{
		{Days: 7, Label: "7 days"},
		{Days: 30, Label: "30 days"},
		{Days: 60, Label: "60 days"},
		{Days: 90, Label: "90 days", Default: true},
	}
}

func allowedAPITokenExpirationDays(raw string) (int, bool) {
	for _, option := range apiTokenExpirationOptions() {
		if raw == "" && option.Default {
			return option.Days, true
		}
		if raw == strconv.Itoa(option.Days) {
			return option.Days, true
		}
	}
	return 0, false
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
	if session.CSRFToken == "" || r.PostForm.Get("csrf_token") != session.CSRFToken {
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
		clearCookie(w, sessionCookieName, s.cookieSecure())
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
			ID:          t.id,
			PublicURL:   t.publicURL,
			Owner:       t.owner,
			LocalPort:   t.localPort,
			ConnectedAt: t.connectedAt.Unix(),
			Uptime:      formatUptime(time.Since(t.connectedAt)),
			Requests:    t.requests.Load(),
		})
	}
	sort.Slice(tunnels, func(i, j int) bool {
		return tunnels[i].ID < tunnels[j].ID
	})
	return tunnels
}

func totalRequests(tunnels []dashboardTunnel) int64 {
	var total int64
	for _, t := range tunnels {
		total += t.Requests
	}
	return total
}

// formatUptime renders a connection duration as a compact human string,
// e.g. "2h 14m", "41m", "12s".
func formatUptime(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	}
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

func (s *Server) disconnectApplicationTunnels(profileID string) {
	s.mu.RLock()
	targets := make([]*tunnel, 0)
	for _, t := range s.tunnels {
		if t.applicationProfileID == profileID {
			targets = append(targets, t)
		}
	}
	s.mu.RUnlock()
	for _, target := range targets {
		_ = target.conn.Close()
	}
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

//go:embed templates/dashboard.html
var dashboardHTML string

var dashboardTemplate = template.Must(template.New("dashboard").Parse(dashboardHTML))

//go:embed templates/tunnels_partial.html
var tunnelsPartialHTML string

var tunnelTablePartial = template.Must(template.New("tunnelTable").Parse(tunnelsPartialHTML))

//go:embed templates/dashboard.js
var dashboardJS []byte

func (s *Server) handleDashboardJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(dashboardJS)
}

func (s *Server) handleDashboardTunnels(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireSession(w, r)
	if !ok {
		return
	}

	tunnels := s.visibleTunnels(session)
	data := struct {
		Session       StoredSession
		Tunnels       []dashboardTunnel
		TotalRequests int64
	}{
		Session:       session,
		Tunnels:       tunnels,
		TotalRequests: totalRequests(tunnels),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'")
	if err := tunnelTablePartial.Execute(w, data); err != nil {
		s.cfg.Logger.Error("tunnel table partial render failed", "err", err)
	}
}
