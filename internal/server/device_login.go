package server

import (
	"encoding/json"
	"net/http"
	"time"
)

type deviceStartResponse struct {
	ID              string `json:"id"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type devicePollResponse struct {
	Status string `json:"status"`
	Token  string `json:"token,omitempty"`
	Login  string `json:"login,omitempty"`
	Error  string `json:"error,omitempty"`
}

func (s *Server) handleDeviceLoginStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.GitHubClientID == "" {
		http.Error(w, "GitHub OAuth is not configured", http.StatusServiceUnavailable)
		return
	}

	device, err := s.github.StartDeviceFlow(r.Context())
	if err != nil {
		http.Error(w, "could not start GitHub device login", http.StatusBadGateway)
		return
	}
	id, err := randomHex(24)
	if err != nil {
		http.Error(w, "could not create login id", http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.deviceLogins[id] = &deviceLogin{
		ID:         id,
		DeviceCode: device.DeviceCode,
		ExpiresAt:  time.Now().UTC().Add(time.Duration(device.ExpiresIn) * time.Second),
		Interval:   device.Interval,
	}
	s.mu.Unlock()

	s.cfg.Logger.Info("device login started", "id", id, "user_code", device.UserCode)
	writeJSON(w, deviceStartResponse{
		ID:              id,
		UserCode:        device.UserCode,
		VerificationURI: device.VerificationURI,
		ExpiresIn:       device.ExpiresIn,
		Interval:        device.Interval,
	})
}

func (s *Server) handleDeviceLoginPoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	login := s.deviceLogin(id)
	if login == nil {
		writeJSON(w, devicePollResponse{Status: "expired"})
		return
	}

	if !s.updateLastPoll(id, login.Interval) {
		s.cfg.Logger.Debug("device login poll rate limited", "id", id)
		writeJSON(w, devicePollResponse{Status: "pending"})
		return
	}

	token, err := s.github.PollDeviceFlowOnce(r.Context(), login.DeviceCode)
	if err != nil {
		s.cfg.Logger.Warn("device login poll failed", "id", id, "err", err)
		writeJSON(w, devicePollResponse{Status: "error", Error: err.Error()})
		return
	}
	switch token.Error {
	case "":
		s.cfg.Logger.Info("device login token received", "id", id, "token_present", token.AccessToken != "")
	case "authorization_pending":
		s.cfg.Logger.Debug("device login still pending", "id", id)
		writeJSON(w, devicePollResponse{Status: "pending"})
		return
	case "slow_down":
		s.mu.Lock()
		if dev := s.deviceLogins[id]; dev != nil {
			dev.Interval += 5
			s.cfg.Logger.Info("device login slow_down received, increasing interval", "id", id, "new_interval", dev.Interval)
		}
		s.mu.Unlock()
		writeJSON(w, devicePollResponse{Status: "pending"})
		return
	case "expired_token":
		s.deleteDeviceLogin(id)
		s.cfg.Logger.Info("device login expired_token received", "id", id)
		writeJSON(w, devicePollResponse{Status: "expired"})
		return
	default:
		s.cfg.Logger.Warn("device login returned error", "id", id, "error", token.Error, "description", token.Description)
		writeJSON(w, devicePollResponse{Status: "error", Error: token.Error})
		return
	}

	ghUser, err := s.github.User(r.Context(), token.AccessToken)
	if err != nil {
		s.cfg.Logger.Warn("device login user lookup failed", "id", id, "err", err)
		writeJSON(w, devicePollResponse{Status: "error", Error: "GitHub user lookup failed"})
		return
	}
	storedUser, ok := s.store.IsAllowed(ghUser.Login)
	if !ok {
		s.deleteDeviceLogin(id)
		s.cfg.Logger.Info("device login denied by whitelist", "id", id, "github_user", ghUser.Login)
		writeJSON(w, devicePollResponse{Status: "denied", Login: ghUser.Login})
		return
	}
	clientToken, err := s.store.CreateClientToken(storedUser.Login, storedUser.Admin)
	if err != nil {
		s.cfg.Logger.Warn("device login token creation failed", "id", id, "err", err)
		writeJSON(w, devicePollResponse{Status: "error", Error: "could not create rgrok token"})
		return
	}
	s.deleteDeviceLogin(id)
	s.cfg.Logger.Info("device login complete", "id", id, "login", clientToken.Login)
	writeJSON(w, devicePollResponse{Status: "complete", Token: clientToken.Token, Login: clientToken.Login})
}

func (s *Server) deviceLogin(id string) *deviceLogin {
	s.mu.Lock()
	defer s.mu.Unlock()
	login := s.deviceLogins[id]
	if login == nil {
		return nil
	}
	if time.Now().UTC().After(login.ExpiresAt) {
		delete(s.deviceLogins, id)
		return nil
	}
	return login
}

func (s *Server) updateLastPoll(id string, interval int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	login := s.deviceLogins[id]
	if login == nil {
		return false
	}
	now := time.Now().UTC()
	if now.Before(login.LastPoll.Add(time.Duration(interval) * time.Second)) {
		return false
	}
	login.LastPoll = now
	return true
}

func (s *Server) deleteDeviceLogin(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.deviceLogins, id)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
