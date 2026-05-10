package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rselbach/rgrok/internal/atomicfile"
)

const clientTokenLifetime = 90 * 24 * time.Hour

type Store struct {
	path string
	mu   sync.Mutex
	data storeData
}

type storeData struct {
	Users        map[string]StoredUser        `json:"users"`
	Sessions     map[string]StoredSession     `json:"sessions"`
	ClientTokens map[string]StoredClientToken `json:"client_tokens"`
}

type StoredUser struct {
	Login     string    `json:"login"`
	Admin     bool      `json:"admin"`
	CreatedAt time.Time `json:"created_at"`
}

type StoredSession struct {
	ID        string    `json:"id"`
	Login     string    `json:"login"`
	Admin     bool      `json:"admin"`
	CSRFToken string    `json:"csrf_token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type StoredClientToken struct {
	Token     string    `json:"token"`
	Login     string    `json:"login"`
	Admin     bool      `json:"admin"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func OpenStore(path string) (*Store, error) {
	if path == "" {
		path = "rgrok.json"
	}
	s := &Store{path: path}
	if err := s.load(); err != nil {
		return nil, err
	}
	if err := s.ensureDefaultAdmin(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) IsAllowed(login string) (StoredUser, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.data.Users[normalizeLogin(login)]
	return user, ok
}

func (s *Store) ListUsers() []StoredUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	users := make([]StoredUser, 0, len(s.data.Users))
	for _, user := range s.data.Users {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].Login < users[j].Login
	})
	return users
}

func (s *Store) UpsertUser(login string, admin bool) error {
	login = normalizeLogin(login)
	if login == "" {
		return errors.New("login is required")
	}
	if login == "rselbach" {
		admin = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Users == nil {
		s.data.Users = make(map[string]StoredUser)
	}
	user := s.data.Users[login]
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now().UTC()
	}
	user.Login = login
	user.Admin = admin
	s.data.Users[login] = user
	return s.saveLocked()
}

func (s *Store) DeleteUser(login string) error {
	login = normalizeLogin(login)
	if login == "rselbach" {
		return errors.New("cannot remove default admin rselbach")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.Users, login)
	for id, session := range s.data.Sessions {
		if normalizeLogin(session.Login) == login {
			delete(s.data.Sessions, id)
		}
	}
	for token, clientToken := range s.data.ClientTokens {
		if normalizeLogin(clientToken.Login) == login {
			delete(s.data.ClientTokens, token)
		}
	}
	return s.saveLocked()
}

func (s *Store) CreateSession(login string, admin bool) (StoredSession, error) {
	login = normalizeLogin(login)
	id, err := randomHex(32)
	if err != nil {
		return StoredSession{}, err
	}
	csrf, err := randomHex(32)
	if err != nil {
		return StoredSession{}, err
	}
	session := StoredSession{
		ID:        id,
		Login:     login,
		Admin:     admin,
		CSRFToken: csrf,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Sessions == nil {
		s.data.Sessions = make(map[string]StoredSession)
	}
	s.data.Sessions[id] = session
	return session, s.saveLocked()
}

func (s *Store) Session(id string) (StoredSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.data.Sessions[id]
	if !ok {
		return StoredSession{}, false
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		delete(s.data.Sessions, id)
		_ = s.saveLocked()
		return StoredSession{}, false
	}
	return session, true
}

func (s *Store) DeleteSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.Sessions, id)
	return s.saveLocked()
}

func (s *Store) CreateClientToken(login string, admin bool) (StoredClientToken, error) {
	login = normalizeLogin(login)
	token, err := randomHex(32)
	if err != nil {
		return StoredClientToken{}, err
	}
	now := time.Now().UTC()
	clientToken := StoredClientToken{
		Token:     token,
		Login:     login,
		Admin:     admin,
		CreatedAt: now,
		ExpiresAt: now.Add(clientTokenLifetime),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.ClientTokens == nil {
		s.data.ClientTokens = make(map[string]StoredClientToken)
	}
	s.data.ClientTokens[token] = clientToken
	return clientToken, s.saveLocked()
}

func (s *Store) ClientToken(token string) (StoredClientToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clientToken, ok := s.data.ClientTokens[token]
	if !ok {
		return StoredClientToken{}, false
	}
	if time.Now().UTC().After(clientToken.ExpiresAt) {
		delete(s.data.ClientTokens, token)
		_ = s.saveLocked()
		return StoredClientToken{}, false
	}
	return clientToken, true
}

func (s *Store) RevokeClientTokensForUser(login string) error {
	login = normalizeLogin(login)
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, ct := range s.data.ClientTokens {
		if normalizeLogin(ct.Login) == login {
			delete(s.data.ClientTokens, token)
		}
	}
	return s.saveLocked()
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = storeData{
		Users:        make(map[string]StoredUser),
		Sessions:     make(map[string]StoredSession),
		ClientTokens: make(map[string]StoredClientToken),
	}

	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&s.data); err != nil {
		return err
	}
	if s.data.Users == nil {
		s.data.Users = make(map[string]StoredUser)
	}
	if s.data.Sessions == nil {
		s.data.Sessions = make(map[string]StoredSession)
	}
	if s.data.ClientTokens == nil {
		s.data.ClientTokens = make(map[string]StoredClientToken)
	}
	return nil
}

func (s *Store) ensureDefaultAdmin() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Users == nil {
		s.data.Users = make(map[string]StoredUser)
	}
	user := s.data.Users["rselbach"]
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now().UTC()
	}
	user.Login = "rselbach"
	user.Admin = true
	s.data.Users["rselbach"] = user
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	return atomicfile.WriteJSON(s.path, s.data)
}

func normalizeLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

func randomHex(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
