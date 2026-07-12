package server

import (
	"crypto/rand"
	"crypto/sha256"
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
const clientTokenMaxLifetime = 90 * 24 * time.Hour
const clientTokenNameMaxLength = 80

type Store struct {
	path string
	mu   sync.Mutex
	data storeData
}

type storeData struct {
	Users               map[string]StoredUser               `json:"users"`
	Sessions            map[string]StoredSession            `json:"sessions"`
	ClientTokens        map[string]StoredClientToken        `json:"client_tokens"`
	ApplicationProfiles map[string]StoredApplicationProfile `json:"application_profiles,omitempty"`
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
	PlainToken string    `json:"-"`
	Token      string    `json:"token,omitempty"`
	TokenHash  string    `json:"token_hash"`
	Name       string    `json:"name"`
	Login      string    `json:"login"`
	Admin      bool      `json:"admin"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
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
	if session.CSRFToken == "" || time.Now().UTC().After(session.ExpiresAt) {
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
	return s.CreateClientTokenWithLifetime(login, admin, clientTokenLifetime)
}

func (s *Store) CreateClientTokenWithLifetime(login string, admin bool, lifetime time.Duration) (StoredClientToken, error) {
	return s.CreateClientTokenWithNameAndLifetime(login, admin, "rgrok login", lifetime)
}

func (s *Store) CreateClientTokenWithNameAndLifetime(login string, admin bool, name string, lifetime time.Duration) (StoredClientToken, error) {
	login = normalizeLogin(login)
	name, err := normalizeClientTokenName(name)
	if err != nil {
		return StoredClientToken{}, err
	}
	if lifetime <= 0 {
		return StoredClientToken{}, errors.New("token lifetime must be positive")
	}
	if lifetime > clientTokenMaxLifetime {
		return StoredClientToken{}, errors.New("token lifetime cannot exceed 90 days")
	}
	token, err := randomHex(32)
	if err != nil {
		return StoredClientToken{}, err
	}
	now := time.Now().UTC()
	clientToken := StoredClientToken{
		PlainToken: token,
		TokenHash:  clientTokenHash(token),
		Name:       name,
		Login:      login,
		Admin:      admin,
		CreatedAt:  now,
		ExpiresAt:  now.Add(lifetime),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.ClientTokens == nil {
		s.data.ClientTokens = make(map[string]StoredClientToken)
	}
	storedToken := clientToken
	storedToken.PlainToken = ""
	s.data.ClientTokens[clientToken.TokenHash] = storedToken
	return clientToken, s.saveLocked()
}

func (s *Store) ListClientTokensForUser(login string) []StoredClientToken {
	login = normalizeLogin(login)
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	tokens := make([]StoredClientToken, 0)
	changed := false
	for tokenHash, ct := range s.data.ClientTokens {
		if now.After(ct.ExpiresAt) {
			delete(s.data.ClientTokens, tokenHash)
			changed = true
			continue
		}
		if normalizeLogin(ct.Login) != login {
			continue
		}
		ct.PlainToken = ""
		ct.Token = ""
		tokens = append(tokens, ct)
	}
	if changed {
		_ = s.saveLocked()
	}
	sort.Slice(tokens, func(i, j int) bool {
		if tokens[i].CreatedAt.Equal(tokens[j].CreatedAt) {
			return tokens[i].Name < tokens[j].Name
		}
		return tokens[i].CreatedAt.After(tokens[j].CreatedAt)
	})
	return tokens
}

func (s *Store) ClientToken(token string) (StoredClientToken, bool) {
	if token == "" {
		return StoredClientToken{}, false
	}
	tokenHash := clientTokenHash(token)

	s.mu.Lock()
	defer s.mu.Unlock()
	clientToken, ok := s.data.ClientTokens[tokenHash]
	if !ok {
		return StoredClientToken{}, false
	}
	if time.Now().UTC().After(clientToken.ExpiresAt) {
		delete(s.data.ClientTokens, tokenHash)
		_ = s.saveLocked()
		return StoredClientToken{}, false
	}
	return clientToken, true
}

func (s *Store) RevokeClientTokenForUser(login string, tokenHash string) (bool, error) {
	login = normalizeLogin(login)
	tokenHash = strings.TrimSpace(tokenHash)
	if tokenHash == "" {
		return false, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	ct, ok := s.data.ClientTokens[tokenHash]
	if !ok || normalizeLogin(ct.Login) != login {
		return false, nil
	}
	delete(s.data.ClientTokens, tokenHash)
	return true, s.saveLocked()
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

type applicationProfileValues struct {
	name                 string
	publicKey            string
	publicKeyFingerprint string
	routes               []StoredApplicationRoute
	requestsPerMinute    int
	requestBurst         int
	concurrentRequests   int
}

func applicationProfileValuesFrom(name, publicKey string, routes []StoredApplicationRoute, requestsPerMinute, requestBurst, concurrentRequests int) (applicationProfileValues, error) {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		return applicationProfileValues{}, errors.New("application name is required")
	}
	if len(name) > applicationNameMaxLength {
		return applicationProfileValues{}, errors.New("application name must be 80 characters or less")
	}
	canonicalKey, _, fingerprint, err := parseEd25519PublicKey(publicKey)
	if err != nil {
		return applicationProfileValues{}, err
	}
	if len(routes) == 0 {
		return applicationProfileValues{}, errors.New("at least one route is required")
	}
	if requestsPerMinute <= 0 || requestBurst <= 0 || concurrentRequests <= 0 {
		return applicationProfileValues{}, errors.New("application limits must be positive")
	}
	return applicationProfileValues{
		name:                 name,
		publicKey:            canonicalKey,
		publicKeyFingerprint: fingerprint,
		routes:               cloneApplicationRoutes(routes),
		requestsPerMinute:    requestsPerMinute,
		requestBurst:         requestBurst,
		concurrentRequests:   concurrentRequests,
	}, nil
}

func (s *Store) CreateApplicationProfile(name, publicKey string, routes []StoredApplicationRoute, requestsPerMinute, requestBurst, concurrentRequests int) (StoredApplicationProfile, error) {
	values, err := applicationProfileValuesFrom(name, publicKey, routes, requestsPerMinute, requestBurst, concurrentRequests)
	if err != nil {
		return StoredApplicationProfile{}, err
	}
	id, err := randomHex(16)
	if err != nil {
		return StoredApplicationProfile{}, err
	}
	profile := StoredApplicationProfile{
		ID:                   id,
		Name:                 values.name,
		PublicKey:            values.publicKey,
		PublicKeyFingerprint: values.publicKeyFingerprint,
		Routes:               values.routes,
		RequestsPerMinute:    values.requestsPerMinute,
		RequestBurst:         values.requestBurst,
		ConcurrentRequests:   values.concurrentRequests,
		Instances:            make(map[string]StoredApplicationInstance),
		CreatedAt:            time.Now().UTC(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.data.ApplicationProfiles {
		if existing.PublicKey == values.publicKey {
			return StoredApplicationProfile{}, errors.New("public key is already used by another application")
		}
	}
	if s.data.ApplicationProfiles == nil {
		s.data.ApplicationProfiles = make(map[string]StoredApplicationProfile)
	}
	s.data.ApplicationProfiles[id] = profile
	return profile, s.saveLocked()
}

func (s *Store) UpdateApplicationProfile(id, name, publicKey string, routes []StoredApplicationRoute, requestsPerMinute, requestBurst, concurrentRequests int) (StoredApplicationProfile, error) {
	values, err := applicationProfileValuesFrom(name, publicKey, routes, requestsPerMinute, requestBurst, concurrentRequests)
	if err != nil {
		return StoredApplicationProfile{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	profile, ok := s.data.ApplicationProfiles[id]
	if !ok {
		return StoredApplicationProfile{}, errors.New("application profile not found")
	}
	for existingID, existing := range s.data.ApplicationProfiles {
		if existingID != id && existing.PublicKey == values.publicKey {
			return StoredApplicationProfile{}, errors.New("public key is already used by another application")
		}
	}
	profile.Name = values.name
	profile.PublicKey = values.publicKey
	profile.PublicKeyFingerprint = values.publicKeyFingerprint
	profile.Routes = values.routes
	profile.RequestsPerMinute = values.requestsPerMinute
	profile.RequestBurst = values.requestBurst
	profile.ConcurrentRequests = values.concurrentRequests
	s.data.ApplicationProfiles[id] = profile
	return cloneApplicationProfile(profile), s.saveLocked()
}

func (s *Store) ApplicationProfile(id string) (StoredApplicationProfile, bool) {
	if !applicationIDRE.MatchString(id) {
		return StoredApplicationProfile{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, ok := s.data.ApplicationProfiles[id]
	if !ok {
		return StoredApplicationProfile{}, false
	}
	return cloneApplicationProfile(profile), true
}

func (s *Store) ListApplicationProfiles() []StoredApplicationProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	profiles := make([]StoredApplicationProfile, 0, len(s.data.ApplicationProfiles))
	for _, profile := range s.data.ApplicationProfiles {
		profiles = append(profiles, cloneApplicationProfile(profile))
	}
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})
	return profiles
}

func (s *Store) DeleteApplicationProfile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.ApplicationProfiles[id]; !ok {
		return errors.New("application profile not found")
	}
	delete(s.data.ApplicationProfiles, id)
	return s.saveLocked()
}

func (s *Store) ApplicationTunnelID(profileID, instanceID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.ApplicationProfiles[profileID].Instances[instanceID].TunnelID
}

func (s *Store) RememberApplicationTunnel(profileID, instanceID, tunnelID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, ok := s.data.ApplicationProfiles[profileID]
	if !ok {
		return errors.New("application profile not found")
	}
	if profile.Instances == nil {
		profile.Instances = make(map[string]StoredApplicationInstance)
	}
	now := time.Now().UTC()
	for id, instance := range profile.Instances {
		if now.Sub(instance.LastUsedAt) > applicationInstanceMaxIdle {
			delete(profile.Instances, id)
		}
	}
	if _, exists := profile.Instances[instanceID]; !exists && len(profile.Instances) >= applicationInstancesMax {
		return errors.New("application has too many remembered instances")
	}
	instance := profile.Instances[instanceID]
	if instance.CreatedAt.IsZero() {
		instance.CreatedAt = now
	}
	instance.TunnelID = tunnelID
	instance.LastUsedAt = now
	profile.Instances[instanceID] = instance
	s.data.ApplicationProfiles[profileID] = profile
	return s.saveLocked()
}

func (s *Store) UnreserveApplicationTunnel(profileID, instanceID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, ok := s.data.ApplicationProfiles[profileID]
	if !ok {
		return false, nil
	}
	if _, ok := profile.Instances[instanceID]; !ok {
		return false, nil
	}
	delete(profile.Instances, instanceID)
	s.data.ApplicationProfiles[profileID] = profile
	return true, s.saveLocked()
}

func cloneApplicationProfile(profile StoredApplicationProfile) StoredApplicationProfile {
	profile.Routes = cloneApplicationRoutes(profile.Routes)
	instances := profile.Instances
	profile.Instances = make(map[string]StoredApplicationInstance, len(instances))
	for id, instance := range instances {
		profile.Instances[id] = instance
	}
	return profile
}

func cloneApplicationRoutes(routes []StoredApplicationRoute) []StoredApplicationRoute {
	cloned := make([]StoredApplicationRoute, len(routes))
	for i, route := range routes {
		cloned[i] = route
		cloned[i].Methods = append([]string(nil), route.Methods...)
	}
	return cloned
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = storeData{
		Users:               make(map[string]StoredUser),
		Sessions:            make(map[string]StoredSession),
		ClientTokens:        make(map[string]StoredClientToken),
		ApplicationProfiles: make(map[string]StoredApplicationProfile),
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
	if s.data.ApplicationProfiles == nil {
		s.data.ApplicationProfiles = make(map[string]StoredApplicationProfile)
	}
	changed := s.migrateClientTokensLocked()
	if s.dropSessionsMissingCSRFLocked() {
		changed = true
	}
	if s.migrateApplicationInstancesLocked() {
		changed = true
	}
	if changed {
		return s.saveLocked()
	}
	return nil
}

func (s *Store) migrateApplicationInstancesLocked() bool {
	changed := false
	for id, profile := range s.data.ApplicationProfiles {
		for instanceID, instance := range profile.Instances {
			if !instance.CreatedAt.IsZero() {
				continue
			}
			instance.CreatedAt = instance.LastUsedAt
			if instance.CreatedAt.IsZero() {
				instance.CreatedAt = profile.CreatedAt
			}
			profile.Instances[instanceID] = instance
			changed = true
		}
		s.data.ApplicationProfiles[id] = profile
	}
	return changed
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

func clientTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Store) migrateClientTokensLocked() bool {
	migrated := false
	tokens := make(map[string]StoredClientToken, len(s.data.ClientTokens))
	for key, ct := range s.data.ClientTokens {
		originalToken := ct.Token
		if ct.TokenHash == "" && ct.Token != "" {
			ct.TokenHash = clientTokenHash(ct.Token)
		}
		ct.Token = ""
		if ct.TokenHash == "" {
			migrated = true
			continue
		}
		if strings.TrimSpace(ct.Name) == "" {
			ct.Name = "Legacy token"
			migrated = true
		}
		tokens[ct.TokenHash] = ct
		if key != ct.TokenHash || originalToken != "" {
			migrated = true
		}
	}
	if migrated {
		s.data.ClientTokens = tokens
	}
	return migrated
}

func (s *Store) dropSessionsMissingCSRFLocked() bool {
	changed := false
	for id, session := range s.data.Sessions {
		if session.CSRFToken != "" {
			continue
		}
		delete(s.data.Sessions, id)
		changed = true
	}
	return changed
}

func normalizeClientTokenName(name string) (string, error) {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		return "", errors.New("token name is required")
	}
	if len(name) > clientTokenNameMaxLength {
		return "", errors.New("token name must be 80 characters or less")
	}
	return name, nil
}
