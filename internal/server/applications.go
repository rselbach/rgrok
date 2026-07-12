package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	applicationNameMaxLength   = 80
	applicationRoutesMax       = 100
	applicationInstancesMax    = 1000
	applicationInstanceMaxIdle = 90 * 24 * time.Hour
)

type StoredApplicationProfile struct {
	ID                   string                               `json:"id"`
	Name                 string                               `json:"name"`
	PublicKey            string                               `json:"public_key"`
	PublicKeyFingerprint string                               `json:"public_key_fingerprint"`
	Routes               []StoredApplicationRoute             `json:"routes"`
	RequestsPerMinute    int                                  `json:"requests_per_minute"`
	RequestBurst         int                                  `json:"request_burst"`
	ConcurrentRequests   int                                  `json:"concurrent_requests"`
	Instances            map[string]StoredApplicationInstance `json:"instances,omitempty"`
	CreatedAt            time.Time                            `json:"created_at"`
}

type StoredApplicationRoute struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
}

type StoredApplicationInstance struct {
	TunnelID   string    `json:"tunnel_id"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

type applicationRateLimiter struct {
	mu       sync.Mutex
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
}

var (
	applicationIDRE = regexp.MustCompile(`^[a-f0-9]{32}$`)
	instanceIDRE    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	parameterRE     = regexp.MustCompile(`^\{[A-Za-z][A-Za-z0-9_]*\}$`)
)

func newApplicationRateLimiter(requestsPerMinute, burst int) *applicationRateLimiter {
	now := time.Now()
	return &applicationRateLimiter{
		rate:     float64(requestsPerMinute) / 60,
		capacity: float64(burst),
		tokens:   float64(burst),
		last:     now,
	}
}

func (l *applicationRateLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.rate
	if l.tokens > l.capacity {
		l.tokens = l.capacity
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

func parseApplicationRoutes(raw string) ([]StoredApplicationRoute, error) {
	lines := strings.Split(raw, "\n")
	routes := make([]StoredApplicationRoute, 0, len(lines))
	for number, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("route line %d must be METHODS PATH", number+1)
		}
		methods, err := parseApplicationMethods(fields[0])
		if err != nil {
			return nil, fmt.Errorf("route line %d: %w", number+1, err)
		}
		if err := validateApplicationPath(fields[1]); err != nil {
			return nil, fmt.Errorf("route line %d: %w", number+1, err)
		}
		routes = append(routes, StoredApplicationRoute{Methods: methods, Path: fields[1]})
	}
	if len(routes) == 0 {
		return nil, errors.New("at least one route is required")
	}
	if len(routes) > applicationRoutesMax {
		return nil, fmt.Errorf("applications cannot have more than %d routes", applicationRoutesMax)
	}
	return routes, nil
}

func parseApplicationMethods(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	methods := make([]string, 0, len(parts))
	seen := make(map[string]bool)
	for _, part := range parts {
		method := strings.ToUpper(strings.TrimSpace(part))
		if method == "" {
			return nil, errors.New("method is required")
		}
		if method != "*" && !validHTTPToken(method) {
			return nil, fmt.Errorf("invalid method %q", method)
		}
		if !seen[method] {
			methods = append(methods, method)
			seen[method] = true
		}
	}
	sort.Strings(methods)
	return methods, nil
}

func validHTTPToken(value string) bool {
	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return value != ""
}

func validateApplicationPath(value string) error {
	if value == "" || value[0] != '/' {
		return errors.New("path must start with /")
	}
	if value != "/" && strings.HasSuffix(value, "/") {
		return errors.New("trailing slashes are not allowed")
	}
	if strings.Contains(value, "//") || strings.Contains(value, "\\") {
		return errors.New("path contains an ambiguous separator")
	}
	for _, segment := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if segment == "." || segment == ".." {
			return errors.New("dot path segments are not allowed")
		}
		if strings.Contains(segment, "*") {
			return errors.New("wildcards are not allowed; use a full {name} segment")
		}
		if strings.ContainsAny(segment, "{}") && !parameterRE.MatchString(segment) {
			return fmt.Errorf("invalid path parameter %q", segment)
		}
	}
	return nil
}

func applicationRequestAllowed(routes []StoredApplicationRoute, r *http.Request) bool {
	if !safeApplicationRequestPath(r) {
		return false
	}
	for _, route := range routes {
		if applicationMethodAllowed(route.Methods, r.Method) && applicationPathMatches(route.Path, r.URL.Path) {
			return true
		}
	}
	return false
}

func safeApplicationRequestPath(r *http.Request) bool {
	escaped := strings.ToLower(r.URL.EscapedPath())
	if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
		return false
	}
	value := r.URL.Path
	if value == "" || strings.Contains(value, "//") || strings.Contains(value, "\\") {
		return false
	}
	return path.Clean(value) == value
}

func applicationMethodAllowed(methods []string, method string) bool {
	for _, allowed := range methods {
		if allowed == "*" || allowed == method {
			return true
		}
	}
	return false
}

func applicationPathMatches(pattern, value string) bool {
	patternSegments := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	valueSegments := strings.Split(strings.TrimPrefix(value, "/"), "/")
	if len(patternSegments) != len(valueSegments) {
		return false
	}
	for i, patternSegment := range patternSegments {
		if parameterRE.MatchString(patternSegment) {
			if valueSegments[i] == "" {
				return false
			}
			continue
		}
		if patternSegment != valueSegments[i] {
			return false
		}
	}
	return true
}

func parseEd25519PublicKey(value string) (string, ed25519.PublicKey, string, error) {
	fields := strings.Fields(value)
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		return "", nil, "", errors.New("public key must be an ssh-ed25519 key")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", nil, "", errors.New("public key is not valid OpenSSH base64")
	}
	keyType, rest, ok := readSSHString(blob)
	if !ok || string(keyType) != "ssh-ed25519" {
		return "", nil, "", errors.New("public key contains an invalid key type")
	}
	key, rest, ok := readSSHString(rest)
	if !ok || len(rest) != 0 || len(key) != ed25519.PublicKeySize {
		return "", nil, "", errors.New("public key contains invalid Ed25519 key data")
	}
	fingerprint := sha256.Sum256(blob)
	canonical := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
	return canonical, ed25519.PublicKey(key), "SHA256:" + base64.RawStdEncoding.EncodeToString(fingerprint[:]), nil
}

func readSSHString(value []byte) ([]byte, []byte, bool) {
	if len(value) < 4 {
		return nil, nil, false
	}
	length := uint64(binary.BigEndian.Uint32(value[:4]))
	if length > uint64(len(value)-4) {
		return nil, nil, false
	}
	return value[4 : 4+length], value[4+length:], true
}
