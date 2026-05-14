package server

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOpenStoreCreatesDefaultAdmin(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	user, ok := store.IsAllowed("rselbach")
	r.True(ok)
	r.True(user.Admin)
	r.Equal("rselbach", user.Login)
}

func TestUpsertUser(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	r.NoError(store.UpsertUser("troy", false))

	user, ok := store.IsAllowed("troy")
	r.True(ok)
	r.False(user.Admin)

	// Promote to admin.
	r.NoError(store.UpsertUser("troy", true))
	user, ok = store.IsAllowed("troy")
	r.True(ok)
	r.True(user.Admin)
}

func TestUpsertUserRequiresLogin(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	err = store.UpsertUser("", false)
	r.Error(err)
	r.Contains(err.Error(), "login is required")
}

func TestDeleteUser(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	r.NoError(store.UpsertUser("abed", false))
	session, err := store.CreateSession("abed", false)
	r.NoError(err)
	token, err := store.CreateClientToken("abed", false)
	r.NoError(err)

	r.NoError(store.DeleteUser("abed"))

	_, ok := store.IsAllowed("abed")
	r.False(ok)
	_, ok = store.Session(session.ID)
	r.False(ok)
	_, ok = store.ClientToken(token.PlainToken)
	r.False(ok)
}

func TestClientTokenStoredAsHash(t *testing.T) {
	r := require.New(t)
	path := t.TempDir() + "/test.json"
	store, err := OpenStore(path)
	r.NoError(err)

	token, err := store.CreateClientTokenWithNameAndLifetime("abed", false, "Work laptop", 30*24*time.Hour)
	r.NoError(err)
	r.NotEmpty(token.PlainToken)
	r.NotEmpty(token.TokenHash)
	r.Equal("Work laptop", token.Name)
	r.Empty(token.Token)

	raw, err := os.ReadFile(path)
	r.NoError(err)
	r.NotContains(string(raw), token.PlainToken)
	r.Contains(string(raw), `"token_hash"`)
	r.Contains(string(raw), `"name": "Work laptop"`)
}

func TestListClientTokensForUserAllowsMultipleNamedTokens(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	first, err := store.CreateClientTokenWithNameAndLifetime("abed", false, "Laptop", 30*24*time.Hour)
	r.NoError(err)
	time.Sleep(time.Millisecond)
	second, err := store.CreateClientTokenWithNameAndLifetime("abed", false, "CI deploy", 7*24*time.Hour)
	r.NoError(err)
	_, err = store.CreateClientTokenWithNameAndLifetime("troy", false, "Other user", 7*24*time.Hour)
	r.NoError(err)

	tokens := store.ListClientTokensForUser("ABED")
	r.Len(tokens, 2)
	r.Equal("CI deploy", tokens[0].Name)
	r.Equal("Laptop", tokens[1].Name)
	r.Empty(tokens[0].PlainToken)
	r.Empty(tokens[1].PlainToken)

	_, ok := store.ClientToken(first.PlainToken)
	r.True(ok)
	_, ok = store.ClientToken(second.PlainToken)
	r.True(ok)
}

func TestCreateClientTokenRequiresName(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	_, err = store.CreateClientTokenWithNameAndLifetime("abed", false, "", 30*24*time.Hour)
	r.Error(err)
	r.Contains(err.Error(), "token name is required")
}

func TestRevokeClientTokenForUser(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	abedToken, err := store.CreateClientTokenWithNameAndLifetime("abed", false, "Laptop", 30*24*time.Hour)
	r.NoError(err)
	troyToken, err := store.CreateClientTokenWithNameAndLifetime("troy", false, "Deploy", 30*24*time.Hour)
	r.NoError(err)

	deleted, err := store.RevokeClientTokenForUser("abed", troyToken.TokenHash)
	r.NoError(err)
	r.False(deleted)
	_, ok := store.ClientToken(troyToken.PlainToken)
	r.True(ok)

	deleted, err = store.RevokeClientTokenForUser("abed", abedToken.TokenHash)
	r.NoError(err)
	r.True(deleted)
	_, ok = store.ClientToken(abedToken.PlainToken)
	r.False(ok)
}

func TestOpenStoreMigratesLegacyPlaintextClientToken(t *testing.T) {
	r := require.New(t)
	path := t.TempDir() + "/test.json"
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	created := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	legacyToken := "legacy-plaintext-token"
	raw := fmt.Sprintf(`{
		"users": {},
		"sessions": {},
		"client_tokens": {
			%q: {
				"token": %q,
				"login": "abed",
				"admin": false,
				"created_at": %q,
				"expires_at": %q
			}
		}
	}`, legacyToken, legacyToken, created, expires)
	r.NoError(os.WriteFile(path, []byte(raw), 0o600))

	store, err := OpenStore(path)
	r.NoError(err)

	ct, ok := store.ClientToken(legacyToken)
	r.True(ok)
	r.Equal("abed", ct.Login)
	r.Equal("Legacy token", ct.Name)
	r.Empty(ct.Token)
	r.NotEmpty(ct.TokenHash)

	persisted, err := os.ReadFile(path)
	r.NoError(err)
	r.False(strings.Contains(string(persisted), legacyToken), "legacy plaintext token should be removed after load")
	r.Contains(string(persisted), `"token_hash"`)
}

func TestDeleteUserCannotDeleteDefaultAdmin(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	err = store.DeleteUser("rselbach")
	r.Error(err)
	r.Contains(err.Error(), "cannot remove default admin")
}

func TestDeleteUserNormalizesLogin(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	r.NoError(store.UpsertUser("Troy", false))
	r.NoError(store.DeleteUser("troy"))

	_, ok := store.IsAllowed("troy")
	r.False(ok)
}

func TestSessionExpiry(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	session, err := store.CreateSession("troy", false)
	r.NoError(err)

	// Fresh session is valid.
	_, ok := store.Session(session.ID)
	r.True(ok)

	// Manually expire the session in the store.
	store.mu.Lock()
	expired := store.data.Sessions[session.ID]
	expired.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	store.data.Sessions[session.ID] = expired
	store.mu.Unlock()

	_, ok = store.Session(session.ID)
	r.False(ok, "expired session should be rejected")
}

func TestDeleteSession(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	session, err := store.CreateSession("troy", false)
	r.NoError(err)

	r.NoError(store.DeleteSession(session.ID))

	_, ok := store.Session(session.ID)
	r.False(ok)
}

func TestListUsers(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	r.NoError(store.UpsertUser("troy", false))
	r.NoError(store.UpsertUser("abed", true))

	users := store.ListUsers()
	r.Len(users, 3) // rselbach (default) + troy + abed

	// Should be sorted by login.
	r.Equal("abed", users[0].Login)
	r.Equal("rselbach", users[1].Login)
	r.Equal("troy", users[2].Login)
}

func TestStorePersistence(t *testing.T) {
	r := require.New(t)
	path := t.TempDir() + "/persist.json"

	store1, err := OpenStore(path)
	r.NoError(err)

	r.NoError(store1.UpsertUser("britta", false))
	session, err := store1.CreateSession("britta", false)
	r.NoError(err)

	// Re-open the same file.
	store2, err := OpenStore(path)
	r.NoError(err)

	user, ok := store2.IsAllowed("britta")
	r.True(ok)
	r.Equal("britta", user.Login)

	_, ok = store2.Session(session.ID)
	r.True(ok)
}

func TestUpsertUserForcesRselbachAdmin(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)

	// Try to demote rselbach.
	r.NoError(store.UpsertUser("rselbach", false))

	user, ok := store.IsAllowed("rselbach")
	r.True(ok)
	r.True(user.Admin, "rselbach must always be admin")
}
