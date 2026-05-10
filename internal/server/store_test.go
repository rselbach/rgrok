package server

import (
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
	_, ok = store.ClientToken(token.Token)
	r.False(ok)
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
