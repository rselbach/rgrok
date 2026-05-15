package atomicfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteJSONWritesPrivateFile(t *testing.T) {
	r := require.New(t)
	path := filepath.Join(t.TempDir(), "nested", "store.json")

	err := WriteJSON(path, map[string]string{"dean": "pelton"})
	r.NoError(err)

	file, err := os.Open(path)
	r.NoError(err)
	defer file.Close()

	var got map[string]string
	r.NoError(json.NewDecoder(file).Decode(&got))
	r.Equal("pelton", got["dean"])

	info, err := os.Stat(path)
	r.NoError(err)
	r.Equal(os.FileMode(0o600), info.Mode().Perm())
}

func TestWriteJSONReplacesExistingFile(t *testing.T) {
	r := require.New(t)
	path := filepath.Join(t.TempDir(), "store.json")
	r.NoError(os.WriteFile(path, []byte(`{"old":"value"}`), 0o600))

	err := WriteJSON(path, map[string]string{"new": "value"})
	r.NoError(err)

	data, err := os.ReadFile(path)
	r.NoError(err)
	r.Contains(string(data), `"new"`)
	r.NotContains(string(data), `"old"`)
}
