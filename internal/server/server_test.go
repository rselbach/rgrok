package server

import (
	"strings"
	"testing"
)

func TestRandomIDIsCommunityPhrase(t *testing.T) {
	for range 100 {
		id := randomID()
		if !nameRE.MatchString(id) {
			t.Fatalf("randomID generated invalid DNS label %q", id)
		}
		if strings.Count(id, "-") < 2 {
			t.Fatalf("randomID should be a hyphenated phrase, got %q", id)
		}
	}
}
