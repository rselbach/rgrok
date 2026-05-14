package httputil

import (
	"net/http"
	"testing"
)

func TestRemoveHopHeadersRemovesConnectionListedHeaders(t *testing.T) {
	h := http.Header{}
	h.Add("Connection", "X-Trace-ID, x-internal-token")
	h.Add("Connection", "Keep-Alive")
	h.Set("X-Trace-ID", "trace")
	h.Set("X-Internal-Token", "secret")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Content-Type", "text/plain")

	RemoveHopHeaders(h)

	if got := h.Get("X-Trace-ID"); got != "" {
		t.Fatalf("X-Trace-ID was not removed: %q", got)
	}
	if got := h.Get("X-Internal-Token"); got != "" {
		t.Fatalf("X-Internal-Token was not removed: %q", got)
	}
	if got := h.Get("Connection"); got != "" {
		t.Fatalf("Connection was not removed: %q", got)
	}
	if got := h.Get("Keep-Alive"); got != "" {
		t.Fatalf("Keep-Alive was not removed: %q", got)
	}
	if got := h.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("Content-Type changed: %q", got)
	}
}
