package fortnite

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// A gift POST is retried after a token refresh. Without rewinding, the retry
// sends an empty body and Epic rejects the gift.
func TestRewindRequestBody(t *testing.T) {
	const payload = `{"offerId":"v2:/abc","expectedTotalPrice":1200}`

	req, err := http.NewRequest("POST", "https://example.com", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	// Simulate the first client.Do draining the body.
	first, _ := io.ReadAll(req.Body)
	req.Body.Close()
	if string(first) != payload {
		t.Fatalf("first read = %q", first)
	}

	// Without a rewind the body is now empty.
	drained, _ := io.ReadAll(req.Body)
	if len(drained) != 0 {
		t.Fatalf("expected drained body, got %q", drained)
	}

	// After the rewind the retry sees the full payload again.
	rewindRequestBody(req)
	second, _ := io.ReadAll(req.Body)
	if string(second) != payload {
		t.Errorf("after rewind = %q, want %q", second, payload)
	}
}

func TestRewindRequestBodyNoBody(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	rewindRequestBody(req) // must not panic
}
