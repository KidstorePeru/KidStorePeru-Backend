package fortnite

import (
	"net/http"
	"time"
)

// epicHTTPClient is the shared HTTP client for all calls to Epic Games services.
// It has an explicit timeout so a hung connection can never block a request
// handler (or the per-account gift lock) indefinitely.
var epicHTTPClient = &http.Client{Timeout: 20 * time.Second}
