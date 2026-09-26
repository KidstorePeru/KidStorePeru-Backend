package utils

import (
	"sync"
	"time"
)

// AttemptLimiter is a small in-memory sliding-window limiter used to slow down
// password guessing. It is per process, which matches the single Railway
// instance this backend runs on.
type AttemptLimiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	failures map[string][]time.Time
}

func NewAttemptLimiter(max int, window time.Duration) *AttemptLimiter {
	return &AttemptLimiter{max: max, window: window, failures: make(map[string][]time.Time)}
}

// prune drops expired failures for key and returns what is left. Caller holds mu.
func (l *AttemptLimiter) prune(key string, now time.Time) []time.Time {
	kept := l.failures[key][:0]
	for _, t := range l.failures[key] {
		if now.Sub(t) < l.window {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.failures, key)
		return nil
	}
	l.failures[key] = kept
	return kept
}

// Allow reports whether key may try again (fewer than max recent failures).
func (l *AttemptLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key, time.Now())) < l.max
}

// Fail records a failed attempt for key.
func (l *AttemptLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.failures) > 10000 { // bound memory under a spray of random keys
		for k := range l.failures {
			l.prune(k, now)
		}
	}
	l.failures[key] = append(l.prune(key, now), now)
}

// Reset forgets key's failures (after a successful login).
func (l *AttemptLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}
