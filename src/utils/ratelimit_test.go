package utils

import (
	"testing"
	"time"
)

func TestAttemptLimiter(t *testing.T) {
	l := NewAttemptLimiter(3, 50*time.Millisecond)
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("attempt %d should be allowed", i)
		}
		l.Fail("a")
	}
	if l.Allow("a") {
		t.Error("4th attempt should be blocked")
	}
	if !l.Allow("b") {
		t.Error("other keys must be independent")
	}
	time.Sleep(60 * time.Millisecond)
	if !l.Allow("a") {
		t.Error("should be allowed again after the window")
	}
	l.Fail("a")
	l.Reset("a")
	if !l.Allow("a") {
		t.Error("Reset should clear the failures")
	}
}
