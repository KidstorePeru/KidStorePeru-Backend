package fortnite

import (
	"sync"

	"github.com/google/uuid"
)

// accountLocks serializes sensitive per-account operations (currently gift
// sending) so two concurrent requests cannot both pass the remaining-slots
// check and over-send. This is an in-process lock and therefore assumes a
// single backend instance; a multi-instance deployment would need a database
// or distributed lock instead.
var accountLocks sync.Map // map[uuid.UUID]*sync.Mutex

// lockAccount acquires the lock for the given account and returns the unlock
// function, intended to be deferred by the caller.
func lockAccount(id uuid.UUID) func() {
	m, _ := accountLocks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
