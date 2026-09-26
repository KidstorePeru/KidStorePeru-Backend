package db

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// FriendsState is what is known about an account's friend list.
type FriendsState struct {
	Count    *int       // number of friends, nil if it could not be read yet
	Full     bool       // the account cannot accept more friends
	SyncedAt *time.Time // last time this state was checked
}

// SetFriendsState stores a friend count read from Epic together with whether
// the list is full.
func SetFriendsState(db *sql.DB, accountID uuid.UUID, count int, full bool) error {
	_, err := db.Exec(`UPDATE game_accounts SET friends_count = $1, friends_full = $2, friends_synced_at = now() WHERE id = $3`, count, full, accountID)
	return err
}

// SetFriendsFull flips only the "full" flag (used when the count is unknown,
// e.g. Epic rejected an accept because the list is full).
func SetFriendsFull(db *sql.DB, accountID uuid.UUID, full bool) error {
	_, err := db.Exec(`UPDATE game_accounts SET friends_full = $1, friends_synced_at = now() WHERE id = $2`, full, accountID)
	return err
}

// GetFriendsStates returns the stored friend-list state of each account.
func GetFriendsStates(db *sql.DB, accountIDs []uuid.UUID) (map[uuid.UUID]FriendsState, error) {
	out := make(map[uuid.UUID]FriendsState)
	if len(accountIDs) == 0 {
		return out, nil
	}
	rows, err := db.Query(`SELECT id, friends_count, friends_full, friends_synced_at FROM game_accounts WHERE id = ANY($1)`, pq.Array(accountIDs))
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var count sql.NullInt64
		var full bool
		var at sql.NullTime
		if err := rows.Scan(&id, &count, &full, &at); err != nil {
			return out, err
		}
		st := FriendsState{Full: full}
		if count.Valid {
			n := int(count.Int64)
			st.Count = &n
		}
		if at.Valid {
			t := at.Time
			st.SyncedAt = &t
		}
		out[id] = st
	}
	return out, rows.Err()
}
