package fortnite

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	defaultMaxFriends = 1000
	// A full account is checked again this often (to notice friends removed by
	// hand); friend counts of the others are refreshed at the same pace.
	friendsRecheckEvery = 10 * time.Minute
)

func maxFriends() int {
	if utils.Config.MaxFriends > 0 {
		return utils.Config.MaxFriends
	}
	return defaultMaxFriends
}

// isFriendsFullError reports whether Epic refused to accept a friend request
// because the account's own friend list is full.
func isFriendsFullError(err error) bool {
	var ee *epicError
	return errors.As(err, &ee) && strings.Contains(ee.Code, "invitee_friendships_limit_exceeded")
}

func isThrottledError(err error) bool {
	var ee *epicError
	return errors.As(err, &ee) && ee.Status == http.StatusTooManyRequests
}

// friendsSummary is the part of Epic's friends summary this app uses.
type friendsSummary struct {
	Friends       []json.RawMessage `json:"friends"`
	LimitsReached struct {
		Accepted bool `json:"accepted"`
	} `json:"limitsReached"`
}

// fetchFriendsCount reads how many friends the account has.
func fetchFriendsCount(db *sql.DB, accountID uuid.UUID) (count int, acceptedLimit bool, err error) {
	hexID, err := utils.ConvertUUIDToString(accountID)
	if err != nil {
		return 0, false, err
	}
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/friends/api/v1/%s/summary", epicFriendsBase, hexID), nil)
	resp, err := ExecuteOperationWithRefresh(req, db, accountID, "friendsSummary")
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != http.StatusOK {
		return 0, false, parseEpicError(resp.StatusCode, body)
	}
	var s friendsSummary
	if err := json.Unmarshal(body, &s); err != nil || s.Friends == nil {
		return 0, false, fmt.Errorf("unexpected friends summary response")
	}
	return len(s.Friends), s.LimitsReached.Accepted, nil
}

// RefreshFriendsState reads the account's friend count from Epic and stores it
// with the "full" flag. Skipped when the stored state is younger than minAge.
// Returns whether the account is full according to the stored/refreshed state.
func RefreshFriendsState(db *sql.DB, accountID uuid.UUID, minAge time.Duration) (full bool, err error) {
	states, _ := database.GetFriendsStates(db, []uuid.UUID{accountID})
	st := states[accountID]
	if st.SyncedAt != nil && time.Since(*st.SyncedAt) < minAge {
		return st.Full, nil
	}
	count, acceptedLimit, err := fetchFriendsCount(db, accountID)
	if err != nil {
		return st.Full, err
	}
	full = count >= maxFriends() || acceptedLimit
	if err := database.SetFriendsState(db, accountID, count, full); err != nil {
		return st.Full, err
	}
	return full, nil
}

// friendsAttempts remembers when the friend count was last tried, so an account
// whose summary cannot be read is not retried on every accepting round.
var friendsAttempts sync.Map // map[uuid.UUID]time.Time

// friendsCheckDue reports whether the account's friend list should be checked
// again (never checked, or last check older than friendsRecheckEvery).
func friendsCheckDue(id uuid.UUID, st database.FriendsState) bool {
	last := time.Time{}
	if st.SyncedAt != nil {
		last = *st.SyncedAt
	}
	if v, ok := friendsAttempts.Load(id); ok {
		if t := v.(time.Time); t.After(last) {
			last = t
		}
	}
	return time.Since(last) >= friendsRecheckEvery
}
