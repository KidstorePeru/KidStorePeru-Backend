package fortnite

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/utils"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestFriendsFullErrorDetection(t *testing.T) {
	full := &epicError{Status: 403, Code: "errors.com.epicgames.friends.invitee_friendships_limit_exceeded"}
	throttled := &epicError{Status: 429, Code: "errors.com.epicgames.common.throttled"}
	if !isFriendsFullError(full) || isFriendsFullError(throttled) {
		t.Error("only the invitee limit error means the friend list is full")
	}
	if !isThrottledError(throttled) || isThrottledError(full) {
		t.Error("only 429 is throttling")
	}
	if isFriendsFullError(fmt.Errorf("network down")) {
		t.Error("a plain error is not a full friend list")
	}
}

func summaryWithFriends(n int) string {
	items := make([]string, n)
	for i := range items {
		items[i] = fmt.Sprintf(`{"accountId":"f%d"}`, i)
	}
	return `{"friends":[` + strings.Join(items, ",") + `],"incoming":[],"outgoing":[],"limitsReached":{"accepted":false}}`
}

func setMaxFriends(t *testing.T, n int) {
	old := utils.Config.MaxFriends
	utils.Config.MaxFriends = n
	t.Cleanup(func() { utils.Config.MaxFriends = old })
}

func friendsState(t *testing.T, id uuid.UUID) database.FriendsState {
	t.Helper()
	m, err := database.GetFriendsStates(requireDB(t), []uuid.UUID{id})
	if err != nil {
		t.Fatal(err)
	}
	return m[id]
}

func runFriendRound(t *testing.T) {
	t.Helper()
	db := requireDB(t)
	acc, err := database.GetGameAccount(db, testAccountID)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := database.GetFriendsStates(db, []uuid.UUID{testAccountID})
	processFriendRequests(db, acc, m[testAccountID])
}

func expireFriendsCheck(t *testing.T) {
	t.Helper()
	friendsAttempts.Delete(testAccountID)
	if _, err := requireDB(t).Exec(`UPDATE game_accounts SET friends_synced_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
}

func TestFullFriendListIsSkippedAndResumesWhenFriendsAreRemoved(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	setMaxFriends(t, 3)
	seedAccount(t, db, accountOpts{withSecrets: true})
	friendsAttempts.Delete(testAccountID)
	f.summaryHook = func() (int, string) { return 200, summaryWithFriends(3) }
	f.incoming = `[{"accountId":"cust1"}]`

	runFriendRound(t)
	st := friendsState(t, testAccountID)
	if !st.Full || st.Count == nil || *st.Count != 3 {
		t.Fatalf("state = %+v, want full with 3 friends", st)
	}
	if f.incomingCalls != 0 || len(f.accepted) != 0 {
		t.Errorf("a full account must not be polled or accept anyone (incoming calls %d, accepted %v)", f.incomingCalls, f.accepted)
	}

	// Another round right away must not even ask Epic for the friend list.
	calls := f.summaryCalls
	runFriendRound(t)
	if f.summaryCalls != calls || f.incomingCalls != 0 {
		t.Error("a full account checked a moment ago must be left alone")
	}

	// The operator removes friends by hand: at the next re-check it resumes.
	f.summaryHook = func() (int, string) { return 200, summaryWithFriends(2) }
	expireFriendsCheck(t)
	runFriendRound(t)
	if len(f.accepted) != 1 || f.accepted[0] != "cust1" {
		t.Errorf("accepted = %v, want [cust1] once there is room again", f.accepted)
	}
	if st := friendsState(t, testAccountID); st.Full {
		t.Errorf("state still full after room appeared: %+v", st)
	}
}

func TestLimitErrorFromEpicPausesAcceptingEvenWithoutACount(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{withSecrets: true})
	friendsAttempts.Delete(testAccountID)
	f.summaryHook = func() (int, string) { return 500, `{}` } // count unavailable
	f.incoming = `[{"accountId":"a"},{"accountId":"b"},{"accountId":"c"}]`
	f.acceptHook = func(target string) (int, string) {
		return 403, `{"errorCode":"errors.com.epicgames.friends.invitee_friendships_limit_exceeded","errorMessage":"Limit of accepted requests has been exceeded"}`
	}

	runFriendRound(t)
	if !friendsState(t, testAccountID).Full {
		t.Fatal("the account must be flagged as full after Epic's limit error")
	}

	// Later rounds skip it completely instead of retrying every request.
	in := f.incomingCalls
	runFriendRound(t)
	runFriendRound(t)
	if f.incomingCalls != in {
		t.Errorf("a full account was polled again (%d -> %d incoming calls)", in, f.incomingCalls)
	}
}

func TestThrottlingStopsTheBatchWithoutMarkingTheAccountFull(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{withSecrets: true})
	friendsAttempts.Delete(testAccountID)
	f.incoming = `[{"accountId":"a"},{"accountId":"b"}]`
	tries := 0
	f.acceptHook = func(target string) (int, string) {
		tries++
		return 429, `{"errorCode":"errors.com.epicgames.common.throttled","errorMessage":"try again in 29 second(s)"}`
	}

	runFriendRound(t)
	if tries != 1 {
		t.Errorf("throttled batch made %d accept calls, want 1 (stop at the first 429)", tries)
	}
	if friendsState(t, testAccountID).Full {
		t.Error("throttling must not mark the account as full")
	}
}
