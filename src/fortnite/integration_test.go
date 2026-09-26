package fortnite

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------- fake Epic

type fakeEpic struct {
	t   *testing.T
	srv *httptest.Server

	mu         sync.Mutex
	grants     map[string]int
	seq        int
	giftBodies [][]byte

	// hooks (nil = default success behaviour)
	tokenHook   func(grant string) (int, string)
	profileHook func(bearer string) (int, string)
	giftHook    func(bearer string, body []byte) (int, string)
}

func newFakeEpic(t *testing.T) *fakeEpic {
	f := &fakeEpic{t: t, grants: map[string]int{}}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /account/api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		grant := r.Form.Get("grant_type")
		f.mu.Lock()
		f.grants[grant]++
		f.seq++
		n := f.seq
		f.mu.Unlock()
		if f.tokenHook != nil {
			if status, body := f.tokenHook(grant); status != 0 {
				w.WriteHeader(status)
				io.WriteString(w, body)
				return
			}
		}
		fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":7200,"expires_at":"2099-01-01T00:00:00.000Z","refresh_token":"ref-%d","refresh_expires":28800,"account_id":"11111111222233334444555555555555","displayName":"Tester"}`, n, n)
	})

	mux.HandleFunc("POST /account/api/public/account/{id}/deviceAuth", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"deviceId":"dev-1","accountId":"11111111222233334444555555555555","secret":"sec-1"}`)
	})

	mux.HandleFunc("POST /fortnite/api/game/v2/profile/{id}/client/QueryProfile", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if f.profileHook != nil {
			status, body := f.profileHook(bearer)
			w.WriteHeader(status)
			io.WriteString(w, body)
			return
		}
		io.WriteString(w, profileJSON(2000, nil))
	})

	mux.HandleFunc("POST /fortnite/api/game/v2/profile/{id}/client/GiftCatalogEntry", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.giftBodies = append(f.giftBodies, body)
		f.mu.Unlock()
		if f.giftHook != nil {
			status, resp := f.giftHook(bearer, body)
			w.WriteHeader(status)
			io.WriteString(w, resp)
			return
		}
		io.WriteString(w, `{"profileChanges":[]}`)
	})

	f.srv = httptest.NewServer(mux)
	oldA, oldM, oldF := epicAccountBase, epicMCPBase, epicFriendsBase
	epicAccountBase, epicMCPBase, epicFriendsBase = f.srv.URL, f.srv.URL, f.srv.URL
	t.Cleanup(func() {
		f.srv.Close()
		epicAccountBase, epicMCPBase, epicFriendsBase = oldA, oldM, oldF
	})
	return f
}

func (f *fakeEpic) grantCount(grant string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.grants[grant]
}

// profileJSON builds a QueryProfile response with the given spendable pavos and
// gifts sent at the given times.
func profileJSON(pavos int, giftTimes []time.Time) string {
	var gifts []string
	for _, g := range giftTimes {
		gifts = append(gifts, fmt.Sprintf(`{"date":%q,"offerId":"v2:/x","toAccountId":"receiver"}`, g.UTC().Format(time.RFC3339Nano)))
	}
	return fmt.Sprintf(`{"profileChanges":[{"changeType":"fullProfileUpdate","profile":{"items":{
		"c1":{"templateId":"Currency:MtxPurchased","quantity":%d,"attributes":{"platform":"EpicPC"}}
	},"stats":{"attributes":{"gift_history":{"num_sent":%d,"gifts":[%s]}}}}}]}`, pavos, len(giftTimes), strings.Join(gifts, ","))
}

// ---------------------------------------------------------------- fixtures

var (
	testAccountID = uuid.MustParse("11111111-2222-3333-4444-555555555555")
	testUserID    = uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
)

// resetDB empties every table and (re)creates the test user.
func resetDB(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`TRUNCATE transactions, secrets, game_accounts, users CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, username, password) VALUES ($1, 'tester', 'x')`, testUserID); err != nil {
		t.Fatal(err)
	}
}

type accountOpts struct {
	token       string
	tokenExpiry time.Time
	withSecrets bool
	pavos       int
}

func seedAccount(t *testing.T, db *sql.DB, o accountOpts) {
	t.Helper()
	resetDB(t, db)
	if o.token == "" {
		o.token = "old-token"
	}
	if o.tokenExpiry.IsZero() {
		o.tokenExpiry = time.Now().Add(time.Hour)
	}
	if err := database.UpsertGameAccount(db, types.GameAccount{
		ID: testAccountID, DisplayName: "Tester", RemainingGifts: 5, PaVos: o.pavos,
		AccessToken: o.token, AccessTokenExp: 7200, AccessTokenExpDate: o.tokenExpiry,
		RefreshToken: "old-refresh", RefreshTokenExp: 28800, RefreshTokenExpDate: time.Now().Add(8 * time.Hour),
		OwnerUserID: testUserID,
	}); err != nil {
		t.Fatal(err)
	}
	if o.withSecrets {
		if err := database.UpsertGameAccountSecrets(db, types.GameAccountSecrets{
			Owner_user_id: testUserID, DeviceId: "dev-1", AccountId: "11111111222233334444555555555555", Secret: "sec-1",
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func txCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM transactions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func storedPavos(t *testing.T, db *sql.DB) int {
	t.Helper()
	p, err := database.GetPavos(db, testAccountID)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------------------------------------------------------------- schema

func TestEnsureSchemaAddsColumnAndRemovesPhantomRows(t *testing.T) {
	db := requireDB(t)
	seedAccount(t, db, accountOpts{})

	// 5 phantom rows from the old purchase_not_allowed bug (recent), one old
	// legacy row, and one real gift.
	for i := 0; i < 5; i++ {
		db.Exec(`INSERT INTO transactions (game_account_id, object_store_id, object_store_name, regular_price, final_price, gift_image) VALUES ($1,'o','External Gift',100,100,'')`, testAccountID)
	}
	db.Exec(`INSERT INTO transactions (game_account_id, object_store_id, object_store_name, regular_price, final_price, gift_image, created_at) VALUES ($1,'o','External Gift',100,100,'', now() - interval '3 days')`, testAccountID)
	db.Exec(`INSERT INTO transactions (game_account_id, object_store_id, object_store_name, regular_price, final_price, gift_image) VALUES ($1,'o','Real skin',800,800,'https://img')`, testAccountID)

	for i := 0; i < 2; i++ { // idempotent
		if err := database.EnsureSchema(db); err != nil {
			t.Fatalf("EnsureSchema run %d: %v", i, err)
		}
	}
	if n := txCount(t, db); n != 2 {
		t.Errorf("transactions left = %d, want 2 (real gift + old legacy row)", n)
	}
	remaining, err := database.CalculateRemainingGifts(db, testAccountID)
	if err != nil || remaining != 4 {
		t.Errorf("remaining gifts = %d (err %v), want 4: phantom rows must not use slots", remaining, err)
	}
	if err := database.SetPaVosSynced(db, testAccountID, 10); err != nil {
		t.Errorf("pavos_synced_at column missing: %v", err)
	}
}

func TestPavosArithmeticIsAtomicAndClamped(t *testing.T) {
	db := requireDB(t)
	seedAccount(t, db, accountOpts{pavos: 1000})
	if got, _ := database.SubtractPaVos(db, testAccountID, 300); got != 700 {
		t.Errorf("subtract = %d", got)
	}
	if got, _ := database.SubtractPaVos(db, testAccountID, 5000); got != 0 {
		t.Errorf("subtract below zero must clamp to 0, got %d", got)
	}
	if got, _ := database.AddPaVos(db, testAccountID, 2800); got != 2800 {
		t.Errorf("add = %d", got)
	}
	if got, _ := database.AddPaVos(db, testAccountID, -99999); got != 0 {
		t.Errorf("negative add must clamp to 0, got %d", got)
	}
}

// ---------------------------------------------------------------- sync

func TestSyncStoresRealPavosAndTimestamp(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{pavos: 12345, withSecrets: true})
	f.profileHook = func(string) (int, string) { return 200, profileJSON(2000, nil) }

	res, err := SyncAccountFromEpic(db, testAccountID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Pavos != 2000 || storedPavos(t, db) != 2000 {
		t.Errorf("pavos result=%d stored=%d, want 2000", res.Pavos, storedPavos(t, db))
	}
	m, _ := database.GetPavosSyncedAt(db, []uuid.UUID{testAccountID})
	if _, ok := m[testAccountID]; !ok {
		t.Error("pavos_synced_at was not set")
	}
}

func TestSyncZeroPavosIsStoredNotSkipped(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{pavos: 500})
	f.profileHook = func(string) (int, string) { return 200, profileJSON(0, nil) }
	if _, err := SyncAccountFromEpic(db, testAccountID); err != nil {
		t.Fatal(err)
	}
	if storedPavos(t, db) != 0 {
		t.Errorf("an account that really has 0 pavos must show 0, got %d", storedPavos(t, db))
	}
}

func TestSyncFailureNeverOverwritesPavos(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{pavos: 777})
	for name, hook := range map[string]func(string) (int, string){
		"server error": func(string) (int, string) { return 500, `oops` },
		"epic error":   func(string) (int, string) { return 400, `{"errorCode":"errors.com.epicgames.x","errorMessage":"nope"}` },
		"garbage 200":  func(string) (int, string) { return 200, `<html>maintenance</html>` },
	} {
		f.profileHook = hook
		if _, err := SyncAccountFromEpic(db, testAccountID); err == nil {
			t.Errorf("%s: expected an error", name)
		}
		if got := storedPavos(t, db); got != 777 {
			t.Errorf("%s: pavos changed to %d", name, got)
		}
	}
}

func TestSyncRecordsGiftsSentFromTheGameOnce(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{})
	gifts := []time.Time{time.Now().Add(-5 * time.Hour), time.Now().Add(-2 * time.Hour), time.Now().Add(-40 * time.Hour)}
	f.profileHook = func(string) (int, string) { return 200, profileJSON(100, gifts) }

	for i := 0; i < 3; i++ { // running it repeatedly must not duplicate anything
		if _, err := SyncAccountFromEpic(db, testAccountID); err != nil {
			t.Fatal(err)
		}
	}
	if n := txCount(t, db); n != 2 {
		t.Errorf("recorded %d gifts, want 2 (the 40h-old one is outside the cooldown)", n)
	}
	remaining, _ := database.CalculateRemainingGifts(db, testAccountID)
	if remaining != 3 {
		t.Errorf("remaining = %d, want 3", remaining)
	}
	var stored int
	db.QueryRow(`SELECT remaining_gifts FROM game_accounts WHERE id=$1`, testAccountID).Scan(&stored)
	if stored != 3 {
		t.Errorf("stored counter = %d, want 3", stored)
	}
}

func TestSyncAdoptsManualAdjustment(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{})
	// the operator sent a gift in the game and subtracted a slot by hand
	db.Exec(`INSERT INTO transactions (game_account_id, object_store_id, object_store_name, regular_price, final_price, gift_image) VALUES ($1,'manual-adjustment','Ajuste manual',0,0,'')`, testAccountID)
	real := time.Now().Add(-6 * time.Hour)
	f.profileHook = func(string) (int, string) { return 200, profileJSON(100, []time.Time{real}) }

	if _, err := SyncAccountFromEpic(db, testAccountID); err != nil {
		t.Fatal(err)
	}
	if n := txCount(t, db); n != 1 {
		t.Fatalf("transactions = %d, want 1 (the manual row is adopted, not doubled)", n)
	}
	var at time.Time
	db.QueryRow(`SELECT created_at FROM transactions`).Scan(&at)
	if d := at.Sub(real); d > time.Second || d < -time.Second {
		t.Errorf("slot time %v should be the real gift time %v", at, real)
	}
}

func TestFreeGiftSlotsPrefersNonWebRows(t *testing.T) {
	db := requireDB(t)
	seedAccount(t, db, accountOpts{})
	db.Exec(`INSERT INTO transactions (game_account_id, object_store_id, object_store_name, regular_price, final_price, gift_image, created_at) VALUES ($1,'real','Real gift',800,800,'img', now() - interval '5 hours')`, testAccountID)
	db.Exec(`INSERT INTO transactions (game_account_id, object_store_id, object_store_name, regular_price, final_price, gift_image, created_at) VALUES ($1,'manual-adjustment','Ajuste manual',0,0,'', now() - interval '1 hour')`, testAccountID)

	database.FreeGiftSlots(db, testAccountID, 1)

	var id string
	if err := db.QueryRow(`SELECT object_store_id FROM transactions`).Scan(&id); err != nil || id != "real" {
		t.Errorf("the real gift must survive, remaining row = %q (err %v)", id, err)
	}
}

// ---------------------------------------------------------------- tokens

func operation(db *sql.DB) (*http.Response, error) {
	req, _ := http.NewRequest("POST", epicMCPBase+"/fortnite/api/game/v2/profile/11111111222233334444555555555555/client/QueryProfile?profileId=common_core&rvn=-1", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	return ExecuteOperationWithRefresh(req, db, testAccountID, "test")
}

func TestExpiredTokenIsRefreshedBeforeTheCall(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{token: "old-token", tokenExpiry: time.Now().Add(-time.Hour), withSecrets: true})
	var seen []string
	f.profileHook = func(b string) (int, string) { seen = append(seen, b); return 200, profileJSON(1, nil) }

	resp, err := operation(db)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("err=%v resp=%v", err, resp)
	}
	if len(seen) != 1 || seen[0] == "old-token" {
		t.Errorf("the request must go out with the refreshed token, bearers seen: %v", seen)
	}
	if f.grantCount("device_auth") != 1 || f.grantCount("refresh_token") != 0 {
		t.Errorf("grants: %v (device auth is preferred when available)", f.grants)
	}
	acc, _ := database.GetGameAccount(db, testAccountID)
	if acc.AccessToken != seen[0] {
		t.Error("the new token must be stored")
	}
}

func TestRejectedTokenIsRefreshedOnceAndBodyIsResent(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	// token looks valid locally but Epic says it is not (revoked early)
	seedAccount(t, db, accountOpts{token: "revoked", tokenExpiry: time.Now().Add(time.Hour), withSecrets: true})
	f.giftHook = func(bearer string, body []byte) (int, string) {
		if bearer == "revoked" {
			return 401, `{"errorCode":"errors.com.epicgames.common.authentication.token_verification_failed"}`
		}
		if !bytes.Contains(body, []byte(`"offerId":"v2:/skin"`)) {
			return 400, `{"errorCode":"errors.com.epicgames.validation.validation_failed","errorMessage":"empty body"}`
		}
		return 200, `{"profileChanges":[]}`
	}

	err := sendGiftRequest(db, "11111111222233334444555555555555", testAccountID, "receiverid", "v2:/skin", 1200, nil, "hola")
	if err != nil {
		t.Fatalf("the gift must go through after the token refresh, got: %v", err)
	}
	if len(f.giftBodies) != 2 || !bytes.Equal(f.giftBodies[0], f.giftBodies[1]) {
		t.Errorf("the retry must resend the full body, bodies=%q", f.giftBodies)
	}
}

func TestConcurrentCallsRefreshTheTokenOnlyOnce(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{token: "old-token", tokenExpiry: time.Now().Add(-time.Hour)}) // no device auth: refresh-token grant
	f.profileHook = func(b string) (int, string) {
		if b == "old-token" {
			return 401, `{}`
		}
		return 200, profileJSON(1, nil)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := operation(db)
			if err == nil && resp.StatusCode != 200 {
				err = fmt.Errorf("status %d", resp.StatusCode)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("a concurrent call failed: %v", err)
		}
	}
	if n := f.grantCount("refresh_token"); n != 1 {
		t.Errorf("refresh-token grant called %d times, want exactly 1 (Epic refresh tokens are single use)", n)
	}
}

func TestTransientEpicFailureNeverDeletesTheAccount(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{tokenExpiry: time.Now().Add(-time.Hour), withSecrets: true})
	// the stored token really is dead, so the call can only work after a refresh
	f.profileHook = func(b string) (int, string) {
		if b == "old-token" {
			return 401, `{}`
		}
		return 200, profileJSON(1, nil)
	}

	for name, hook := range map[string]func(string) (int, string){
		"epic down":  func(string) (int, string) { return 503, `service unavailable` },
		"rate limit": func(string) (int, string) { return 429, `{"errorCode":"errors.com.epicgames.common.throttled"}` },
		"html error": func(string) (int, string) { return 502, `<html>bad gateway</html>` },
	} {
		f.tokenHook = func(string) (int, string) { return hook("") }
		_, err := operation(db)
		if err == nil {
			t.Errorf("%s: expected an error", name)
		}
		if errors.Is(err, ErrNeedsRelink) {
			t.Errorf("%s: a temporary problem must not ask to re-link the account", name)
		}
		if _, gerr := database.GetGameAccount(db, testAccountID); gerr != nil {
			t.Fatalf("%s: the account was deleted (%v)", name, gerr)
		}
	}
}

func TestRevokedCredentialsAskToRelinkButKeepTheAccount(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{tokenExpiry: time.Now().Add(-time.Hour), withSecrets: true})
	f.tokenHook = func(string) (int, string) {
		return 400, `{"errorCode":"errors.com.epicgames.account.invalid_account_credentials","errorMessage":"nope"}`
	}
	_, err := operation(db)
	if !errors.Is(err, ErrNeedsRelink) {
		t.Fatalf("want ErrNeedsRelink, got %v", err)
	}
	if _, gerr := database.GetGameAccount(db, testAccountID); gerr != nil {
		t.Errorf("the account must NOT be deleted automatically: %v", gerr)
	}
}

// ---------------------------------------------------------------- gifts

func TestRejectedGiftNeverFabricatesGiftSlots(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{})
	f.giftHook = func(string, []byte) (int, string) {
		return 400, `{"errorCode":"errors.com.epicgames.modules.gamesubcatalog.purchase_not_allowed","errorMessage":"Purchase not allowed"}`
	}

	err := sendGiftRequest(db, "11111111222233334444555555555555", testAccountID, "receiver", "v2:/x", 800, nil, "")
	var rejected *giftRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("want a giftRejectedError, got %v", err)
	}
	if n := txCount(t, db); n != 0 {
		t.Errorf("%d transactions were created for a REJECTED gift (this was the phantom '5 gifts used' bug)", n)
	}
	remaining, _ := database.CalculateRemainingGifts(db, testAccountID)
	if remaining != 5 {
		t.Errorf("remaining = %d, want 5", remaining)
	}
}

func giftRouter(db *sql.DB) (*gin.Engine, string) {
	gin.SetMode(gin.TestMode)
	utils.SetSigningKey("integration-test-key")
	r := gin.New()
	g := r.Group("/", utils.AuthMiddleware())
	g.POST("/sendGift", HandlerSendGift(db))
	g.POST("/refreshpavos", HandlerRefreshPavosForAccount(db))
	hexUser, _ := utils.ConvertUUIDToString(testUserID)
	tok, _ := utils.CreateToken("tester", hexUser)
	return r, tok
}

func postJSON(r *gin.Engine, token, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

const giftBody = `{"account_id":"11111111-2222-3333-4444-555555555555","sender_username":"Tester","receiver_id":"receiverid","receiver_username":"Friend","gift_id":"v2:/skin","gift_price":800,"gift_name":"Skin","message":"hola","gift_image":"https://img"}`

func TestSendGiftEndToEnd(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	postGiftSyncDelays = nil
	seedAccount(t, db, accountOpts{pavos: 2000})
	r, tok := giftRouter(db)

	// success: recorded, pavos lowered immediately, slot used
	w := postJSON(r, tok, "/sendGift", giftBody)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if n := txCount(t, db); n != 1 || storedPavos(t, db) != 1200 {
		t.Errorf("tx=%d pavos=%d, want 1 and 1200", n, storedPavos(t, db))
	}

	// Epic rejects: 502 with a reason, nothing spent
	f.giftHook = func(string, []byte) (int, string) {
		return 400, `{"errorCode":"errors.com.epicgames.modules.gamesubcatalog.purchase_not_allowed","errorMessage":"Purchase not allowed"}`
	}
	w = postJSON(r, tok, "/sendGift", giftBody)
	var out map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != http.StatusBadGateway || out["success"] != false || !strings.Contains(fmt.Sprint(out["details"]), "purchase_not_allowed") {
		t.Errorf("rejected gift response: %d %s", w.Code, w.Body.String())
	}
	if n := txCount(t, db); n != 1 || storedPavos(t, db) != 1200 {
		t.Errorf("a rejected gift changed state: tx=%d pavos=%d", n, storedPavos(t, db))
	}

	// somebody else's account is off limits
	other := uuid.New()
	hexOther, _ := utils.ConvertUUIDToString(other)
	otherTok, _ := utils.CreateToken("intruder", hexOther)
	w = postJSON(r, otherTok, "/sendGift", giftBody)
	if w.Code != http.StatusForbidden {
		t.Errorf("a non-owner must get 403, got %d", w.Code)
	}
}

func TestRefreshPavosEndpointReadsEpic(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{pavos: 1})
	f.profileHook = func(string) (int, string) { return 200, profileJSON(4321, nil) }
	r, tok := giftRouter(db)

	w := postJSON(r, tok, "/refreshpavos", `{"account_id":"11111111-2222-3333-4444-555555555555"}`)
	if w.Code != 200 || storedPavos(t, db) != 4321 {
		t.Errorf("status %d pavos %d body %s", w.Code, storedPavos(t, db), w.Body.String())
	}

	f.profileHook = func(string) (int, string) { return 500, `boom` }
	w = postJSON(r, tok, "/refreshpavos", `{"account_id":"11111111-2222-3333-4444-555555555555"}`)
	if w.Code != http.StatusBadGateway || storedPavos(t, db) != 4321 {
		t.Errorf("failed refresh: status %d pavos %d", w.Code, storedPavos(t, db))
	}
}

// ---------------------------------------------------------------- linking

func linkRouter(db *sql.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	utils.SetSigningKey("integration-test-key")
	r := gin.New()
	g := r.Group("/", utils.AuthMiddleware())
	g.POST("/finishconnectfaccount", HandlerFinishConnectFortniteAccount(db))
	return r
}

func TestLinkingAnAccountShowsRealPavosAndCanBeRepeated(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	resetDB(t, db)
	f.profileHook = func(string) (int, string) {
		return 200, profileJSON(3400, []time.Time{time.Now().Add(-1 * time.Hour)})
	}
	r := linkRouter(db)
	hexUser, _ := utils.ConvertUUIDToString(testUserID)
	tok, _ := utils.CreateToken("tester", hexUser)

	w := postJSON(r, tok, "/finishconnectfaccount", `{"device_code":"abc"}`)
	var out map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 || out["pavos"] != float64(3400) || out["pavos_synced"] != true || out["gifts_sent_24h"] != float64(1) {
		t.Fatalf("link response: %d %s", w.Code, w.Body.String())
	}
	if storedPavos(t, db) != 3400 {
		t.Errorf("stored pavos = %d, want the real 3400", storedPavos(t, db))
	}
	if _, err := database.GetGameAccountSecrets(db, "11111111222233334444555555555555"); err != nil {
		t.Errorf("device auth secrets were not stored: %v", err)
	}

	// linking the same account again (e.g. after Epic revoked it) works
	if w := postJSON(r, tok, "/finishconnectfaccount", `{"device_code":"abc"}`); w.Code != 200 {
		t.Errorf("re-linking failed: %d %s", w.Code, w.Body.String())
	}

	// another non-admin user cannot take the account over
	other := uuid.New()
	db.Exec(`INSERT INTO users (id, username, password) VALUES ($1,'other','x')`, other)
	hexOther, _ := utils.ConvertUUIDToString(other)
	otherTok, _ := utils.CreateToken("other", hexOther)
	if w := postJSON(r, otherTok, "/finishconnectfaccount", `{"device_code":"abc"}`); w.Code != http.StatusConflict {
		t.Errorf("taking over someone else's account should be 409, got %d", w.Code)
	}
}

func TestLinkingStillWorksWhenTheProfileIsUnavailable(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	resetDB(t, db)
	f.profileHook = func(string) (int, string) { return 500, `down` }
	r := linkRouter(db)
	hexUser, _ := utils.ConvertUUIDToString(testUserID)
	tok, _ := utils.CreateToken("tester", hexUser)

	w := postJSON(r, tok, "/finishconnectfaccount", `{"device_code":"abc"}`)
	var out map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 || out["pavos_synced"] != false || out["sync_error"] == nil {
		t.Errorf("the account must still be linked (pavos can sync later): %d %s", w.Code, w.Body.String())
	}
}
