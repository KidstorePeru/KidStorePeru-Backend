package fortnite

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const accountUUID = "11111111-2222-3333-4444-555555555555"

// accountRouter exposes every endpoint that acts on one game account.
func accountRouter(db *sql.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	utils.SetSigningKey("integration-test-key")
	r := gin.New()
	g := r.Group("/", utils.AuthMiddleware())
	g.POST("/sendGift", HandlerSendGift(db))
	g.POST("/refreshpavos", HandlerRefreshPavosForAccount(db))
	g.POST("/updatepavos", HandlerUpdatePavosForAccount(db))
	g.POST("/giftslotstatus", HandlerGetGiftSlotStatus(db))
	g.POST("/updateremaininggifts", HandlerUpdateRemainingGifts(db))
	g.POST("/searchfortnitefriend", HandlerSearchOnlineFortniteAccount(db))
	g.POST("/disconnectfortniteaccount", HandlerDisconnectFAccount(db))
	return r
}

func tokenFor(t *testing.T, id uuid.UUID, name string, admin bool) string {
	t.Helper()
	hexID, _ := utils.ConvertUUIDToString(id)
	var tok string
	var err error
	if admin {
		tok, err = utils.CreateAdminToken(name, hexID)
	} else {
		tok, err = utils.CreateToken(name, hexID)
	}
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// Every endpoint that touches an account must refuse anyone who is neither its
// owner nor an admin. This is the safety net behind the shared authorization
// helper.
func TestAccountEndpointsAreOwnerOrAdminOnly(t *testing.T) {
	db := requireDB(t)
	newFakeEpic(t)
	postGiftSyncDelays = nil
	seedAccount(t, db, accountOpts{pavos: 1000, withSecrets: true})
	r := accountRouter(db)

	intruder := tokenFor(t, uuid.New(), "intruder", false)
	owner := tokenFor(t, testUserID, "tester", false)
	admin := tokenFor(t, uuid.New(), "boss", true)

	endpoints := map[string]string{
		"/sendGift":                  giftBody,
		"/refreshpavos":              `{"account_id":"` + accountUUID + `"}`,
		"/updatepavos":               `{"account_id":"` + accountUUID + `","type":"add","amount":10}`,
		"/giftslotstatus":            `{"account_id":"` + accountUUID + `"}`,
		"/updateremaininggifts":      `{"account_id":"` + accountUUID + `","type":"subtract","amount":1}`,
		"/searchfortnitefriend":      `{"display_name":"Friend","account_id":"` + accountUUID + `"}`,
		"/disconnectfortniteaccount": `{"id":"` + accountUUID + `"}`,
	}

	pavosBefore := storedPavos(t, db)
	for path, body := range endpoints {
		if w := postJSON(r, "", path, body); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token: %d, want 401", path, w.Code)
		}
		if w := postJSON(r, intruder, path, body); w.Code != http.StatusForbidden {
			t.Errorf("%s as a stranger: %d, want 403 (%s)", path, w.Code, w.Body.String())
		}
	}
	// nothing the stranger tried changed anything
	if storedPavos(t, db) != pavosBefore || txCount(t, db) != 0 {
		t.Errorf("a refused request changed state: pavos %d, transactions %d", storedPavos(t, db), txCount(t, db))
	}
	if _, err := database.GetGameAccount(db, testAccountID); err != nil {
		t.Fatalf("a stranger managed to delete the account: %v", err)
	}

	for path, body := range endpoints {
		if path == "/disconnectfortniteaccount" {
			continue // destructive, checked below
		}
		for name, tok := range map[string]string{"owner": owner, "admin": admin} {
			if w := postJSON(r, tok, path, body); w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
				t.Errorf("%s as %s was refused: %d %s", path, name, w.Code, w.Body.String())
			}
		}
	}

	if w := postJSON(r, admin, "/disconnectfortniteaccount", endpoints["/disconnectfortniteaccount"]); w.Code != http.StatusOK {
		t.Fatalf("an admin can disconnect any account, got %d %s", w.Code, w.Body.String())
	}
	if _, err := database.GetGameAccount(db, testAccountID); err == nil {
		t.Error("the account is still there after being disconnected")
	}
	if _, err := database.GetGameAccountSecrets(db, "11111111222233334444555555555555"); err == nil {
		t.Error("its device-auth secrets were left behind")
	}
}

func TestRefreshPavosCoalescesBurstsOfRequests(t *testing.T) {
	db := requireDB(t)
	f := newFakeEpic(t)
	seedAccount(t, db, accountOpts{pavos: 1})
	var profileCalls int32
	f.profileHook = func(string) (int, string) {
		atomic.AddInt32(&profileCalls, 1)
		return 200, profileJSON(1500, nil)
	}
	r := accountRouter(db)
	tok := tokenFor(t, testUserID, "tester", false)
	body := `{"account_id":"` + accountUUID + `"}`

	for i := 0; i < 3; i++ {
		w := postJSON(r, tok, "/refreshpavos", body)
		var out struct {
			Success bool
			Data    struct{ Pavos int }
		}
		json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != 200 || !out.Success || out.Data.Pavos != 1500 {
			t.Fatalf("refresh %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	if n := atomic.LoadInt32(&profileCalls); n != 1 {
		t.Errorf("three quick refreshes asked Epic %d times, want 1", n)
	}

	// once the last read is old enough Epic is asked again
	db.Exec(`UPDATE game_accounts SET pavos_synced_at = now() - interval '1 minute'`)
	postJSON(r, tok, "/refreshpavos", body)
	if n := atomic.LoadInt32(&profileCalls); n != 2 {
		t.Errorf("after a minute Epic was asked %d times in total, want 2", n)
	}
}

func TestGiftWithoutPictureIsAcceptedAndBadBodiesGetAClearError(t *testing.T) {
	db := requireDB(t)
	newFakeEpic(t)
	postGiftSyncDelays = nil
	seedAccount(t, db, accountOpts{pavos: 2000})
	r := accountRouter(db)
	tok := tokenFor(t, testUserID, "tester", false)

	noImage := strings.Replace(giftBody, `"gift_image":"https://img"`, `"gift_image":""`, 1)
	if w := postJSON(r, tok, "/sendGift", noImage); w.Code != 200 {
		t.Errorf("a shop item without a picture must still be giftable: %d %s", w.Code, w.Body.String())
	}

	noReceiver := strings.Replace(giftBody, `"receiver_id":"receiverid"`, `"receiver_id":""`, 1)
	w := postJSON(r, tok, "/sendGift", noReceiver)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Faltan datos del regalo") {
		t.Errorf("incomplete gift: %d %s", w.Code, w.Body.String())
	}
	free := strings.Replace(giftBody, `"gift_price":800`, `"gift_price":-5`, 1)
	if w := postJSON(r, tok, "/sendGift", free); w.Code != http.StatusBadRequest {
		t.Errorf("a negative price must be refused, got %d", w.Code)
	}
}

// Databases created before UpsertGameAccountSecrets may have no unique key on
// secrets.account_id (and may hold duplicates): EnsureSchema must repair that,
// otherwise the permanent device-auth credentials could never be saved.
func TestEnsureSchemaMakesSecretsUniqueAndRepairsDuplicates(t *testing.T) {
	db := requireDB(t)
	resetDB(t, db)
	t.Cleanup(func() {
		db.Exec(`DROP TABLE secrets`)
		db.Exec(`CREATE TABLE secrets (account_id TEXT PRIMARY KEY, owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, device_id TEXT NOT NULL, secret TEXT NOT NULL)`)
	})

	mustExec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(`DROP TABLE secrets`)
	mustExec(`CREATE TABLE secrets (account_id TEXT, owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, device_id TEXT NOT NULL, secret TEXT NOT NULL)`)
	mustExec(`INSERT INTO secrets VALUES ('acc1', $1, 'dev-old', 'sec-old')`, testUserID)
	mustExec(`INSERT INTO secrets VALUES ('acc1', $1, 'dev-new', 'sec-new')`, testUserID)
	mustExec(`INSERT INTO secrets VALUES ('acc2', $1, 'dev-2', 'sec-2')`, testUserID)

	// without the key the upsert cannot even be prepared
	err := database.UpsertGameAccountSecrets(db, types.GameAccountSecrets{Owner_user_id: testUserID, DeviceId: "d", AccountId: "acc3", Secret: "s"})
	if err == nil {
		t.Fatal("precondition failed: the upsert worked on a table without a unique key")
	}

	if err := database.EnsureSchema(db); err != nil {
		t.Fatal(err)
	}

	var n int
	db.QueryRow(`SELECT COUNT(*) FROM secrets`).Scan(&n)
	if n != 2 {
		t.Errorf("%d secret rows left, want 2 (the duplicate of acc1 removed)", n)
	}
	var dev string
	db.QueryRow(`SELECT device_id FROM secrets WHERE account_id='acc1'`).Scan(&dev)
	if dev != "dev-new" {
		t.Errorf("kept %q for acc1, want the newest row dev-new", dev)
	}

	// the upsert now inserts and replaces
	for _, s := range []string{"first", "second"} {
		if err := database.UpsertGameAccountSecrets(db, types.GameAccountSecrets{Owner_user_id: testUserID, DeviceId: "d-" + s, AccountId: "acc3", Secret: s}); err != nil {
			t.Fatalf("upsert after the repair: %v", err)
		}
	}
	db.QueryRow(`SELECT COUNT(*) FROM secrets WHERE account_id='acc3'`).Scan(&n)
	if n != 1 {
		t.Errorf("acc3 has %d rows after two upserts, want 1", n)
	}

	// and running it again is harmless
	if err := database.EnsureSchema(db); err != nil {
		t.Fatalf("EnsureSchema is not idempotent: %v", err)
	}
}

func TestDeviceAuthIsReportedPerAccount(t *testing.T) {
	db := requireDB(t)
	seedAccount(t, db, accountOpts{withSecrets: true})
	other := uuid.New()
	if err := database.UpsertGameAccount(db, types.GameAccount{
		ID: other, DisplayName: "NoSecrets", AccessToken: "t", RefreshToken: "r",
		AccessTokenExpDate: time.Now().Add(time.Hour), RefreshTokenExpDate: time.Now().Add(time.Hour),
		OwnerUserID: testUserID,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := database.GetDeviceAuthAccounts(db, []uuid.UUID{testAccountID, other})
	if err != nil {
		t.Fatal(err)
	}
	if !got[testAccountID] || got[other] {
		t.Errorf("device auth flags = %v, want only the first account", got)
	}
}
