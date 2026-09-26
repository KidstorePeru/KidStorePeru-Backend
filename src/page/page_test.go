package page

import (
	"KidStoreBotBE/src/testutil"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var testDB *sql.DB

func TestMain(m *testing.M) {
	if os.Getenv("SKIP_PG_TESTS") == "" {
		db, stop, err := testutil.StartPostgres()
		if err != nil {
			fmt.Println("integration tests disabled:", err)
		} else {
			testDB = db
			defer stop()
		}
	}
	code := m.Run()
	if testDB != nil {
		testDB.Close()
	}
	os.Exit(code)
}

func setup(t *testing.T) (*gin.Engine, *sql.DB) {
	t.Helper()
	if testDB == nil {
		t.Skip("PostgreSQL not available")
	}
	gin.SetMode(gin.TestMode)
	utils.SetSigningKey("page-test-key")
	if _, err := testDB.Exec(`TRUNCATE transactions, secrets, game_accounts, users CASCADE`); err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.POST("/loginform", HandlerLoginForm(testDB, "admin"))
	auth := r.Group("/", utils.AuthMiddleware())
	auth.POST("/addnewuser", HandlerAddNewUser(testDB))
	auth.POST("/updateuser", HandlerUpdateUser(testDB))
	auth.POST("/removeusers", HandlerRemoveUsers(testDB))
	auth.GET("/getalluser", HandlerGetAllUsers(testDB))
	auth.GET("/transactions", HandlerGetTransactionsByAccount(testDB))
	auth.GET("/alltransactions", HandlerGetTransactionsAdmin(testDB))
	auth.GET("/allfortniteaccounts", HandlerGetAllGameAccounts(testDB))

	// reset the limiters between tests
	loginLimiterIPUser = utils.NewAttemptLimiter(8, 10*60*1e9)
	loginLimiterUser = utils.NewAttemptLimiter(40, 10*60*1e9)
	return r, testDB
}

func addUser(t *testing.T, db *sql.DB, name, password string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO users (id, username, password) VALUES ($1,$2,$3)`, id, name, password); err != nil {
		t.Fatal(err)
	}
	return id
}

func login(r *gin.Engine, user, pass string) *httptest.ResponseRecorder {
	form := url.Values{"user": {user}, "password": {pass}}
	req := httptest.NewRequest("POST", "/loginform", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "1.2.3.4:5555"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func tokenFor(t *testing.T, id uuid.UUID, name string, admin bool) string {
	t.Helper()
	hex, _ := utils.ConvertUUIDToString(id)
	var tok string
	var err error
	if admin {
		tok, err = utils.CreateAdminToken(name, hex)
	} else {
		tok, err = utils.CreateToken(name, hex)
	}
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func call(r *gin.Engine, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestLoginMigratesPlaintextPasswordsAndIssuesAdminToken(t *testing.T) {
	r, db := setup(t)
	addUser(t, db, "admin", "s3cret") // legacy plaintext, like the existing rows

	w := login(r, "admin", "s3cret")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var stored string
	db.QueryRow(`SELECT password FROM users WHERE username='admin'`).Scan(&stored)
	if !utils.IsHashed(stored) {
		t.Errorf("the plaintext password should have been upgraded to bcrypt, stored = %q", stored)
	}
	// still works with the hash
	if w := login(r, "admin", "s3cret"); w.Code != 200 {
		t.Errorf("login after migration: %d", w.Code)
	}

	var out struct{ Token string }
	json.Unmarshal(w.Body.Bytes(), &out)
	if utils.VerifyAdminToken(out.Token) != nil {
		t.Error("the configured admin user must receive an admin token")
	}
}

func TestLoginDoesNotRevealWhichUsersExist(t *testing.T) {
	r, db := setup(t)
	addUser(t, db, "real", "pw")

	wrongPass := login(r, "real", "nope")
	noUser := login(r, "ghost", "nope")
	if wrongPass.Code != 401 || noUser.Code != 401 {
		t.Fatalf("codes %d / %d, want 401 / 401", wrongPass.Code, noUser.Code)
	}
	if wrongPass.Body.String() != noUser.Body.String() {
		t.Errorf("responses differ and leak user existence:\n%s\n%s", wrongPass.Body.String(), noUser.Body.String())
	}
	if strings.Contains(strings.ToLower(noUser.Body.String()), "sql") {
		t.Error("database error text must never reach the client")
	}
}

func TestLoginIsThrottledAfterRepeatedFailures(t *testing.T) {
	r, db := setup(t)
	addUser(t, db, "victim", "right")

	for i := 0; i < 8; i++ {
		if w := login(r, "victim", "wrong"); w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	if w := login(r, "victim", "right"); w.Code != http.StatusTooManyRequests {
		t.Errorf("after 8 failures even the right password must wait, got %d", w.Code)
	}
	// a different client is not affected by that IP's failures
	form := url.Values{"user": {"victim"}, "password": {"right"}}
	req := httptest.NewRequest("POST", "/loginform", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "9.9.9.9:1"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("the real operator on another IP must still be able to log in, got %d", w.Code)
	}
}

func TestAdminEndpointsRejectNormalUsers(t *testing.T) {
	r, db := setup(t)
	uid := addUser(t, db, "worker", "pw")
	tok := tokenFor(t, uid, "worker", false)

	for _, c := range []struct{ method, path, body string }{
		{"GET", "/getalluser", ""},
		{"GET", "/alltransactions", ""},
		{"GET", "/allfortniteaccounts", ""},
		{"POST", "/addnewuser", `{"username":"x","password":"y"}`},
		{"POST", "/removeusers", `["` + uuid.NewString() + `"]`},
		{"POST", "/updateuser", `{"id":"` + uid.String() + `","password":"hacked"}`},
	} {
		if w := call(r, c.method, c.path, tok, c.body); w.Code != http.StatusForbidden {
			t.Errorf("%s %s as a normal user: %d, want 403", c.method, c.path, w.Code)
		}
	}
	if w := call(r, "GET", "/getalluser", "", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", w.Code)
	}
}

func TestUpdateUserRejectsSQLInjectionAndHashesPasswords(t *testing.T) {
	r, db := setup(t)
	adminID := addUser(t, db, "admin", "x")
	victim := addUser(t, db, "victim", "orig")
	tok := tokenFor(t, adminID, "admin", true)

	evil := `{"id":"` + victim.String() + `","username = 'pwned', email":"x"}`
	if w := call(r, "POST", "/updateuser", tok, evil); w.Code != 400 {
		t.Errorf("injection through a column name must be rejected, got %d", w.Code)
	}
	var name string
	db.QueryRow(`SELECT username FROM users WHERE id=$1`, victim).Scan(&name)
	if name != "victim" {
		t.Errorf("username was changed to %q", name)
	}

	ok := `{"id":"` + victim.String() + `","password":"newpass"}`
	if w := call(r, "POST", "/updateuser", tok, ok); w.Code != 200 {
		t.Fatalf("legit update: %d %s", w.Code, w.Body.String())
	}
	var pw string
	db.QueryRow(`SELECT password FROM users WHERE id=$1`, victim).Scan(&pw)
	if !utils.IsHashed(pw) || !utils.CheckPassword(pw, "newpass") {
		t.Errorf("password must be stored hashed, got %q", pw)
	}
}

func TestTransactionsAreReturnedOldestFirstAndScopedToTheOwner(t *testing.T) {
	r, db := setup(t)
	owner := addUser(t, db, "owner", "pw")
	other := addUser(t, db, "other", "pw")
	mine := uuid.New()
	theirs := uuid.New()
	for _, a := range []struct {
		id, owner uuid.UUID
		name      string
	}{{mine, owner, "Mine"}, {theirs, other, "Theirs"}} {
		db.Exec(`INSERT INTO game_accounts (id, display_name, access_token, refresh_token, owner_user_id) VALUES ($1,$2,'t','r',$3)`, a.id, a.name, a.owner)
	}
	db.Exec(`INSERT INTO transactions (game_account_id, object_store_id, object_store_name, regular_price, final_price, gift_image, created_at) VALUES ($1,'a','old',1,1,'', now() - interval '2 days')`, mine)
	db.Exec(`INSERT INTO transactions (game_account_id, object_store_id, object_store_name, regular_price, final_price, gift_image, created_at) VALUES ($1,'b','new',1,1,'', now())`, mine)
	db.Exec(`INSERT INTO transactions (game_account_id, object_store_id, object_store_name, regular_price, final_price, gift_image) VALUES ($1,'c','not mine',1,1,'')`, theirs)

	w := call(r, "GET", "/transactions", tokenFor(t, owner, "owner", false), "")
	var out struct {
		Transactions []struct{ ObjectStoreName string }
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 || len(out.Transactions) != 2 || out.Transactions[0].ObjectStoreName != "old" || out.Transactions[1].ObjectStoreName != "new" {
		t.Errorf("%d %s", w.Code, w.Body.String())
	}
}
