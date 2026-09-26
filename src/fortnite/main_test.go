package fortnite

import (
	"KidStoreBotBE/src/testutil"
	"database/sql"
	"fmt"
	"os"
	"testing"
)

// testDB is a real PostgreSQL shared by the integration tests of this package.
// It is nil when Postgres could not be started (the integration tests then
// skip; the pure unit tests still run).
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

func requireDB(t *testing.T) *sql.DB {
	t.Helper()
	if testDB == nil {
		t.Skip("PostgreSQL not available")
	}
	return testDB
}
