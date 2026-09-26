package fortnite

import (
	database "KidStoreBotBE/src/db"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPlanGiftReconcile(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	tx := func(d time.Duration, manual bool) database.ReconcileTx {
		return database.ReconcileTx{ID: uuid.New(), At: ago(d), Manual: manual}
	}

	t.Run("gift sent from this app is not duplicated", func(t *testing.T) {
		local := []database.ReconcileTx{tx(2*time.Hour, false)}
		epic := []EpicGift{{At: ago(2*time.Hour + 3*time.Minute)}}
		p := PlanGiftReconcile(epic, local, now)
		if len(p.Insert) != 0 || len(p.Retime) != 0 || p.Last24h != 1 {
			t.Errorf("plan = %+v", p)
		}
	})

	t.Run("gift sent from the game is added with its real time", func(t *testing.T) {
		epic := []EpicGift{{At: ago(5 * time.Hour), ToAccountID: "abc"}}
		p := PlanGiftReconcile(epic, nil, now)
		if len(p.Insert) != 1 || !p.Insert[0].At.Equal(ago(5*time.Hour)) {
			t.Errorf("plan = %+v", p)
		}
	})

	t.Run("a manual adjustment that stood in for it is adopted, not doubled", func(t *testing.T) {
		manual := tx(30*time.Minute, true)
		epic := []EpicGift{{At: ago(6 * time.Hour)}}
		p := PlanGiftReconcile(epic, []database.ReconcileTx{manual}, now)
		if len(p.Insert) != 0 || len(p.Retime) != 1 || p.Retime[0].TxID != manual.ID {
			t.Errorf("plan = %+v", p)
		}
	})

	t.Run("gifts older than 24h are ignored", func(t *testing.T) {
		epic := []EpicGift{{At: ago(30 * time.Hour)}, {At: ago(25 * time.Hour)}}
		p := PlanGiftReconcile(epic, nil, now)
		if len(p.Insert) != 0 || p.Last24h != 0 {
			t.Errorf("plan = %+v", p)
		}
	})

	t.Run("planning is idempotent", func(t *testing.T) {
		epic := []EpicGift{{At: ago(5 * time.Hour)}}
		first := PlanGiftReconcile(epic, nil, now)
		local := []database.ReconcileTx{{ID: uuid.New(), At: first.Insert[0].At}}
		second := PlanGiftReconcile(epic, local, now)
		if len(second.Insert) != 0 {
			t.Errorf("second run should not insert again: %+v", second)
		}
	})

	t.Run("an implausible history is ignored", func(t *testing.T) {
		var epic []EpicGift
		for i := 0; i < 12; i++ {
			epic = append(epic, EpicGift{At: ago(time.Duration(i+1) * time.Hour)})
		}
		p := PlanGiftReconcile(epic, nil, now)
		if !p.Suspicious || len(p.Insert) != 0 {
			t.Errorf("plan = %+v", p)
		}
	})

	t.Run("never double counts real web gifts", func(t *testing.T) {
		local := []database.ReconcileTx{tx(1*time.Hour, false), tx(2*time.Hour, false), tx(3*time.Hour, false)}
		epic := []EpicGift{{At: ago(1 * time.Hour)}, {At: ago(2 * time.Hour)}, {At: ago(3 * time.Hour)}, {At: ago(4 * time.Hour)}}
		p := PlanGiftReconcile(epic, local, now)
		if len(p.Insert) != 1 || len(p.Retime) != 0 {
			t.Errorf("plan = %+v", p)
		}
	})
}
