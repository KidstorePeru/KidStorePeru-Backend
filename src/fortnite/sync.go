package fortnite

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"fmt"
	"math/rand/v2"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SyncResult summarizes one sync of an account with Epic.
type SyncResult struct {
	Pavos        int
	GiftsKnown   bool
	GiftsLast24h int
	GiftsAdded   int
}

// SyncAccountFromEpic reads the account's real pavos and (optionally) its gift
// history from Epic, stores the pavos and reconciles the 24h gift cooldown.
func SyncAccountFromEpic(db *sql.DB, accountID uuid.UUID) (*SyncResult, error) {
	snap, err := FetchProfileSnapshot(db, accountID)
	if err != nil {
		return nil, err
	}

	if err := database.SetPaVosSynced(db, accountID, snap.Pavos); err != nil {
		return nil, fmt.Errorf("could not store pavos: %w", err)
	}
	res := &SyncResult{Pavos: snap.Pavos, GiftsKnown: snap.GiftsKnown}

	if snap.GiftsKnown && utils.Config.GiftHistorySync {
		added, last24, rerr := reconcileGiftHistory(db, accountID, snap.Gifts)
		res.GiftsLast24h, res.GiftsAdded = last24, added
		if rerr != nil {
			fmt.Printf("Gift history reconcile failed for %s: %v\n", accountID, rerr)
		}
	} else if snap.GiftsKnown {
		res.GiftsLast24h = countGiftsLast24h(snap.Gifts, time.Now())
	}
	return res, nil
}

func countGiftsLast24h(gifts []EpicGift, now time.Time) int {
	n := 0
	for _, g := range gifts {
		if g.At.After(now.Add(-giftCooldown)) {
			n++
		}
	}
	return n
}

// reconcileGiftHistory aligns the local transactions with the gifts Epic says
// the account sent. It runs under the account's gift lock so it can never race
// with a web gift being sent and recorded at the same moment.
func reconcileGiftHistory(db *sql.DB, accountID uuid.UUID, epic []EpicGift) (added, last24h int, err error) {
	unlock := lockAccount(accountID)
	defer unlock()

	local, err := database.GetRecentTransactionsForReconcile(db, accountID)
	if err != nil {
		return 0, 0, err
	}
	plan := PlanGiftReconcile(epic, local, time.Now())
	last24h = plan.Last24h
	if plan.Suspicious {
		fmt.Printf("Gift history for %s reports %d gifts in 24h (implausible), ignoring it\n", accountID, plan.Last24h)
		return 0, last24h, nil
	}
	if len(plan.Insert) == 0 && len(plan.Retime) == 0 {
		return 0, last24h, nil
	}

	acc, err := database.GetGameAccount(db, accountID)
	if err != nil {
		return 0, last24h, err
	}
	sender := acc.DisplayName

	for _, r := range plan.Retime {
		if e := database.RetimeTransaction(db, r.TxID, r.Gift.At, r.Gift.ToAccountID); e != nil {
			fmt.Printf("Warning: could not retime manual adjustment %s: %v\n", r.TxID, e)
		}
	}
	for _, g := range plan.Insert {
		receiver := g.ToAccountID
		tx := types.Transaction{
			ID:              uuid.New(),
			GameAccountID:   accountID,
			SenderName:      &sender,
			ReceiverID:      &receiver,
			ObjectStoreID:   database.EpicHistoryID,
			ObjectStoreName: database.EpicHistoryName,
			GiftImage:       "",
		}
		if e := database.AddTransactionAt(db, tx, g.At); e != nil {
			fmt.Printf("Warning: could not record in-game gift for %s: %v\n", accountID, e)
			continue
		}
		added++
	}

	if remaining, cerr := database.CalculateRemainingGifts(db, accountID); cerr == nil {
		_ = database.UpdateRemainingGifts(db, accountID, remaining)
	}
	fmt.Printf("Gift history %s: %d in the last 24h, %d added from the game, %d manual adjustments adopted\n", accountID, last24h, added, len(plan.Retime))
	return added, last24h, nil
}

// GoSafe runs fn in a goroutine that survives panics (a panic in a background
// job used to take the whole server down).
func GoSafe(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("PANIC in background job %q: %v\n%s\n", name, r, debug.Stack())
			}
		}()
		fn()
	}()
}

// sleepJitter sleeps between min and min+spread (used to space out Epic calls).
func sleepJitter(min, spread time.Duration) {
	time.Sleep(min + time.Duration(rand.Int64N(int64(spread)+1)))
}

// StartPavosSync periodically syncs every linked account with Epic. Accounts
// are processed one at a time with a pause in between so Epic is never hit in
// bursts. Blocks forever; run it with GoSafe.
func StartPavosSync(db *sql.DB, interval time.Duration) {
	if interval <= 0 {
		fmt.Println("Automatic pavos sync is disabled (PAVOS_SYNC_MINUTES=0)")
		return
	}
	fmt.Printf("Automatic pavos sync every %s\n", interval)

	time.Sleep(45 * time.Second) // let the server settle after a deploy
	for {
		syncAllAccounts(db)
		time.Sleep(interval)
	}
}

func syncAllAccounts(db *sql.DB) {
	ids, err := database.GetAllGameAccountsIds(db)
	if err != nil {
		fmt.Printf("Pavos sync: could not list accounts: %v\n", err)
		return
	}
	ok, failed := 0, 0
	for _, id := range ids {
		if _, err := SyncAccountFromEpic(db, id); err != nil {
			failed++
			fmt.Printf("Pavos sync: account %s: %v\n", id, err)
		} else {
			ok++
		}
		sleepJitter(2*time.Second, 2*time.Second)
	}
	fmt.Printf("Pavos sync finished: %d ok, %d failed\n", ok, failed)
}

// scheduleSyncAfterGift re-reads the account from Epic shortly after a gift so
// the stored pavos become the real balance. Two passes because Epic's profile
// can lag a few seconds behind the purchase.
func scheduleSyncAfterGift(db *sql.DB, accountID uuid.UUID) {
	for _, delay := range postGiftSyncDelays {
		delay := delay
		time.AfterFunc(delay, func() {
			GoSafe("post-gift-sync", func() {
				if _, err := SyncAccountFromEpic(db, accountID); err != nil {
					fmt.Printf("Post-gift sync for %s: %v\n", accountID, err)
				}
			})
		})
	}
}

// freshenMaxAge is how recent a sync must be for freshenBeforeGift to skip it.
const freshenMaxAge = 20 * time.Second

// freshenBeforeGift syncs the account with Epic unless it was synced within
// freshenMaxAge. Errors are logged and ignored: the gift attempt itself will
// report any real credential problem.
func freshenBeforeGift(db *sql.DB, accountID uuid.UUID) {
	if m, err := database.GetPavosSyncedAt(db, []uuid.UUID{accountID}); err == nil {
		if t, ok := m[accountID]; ok && time.Since(t) < freshenMaxAge {
			return
		}
	}
	if _, err := SyncAccountFromEpic(db, accountID); err != nil {
		fmt.Printf("Pre-gift sync for %s: %v\n", accountID, err)
	}
}

// describeAccountError turns a low-level error into a short operator message.
func describeAccountError(err error) string {
	switch {
	case err == nil:
		return ""
	case strings.Contains(err.Error(), ErrNeedsRelink.Error()):
		return "La cuenta necesita volver a vincularse: Epic rechazó sus credenciales."
	default:
		return err.Error()
	}
}

// postGiftSyncDelays is when the account is re-read from Epic after a gift
// (a variable so tests can disable it).
var postGiftSyncDelays = []time.Duration{6 * time.Second, 60 * time.Second}
