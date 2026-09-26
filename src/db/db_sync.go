package db

import (
	"KidStoreBotBE/src/types"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Object-store IDs / names used for transactions that are not regular web gifts.
const (
	ManualAdjustmentID = "manual-adjustment"
	EpicHistoryID      = "epic-history"
	EpicHistoryName    = "Regalo enviado desde el juego"

	// LegacyFabricatedGiftName is the name the old purchase_not_allowed handler
	// used for 5 fake transactions inserted at once. They produced the phantom
	// "all 5 gift slots used" state and are removed at startup.
	LegacyFabricatedGiftName = "External Gift"
)

// EnsureSchema applies small, idempotent schema upgrades and one-off data
// cleanups. It is safe to run on every boot.
func EnsureSchema(db *sql.DB) error {
	stmts := []string{
		`ALTER TABLE game_accounts ADD COLUMN IF NOT EXISTS pavos_synced_at TIMESTAMPTZ`,
		`CREATE INDEX IF NOT EXISTS idx_transactions_account_created ON transactions (game_account_id, created_at DESC)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("schema upgrade failed (%s): %w", s, err)
		}
	}

	// Remove the fabricated "5 gifts sent" rows created by the old
	// purchase_not_allowed handler (only the ones that still affect the 24h
	// cooldown; older history is left untouched).
	res, err := db.Exec(`DELETE FROM transactions WHERE object_store_name = $1 AND gift_image = '' AND created_at >= NOW() - INTERVAL '24 hours'`, LegacyFabricatedGiftName)
	if err != nil {
		return fmt.Errorf("legacy cleanup failed: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		fmt.Printf("Startup cleanup: removed %d fabricated gift rows that were blocking gift slots\n", n)
	}
	return nil
}

// ---------- game accounts ----------

// UpsertGameAccount inserts the account or, if it already exists, refreshes its
// tokens and display name (the owner is intentionally left unchanged).
func UpsertGameAccount(db *sql.DB, a types.GameAccount) error {
	_, err := db.Exec(`
		INSERT INTO game_accounts (id, display_name, remaining_gifts, pavos, access_token, access_token_exp, access_token_exp_date, refresh_token, refresh_token_exp, refresh_token_exp_date, owner_user_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now(), now())
		ON CONFLICT (id) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			access_token = EXCLUDED.access_token,
			access_token_exp = EXCLUDED.access_token_exp,
			access_token_exp_date = EXCLUDED.access_token_exp_date,
			refresh_token = EXCLUDED.refresh_token,
			refresh_token_exp = EXCLUDED.refresh_token_exp,
			refresh_token_exp_date = EXCLUDED.refresh_token_exp_date,
			updated_at = now()`,
		a.ID, a.DisplayName, a.RemainingGifts, a.PaVos, a.AccessToken, a.AccessTokenExp, a.AccessTokenExpDate,
		a.RefreshToken, a.RefreshTokenExp, a.RefreshTokenExpDate, a.OwnerUserID)
	return err
}

// UpsertGameAccountSecrets stores the device-auth credentials, replacing any
// previous (possibly revoked) pair for the same account.
func UpsertGameAccountSecrets(db *sql.DB, s types.GameAccountSecrets) error {
	_, err := db.Exec(`
		INSERT INTO secrets (owner_user_id, device_id, account_id, secret)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (account_id) DO UPDATE SET device_id = EXCLUDED.device_id, secret = EXCLUDED.secret`,
		s.Owner_user_id, s.DeviceId, s.AccountId, s.Secret)
	return err
}

// ---------- pavos ----------

// SetPaVosSynced stores pavos read from Epic and stamps the sync time.
func SetPaVosSynced(db *sql.DB, accountID uuid.UUID, pavos int) error {
	_, err := db.Exec(`UPDATE game_accounts SET pavos = $1, pavos_synced_at = now() WHERE id = $2`, pavos, accountID)
	return err
}

// SubtractPaVos atomically lowers the stored pavos (never below zero) and
// returns the new value. Avoids the read-modify-write race of the old helper.
func SubtractPaVos(db *sql.DB, accountID uuid.UUID, amount int) (int, error) {
	var pavos int
	err := db.QueryRow(`UPDATE game_accounts SET pavos = GREATEST(pavos - $1, 0) WHERE id = $2 RETURNING pavos`, amount, accountID).Scan(&pavos)
	return pavos, err
}

// AddPaVos atomically adds (or, with a negative amount, subtracts) pavos,
// clamped at zero, and returns the new value.
func AddPaVos(db *sql.DB, accountID uuid.UUID, amount int) (int, error) {
	var pavos int
	err := db.QueryRow(`UPDATE game_accounts SET pavos = GREATEST(pavos + $1, 0) WHERE id = $2 RETURNING pavos`, amount, accountID).Scan(&pavos)
	return pavos, err
}

// GetPavosSyncedAt returns when each account's pavos were last read from Epic.
// Accounts that were never synced are omitted. Failures are non-fatal for the
// callers (the column may not exist yet on a very old database).
func GetPavosSyncedAt(db *sql.DB, accountIDs []uuid.UUID) (map[uuid.UUID]time.Time, error) {
	out := make(map[uuid.UUID]time.Time)
	if len(accountIDs) == 0 {
		return out, nil
	}
	rows, err := db.Query(`SELECT id, pavos_synced_at FROM game_accounts WHERE id = ANY($1) AND pavos_synced_at IS NOT NULL`, pq.Array(accountIDs))
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var t time.Time
		if err := rows.Scan(&id, &t); err != nil {
			return out, err
		}
		out[id] = t
	}
	return out, rows.Err()
}

// ---------- transactions ----------

// AddTransactionAt inserts a transaction with an explicit created_at (used to
// record gifts that Epic reports with their real timestamp).
func AddTransactionAt(db *sql.DB, tx types.Transaction, at time.Time) error {
	_, err := db.Exec(`INSERT INTO transactions (id, game_account_id, sender_name, receiver_id, receiver_username, object_store_id, object_store_name, regular_price, final_price, gift_image, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		tx.ID, tx.GameAccountID, tx.SenderName, tx.ReceiverID, tx.ReceiverName, tx.ObjectStoreID, tx.ObjectStoreName, tx.RegularPrice, tx.FinalPrice, tx.GiftImage, at)
	return err
}

// ReconcileTx is the minimal view of a recent transaction needed to match it
// against Epic's gift history.
type ReconcileTx struct {
	ID     uuid.UUID
	At     time.Time
	Manual bool
}

// GetRecentTransactionsForReconcile returns the account's transactions from the
// last 26h (24h cooldown + slack), excluding the legacy fabricated rows.
func GetRecentTransactionsForReconcile(db *sql.DB, accountID uuid.UUID) ([]ReconcileTx, error) {
	rows, err := db.Query(`
		SELECT id, created_at, object_store_id
		FROM transactions
		WHERE game_account_id = $1
		  AND created_at >= NOW() - INTERVAL '26 hours'
		  AND object_store_name <> $2
		ORDER BY created_at ASC`, accountID, LegacyFabricatedGiftName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ReconcileTx
	for rows.Next() {
		var t ReconcileTx
		var storeID string
		if err := rows.Scan(&t.ID, &t.At, &storeID); err != nil {
			return nil, err
		}
		t.Manual = storeID == ManualAdjustmentID
		out = append(out, t)
	}
	return out, rows.Err()
}

// RetimeTransaction moves a (manual-adjustment) row to the real time Epic
// reported and relabels it as an in-game gift.
func RetimeTransaction(db *sql.DB, id uuid.UUID, at time.Time, receiverID string) error {
	_, err := db.Exec(`UPDATE transactions SET created_at = $1, object_store_id = $2, object_store_name = $3, receiver_id = $4 WHERE id = $5`,
		at, EpicHistoryID, EpicHistoryName, receiverID, id)
	return err
}

// FreeGiftSlots removes up to count of the account's transactions from the last
// 24h to free gift slots, preferring rows that are not real web gifts (manual
// adjustments and in-game placeholders) and, among those, the oldest first.
func FreeGiftSlots(db *sql.DB, accountID uuid.UUID, count int) {
	if count <= 0 {
		return
	}
	_, err := db.Exec(`
		DELETE FROM transactions
		WHERE id IN (
			SELECT id FROM transactions
			WHERE game_account_id = $1
			  AND created_at >= NOW() - INTERVAL '24 hours'
			ORDER BY (object_store_id IN ($3, $4)) DESC, created_at ASC
			LIMIT $2
		)`, accountID, count, ManualAdjustmentID, EpicHistoryID)
	if err != nil {
		fmt.Printf("Warning: could not free gift slots: %v\n", err)
	}
}
