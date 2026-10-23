package db

import (
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// ============================ DB METHODS ============================

// ========== USER METHODS ==========
func AddUser(db *sql.DB, user types.User) error {
	_, err := db.Exec(`INSERT INTO users (id, username, email, password, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now())`, user.ID, user.Username, user.Email, user.Password)
	if err != nil {
		fmt.Printf("Error adding user %q: %v\n", user.Username, err)
	}
	return err
}

func GetUserByUsername(db *sql.DB, username string) (types.User, error) {
	var user types.User
	err := db.QueryRow(`SELECT id, username, email, password, created_at, updated_at FROM users WHERE username = $1`, username).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt, &user.UpdatedAt)
	return user, err
}

func GetAllUsers(db *sql.DB) ([]types.User, error) {
	var users []types.User
	rows, err := db.Query(`SELECT id, username, email, created_at, updated_at FROM users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user types.User
		if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func UpdateUser(db *sql.DB, user types.User) error {
	_, err := db.Exec(`UPDATE users SET username = $1, email = $2, password = $3, updated_at = now() WHERE id = $4`, user.Username, user.Email, user.Password, user.ID)
	return err
}

func DeleteUsersByIds(db *sql.DB, ids []uuid.UUID) error {
	_, err := db.Exec(`DELETE FROM users WHERE id = ANY($1)`, pq.Array(ids))
	return err
}

func DeleteGameAccountByID(db *sql.DB, id uuid.UUID) error {
	//delete game account secrets first

	//remove - from id
	idStr, _ := utils.ConvertUUIDToString(id)

	_, err := db.Exec(`DELETE FROM secrets WHERE account_id = $1`, idStr)
	if err != nil {
		fmt.Printf("Error deleting game account secrets: %v\n", err)
	}

	_, err = db.Exec(`DELETE FROM game_accounts WHERE id = $1`, id)
	if err != nil {
		fmt.Printf("Error deleting game account: %v\n", err)
	}
	return err
}

func GetGameAccountSecrets(db *sql.DB, accountId string) (types.GameAccountSecrets, error) {
	var secrets types.GameAccountSecrets
	err := db.QueryRow(`SELECT  owner_user_id, device_id, account_id, secret FROM secrets WHERE account_id = $1`, accountId).Scan(&secrets.Owner_user_id, &secrets.DeviceId, &secrets.AccountId, &secrets.Secret)
	if err != nil {
		// "no rows" just means the account has no device auth; callers handle it.
		if err != sql.ErrNoRows {
			fmt.Printf("Error getting game account secrets: %v\n", err)
		}
		return types.GameAccountSecrets{}, err
	}
	return secrets, nil
}

func GetGameAccountsByOwnerLimited(db *sql.DB, ownerUserID uuid.UUID) ([]types.GameAccount, error) {
	query := `SELECT id, display_name, remaining_gifts, pavos, access_token, refresh_token, created_at, updated_at FROM game_accounts WHERE owner_user_id = $1`
	rows, err := db.Query(query, ownerUserID)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var accounts []types.GameAccount
	for rows.Next() {
		var account types.GameAccount

		err := rows.Scan(&account.ID, &account.DisplayName, &account.RemainingGifts, &account.PaVos, &account.AccessToken, &account.RefreshToken, &account.CreatedAt, &account.UpdatedAt)
		if err != nil {
			return nil, err
		}

		accounts = append(accounts, account)
	}
	return accounts, nil
}

func GetAllGameAccounts(db *sql.DB) ([]types.GameAccount, error) {
	var accounts []types.GameAccount
	rows, err := db.Query(`SELECT id, display_name, remaining_gifts, pavos, access_token, access_token_exp, access_token_exp_date, refresh_token, refresh_token_exp, refresh_token_exp_date FROM game_accounts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var account types.GameAccount
		if err := rows.Scan(&account.ID, &account.DisplayName, &account.RemainingGifts, &account.PaVos, &account.AccessToken, &account.AccessTokenExp, &account.AccessTokenExpDate, &account.RefreshToken, &account.RefreshTokenExp, &account.RefreshTokenExpDate); err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func GetGameAccount(db *sql.DB, id uuid.UUID) (types.GameAccount, error) {
	var account types.GameAccount
	err := db.QueryRow(`SELECT id, display_name, remaining_gifts, pavos, access_token, access_token_exp, access_token_exp_date, refresh_token, refresh_token_exp, refresh_token_exp_date, COALESCE(owner_user_id, '00000000-0000-0000-0000-000000000000') FROM game_accounts WHERE id = $1`, id).Scan(&account.ID, &account.DisplayName, &account.RemainingGifts, &account.PaVos, &account.AccessToken, &account.AccessTokenExp, &account.AccessTokenExpDate, &account.RefreshToken, &account.RefreshTokenExp, &account.RefreshTokenExpDate, &account.OwnerUserID)
	if err != nil {
		if err != sql.ErrNoRows {
			fmt.Printf("Error getting game account: %v\n", err)
		}
		return types.GameAccount{}, err
	}
	return account, nil
}

func GetAllGameAccountsIds(db *sql.DB) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	rows, err := db.Query(`SELECT id FROM game_accounts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func UpdateGameAccount(db *sql.DB, account types.GameAccount) error {
	query := "UPDATE game_accounts SET "
	params := []interface{}{}
	paramCounter := 1

	if account.DisplayName != "" {
		query += fmt.Sprintf("display_name = $%d, ", paramCounter)
		params = append(params, account.DisplayName)
		paramCounter++
	}
	if account.RemainingGifts != 0 {
		query += fmt.Sprintf("remaining_gifts = $%d, ", paramCounter)
		params = append(params, account.RemainingGifts)
		paramCounter++
	}
	if account.PaVos != 0 {
		query += fmt.Sprintf("pavos = $%d, ", paramCounter)
		params = append(params, account.PaVos)
		paramCounter++
	}
	if account.AccessToken != "" {
		query += fmt.Sprintf("access_token = $%d, ", paramCounter)
		params = append(params, account.AccessToken)
		paramCounter++
	}
	if account.AccessTokenExp != 0 {
		query += fmt.Sprintf("access_token_exp = $%d, ", paramCounter)
		params = append(params, account.AccessTokenExp)
		paramCounter++
	}
	if !account.AccessTokenExpDate.IsZero() {
		query += fmt.Sprintf("access_token_exp_date = $%d, ", paramCounter)
		params = append(params, account.AccessTokenExpDate)
		paramCounter++
	}
	if account.RefreshToken != "" {
		query += fmt.Sprintf("refresh_token = $%d, ", paramCounter)
		params = append(params, account.RefreshToken)
		paramCounter++
	}
	if account.RefreshTokenExp != 0 {
		query += fmt.Sprintf("refresh_token_exp = $%d, ", paramCounter)
		params = append(params, account.RefreshTokenExp)
		paramCounter++
	}
	if !account.RefreshTokenExpDate.IsZero() {
		query += fmt.Sprintf("refresh_token_exp_date = $%d, ", paramCounter)
		params = append(params, account.RefreshTokenExpDate)
		paramCounter++
	}

	if len(params) == 0 {
		return nil // nothing to update
	}

	query = query[:len(query)-2] // remove last comma and space
	query += fmt.Sprintf(" WHERE id = $%d", paramCounter)
	params = append(params, account.ID)

	_, err := db.Exec(query, params...)
	return err
}

// ========== TRANSACTION METHODS ==========
func AddTransaction(db *sql.DB, tx types.Transaction) error {
	_, err := db.Exec(`INSERT INTO transactions (id, game_account_id, sender_name, receiver_id, receiver_username, object_store_id, object_store_name, regular_price, final_price, gift_image, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())`, tx.ID, tx.GameAccountID, tx.SenderName, tx.ReceiverID, tx.ReceiverName, tx.ObjectStoreID, tx.ObjectStoreName, tx.RegularPrice, tx.FinalPrice, tx.GiftImage)
	if err != nil {
		fmt.Printf("Error adding transaction: %v\n", err)
	}
	return err
}

// DeleteOldestFakeTransactions frees gift slots when they are added back
// manually. It delegates to FreeGiftSlots, which prefers manual adjustments and
// in-game placeholders over real web gifts so the gift history is preserved.
func DeleteOldestFakeTransactions(db *sql.DB, accountID uuid.UUID, count int) {
	FreeGiftSlots(db, accountID, count)
}

// GetAllSlotExpiryTimes returns the expiry time for each used gift slot in the last 24h
func GetAllSlotExpiryTimes(db *sql.DB, accountID uuid.UUID) ([]time.Time, error) {
	rows, err := db.Query(`
		SELECT created_at + INTERVAL '24 hours' as expiry_time
		FROM transactions
		WHERE game_account_id = $1
		AND created_at >= NOW() - INTERVAL '24 hours'
		ORDER BY created_at ASC
	`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var times []time.Time
	for rows.Next() {
		var t time.Time
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		times = append(times, t)
	}
	return times, nil
}

func GetRemainingGifts(db *sql.DB, accountID uuid.UUID) (int, error) {
	// Use real-time calculation instead of stored value for accuracy
	return CalculateRemainingGifts(db, accountID)
}

func UpdateRemainingGifts(db *sql.DB, accountID uuid.UUID, remainingGifts int) error {
	_, err := db.Exec(`UPDATE game_accounts SET remaining_gifts = $1 WHERE id = $2`, remainingGifts, accountID)
	if err != nil {
		fmt.Printf("Error updating remaining gifts: %v\n", err)
	}
	return err
}

func GetPavos(db *sql.DB, accountID uuid.UUID) (int, error) {
	var pavos int
	err := db.QueryRow(`SELECT pavos FROM game_accounts WHERE id = $1`, accountID).Scan(&pavos)
	if err != nil {
		fmt.Printf("Error fetching PaVos: %v\n", err)
		return 0, err
	}
	return pavos, nil
}

func UpdatePaVos(db *sql.DB, accountID uuid.UUID, pavos int) error {
	_, err := db.Exec(`UPDATE game_accounts SET pavos = $1 WHERE id = $2`, pavos, accountID)
	if err != nil {
		fmt.Printf("Error updating PaVos: %v\n", err)
	}
	return err
}

// GetTransactionsByAccountIDs returns all transactions for the given accounts,
// oldest first (the UI sorts for display).
func GetTransactionsByAccountIDs(db *sql.DB, accountIDs []uuid.UUID) ([]types.Transaction, error) {
	if len(accountIDs) == 0 {
		return []types.Transaction{}, nil
	}
	rows, err := db.Query(`SELECT id, game_account_id, sender_name, receiver_id, receiver_username, object_store_id, object_store_name, regular_price, final_price, gift_image, created_at FROM transactions WHERE game_account_id = ANY($1) ORDER BY created_at ASC`, pq.Array(accountIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	transactions := []types.Transaction{}
	for rows.Next() {
		var tx types.Transaction
		if err := rows.Scan(&tx.ID, &tx.GameAccountID, &tx.SenderName, &tx.ReceiverID, &tx.ReceiverName, &tx.ObjectStoreID, &tx.ObjectStoreName, &tx.RegularPrice, &tx.FinalPrice, &tx.GiftImage, &tx.CreatedAt); err != nil {
			return nil, err
		}
		transactions = append(transactions, tx)
	}
	return transactions, rows.Err()
}

// CalculateRemainingGifts properly calculates remaining gifts based on 24-hour cooldown
func CalculateRemainingGifts(db *sql.DB, accountID uuid.UUID) (int, error) {
	// Count transactions that are less than 24 hours old
	// These are the "used" gift slots that haven't reset yet
	var usedGifts int
	err := db.QueryRow(`
		SELECT COUNT(*) 
		FROM transactions 
		WHERE game_account_id = $1 
		AND created_at >= NOW() - INTERVAL '24 hours'
	`, accountID).Scan(&usedGifts)

	if err != nil {
		return 0, fmt.Errorf("could not count used gifts: %w", err)
	}

	// Each account has MaxGiftsPer24h gifts, so remaining = max - used
	remainingGifts := MaxGiftsPer24h - usedGifts
	if remainingGifts < 0 {
		remainingGifts = 0 // Ensure we don't go negative
	}

	return remainingGifts, nil
}

// UpdateAllRemainingGifts updates the remaining_gifts field for all accounts based on 24-hour cooldown
func UpdateAllRemainingGifts(db *sql.DB) error {
	// Get all game account IDs
	accountIDs, err := GetAllGameAccountsIds(db)
	if err != nil {
		return fmt.Errorf("could not get game account IDs: %w", err)
	}

	// Update each account's remaining gifts
	for _, accountID := range accountIDs {
		remainingGifts, err := CalculateRemainingGifts(db, accountID)
		if err != nil {
			fmt.Printf("Error calculating remaining gifts for account %s: %v\n", accountID, err)
			continue
		}

		if err = UpdateRemainingGifts(db, accountID, remainingGifts); err != nil {
			fmt.Printf("Error updating remaining gifts for account %s: %v\n", accountID, err)
		}
	}

	return nil
}

// MaxGiftsPer24h is how many gifts one account may send in a rolling 24 hours.
const MaxGiftsPer24h = 5

// nextSlotTime returns when the account will have a free gift slot again, given
// the expiry times of its used slots (oldest first, at least one). A slot only
// frees up once fewer than MaxGiftsPer24h of them are still running, which is
// the expiry of the oldest one unless the account is (by a sync mismatch)
// above the maximum.
func nextSlotTime(expiries []time.Time) time.Time {
	idx := 0
	if len(expiries) > MaxGiftsPer24h {
		idx = len(expiries) - MaxGiftsPer24h
	}
	return expiries[idx]
}

// buildSlotStatus assembles the gift-slot status payload shared by the single
// and batch endpoints.
func buildSlotStatus(remaining int, expiries []time.Time) map[string]interface{} {
	if expiries == nil {
		expiries = []time.Time{}
	}
	status := map[string]interface{}{
		"remaining_gifts":   remaining,
		"max_gifts":         MaxGiftsPer24h,
		"used_gifts":        MaxGiftsPer24h - remaining,
		"slot_expiry_times": expiries,
	}
	if len(expiries) > 0 {
		next := nextSlotTime(expiries)
		status["next_slot_available"] = next
		status["time_until_next_slot"] = time.Until(next).String()
	} else {
		status["next_slot_available"] = nil
		status["time_until_next_slot"] = "All slots available"
	}
	return status
}

// GetGiftSlotStatus returns detailed information about gift slot availability
func GetGiftSlotStatus(db *sql.DB, accountID uuid.UUID) (map[string]interface{}, error) {
	remainingGifts, err := CalculateRemainingGifts(db, accountID)
	if err != nil {
		return nil, fmt.Errorf("could not calculate remaining gifts: %w", err)
	}
	slotExpiryTimes, err := GetAllSlotExpiryTimes(db, accountID)
	if err != nil {
		return nil, fmt.Errorf("could not get slot expiry times: %w", err)
	}
	return buildSlotStatus(remainingGifts, slotExpiryTimes), nil
}

// BatchCalculateRemainingGifts calculates remaining gifts for multiple accounts in a single query
func BatchCalculateRemainingGifts(db *sql.DB, accountIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	if len(accountIDs) == 0 {
		return make(map[uuid.UUID]int), nil
	}

	// Count transactions for all accounts in one query
	rows, err := db.Query(`
		SELECT game_account_id, COUNT(*) as used_gifts
		FROM transactions 
		WHERE game_account_id = ANY($1)
		AND created_at >= NOW() - INTERVAL '24 hours'
		GROUP BY game_account_id
	`, pq.Array(accountIDs))

	if err != nil {
		return nil, fmt.Errorf("could not batch count used gifts: %w", err)
	}
	defer rows.Close()

	usedGiftsMap := make(map[uuid.UUID]int)
	for rows.Next() {
		var accountID uuid.UUID
		var usedGifts int
		if err := rows.Scan(&accountID, &usedGifts); err != nil {
			return nil, fmt.Errorf("could not scan used gifts: %w", err)
		}
		usedGiftsMap[accountID] = usedGifts
	}

	// Calculate remaining gifts for all accounts
	result := make(map[uuid.UUID]int)
	for _, accountID := range accountIDs {
		usedGifts := usedGiftsMap[accountID] // defaults to 0 if not found
		remainingGifts := MaxGiftsPer24h - usedGifts
		if remainingGifts < 0 {
			remainingGifts = 0
		}
		result[accountID] = remainingGifts
	}

	return result, nil
}

// BatchGetGiftSlotStatus returns gift slot status for multiple accounts efficiently
func BatchGetGiftSlotStatus(db *sql.DB, accountIDs []uuid.UUID) (map[uuid.UUID]map[string]interface{}, error) {
	if len(accountIDs) == 0 {
		return make(map[uuid.UUID]map[string]interface{}), nil
	}

	remainingGiftsMap, err := BatchCalculateRemainingGifts(db, accountIDs)
	if err != nil {
		return nil, fmt.Errorf("could not batch calculate remaining gifts: %w", err)
	}

	// Get ALL slot expiry times for all accounts in one query (oldest first = soonest to expire)
	rows, err := db.Query(`
		SELECT game_account_id, created_at + INTERVAL '24 hours' as expiry_time
		FROM transactions
		WHERE game_account_id = ANY($1)
		AND created_at >= NOW() - INTERVAL '24 hours'
		ORDER BY game_account_id, created_at ASC
	`, pq.Array(accountIDs))

	if err != nil {
		return nil, fmt.Errorf("could not batch get slot expiry times: %w", err)
	}
	defer rows.Close()

	allExpiryTimes := make(map[uuid.UUID][]time.Time)
	for rows.Next() {
		var accID uuid.UUID
		var expiryTime time.Time
		if err := rows.Scan(&accID, &expiryTime); err != nil {
			return nil, fmt.Errorf("could not scan expiry time: %w", err)
		}
		allExpiryTimes[accID] = append(allExpiryTimes[accID], expiryTime)
	}

	result := make(map[uuid.UUID]map[string]interface{})
	for _, accountID := range accountIDs {
		result[accountID] = buildSlotStatus(remainingGiftsMap[accountID], allExpiryTimes[accountID])
	}
	return result, rows.Err()
}

// IsUniqueViolation reports whether err is PostgreSQL's unique-constraint
// violation (e.g. a username that already exists).
func IsUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}
