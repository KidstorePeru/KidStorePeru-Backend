package page

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/fortnite"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func HandlerLoginForm(db *sql.DB, adminUsername string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !utils.FetchPavos {
			//print true
			fmt.Println("FetchPavos is false")
		}
		var form types.Login
		if err := c.ShouldBind(&form); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}

		//Get user from db
		dbuser, err := database.GetUserByUsername(db, form.User)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Invalid credentials", "details": err.Error()})
			return
		}
		dbUserIDStr, err := utils.ConvertUUIDToString(dbuser.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Invalid user ID"})
			return
		}

		if !passwordMatches(db, dbuser, form.Password) {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Invalid Password"})
			return
		}

		isAdmin := dbuser.Username == adminUsername

		var tokenString string
		if isAdmin {
			tokenString, err = utils.CreateAdminToken(dbuser.Username, dbUserIDStr)
		} else {
			tokenString, err = utils.CreateToken(dbuser.Username, dbUserIDStr)
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not create token", "details": err.Error()})
			return
		}

		if utils.FetchPavos {
			fortnite.UpdatePavosForUser(db, dbuser.ID, isAdmin)
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "token": tokenString})
	}
}

// passwordMatches verifies a login attempt against the stored password. Stored
// passwords are bcrypt hashes; legacy plaintext passwords are still accepted
// and are transparently re-hashed on the next successful login.
func passwordMatches(db *sql.DB, dbuser types.User, attempt string) bool {
	if utils.IsHashed(dbuser.Password) {
		return utils.CheckPassword(dbuser.Password, attempt)
	}

	if dbuser.Password != attempt {
		return false
	}

	// Legacy plaintext match: upgrade the stored value to a bcrypt hash.
	if hashed, err := utils.HashPassword(attempt); err == nil {
		dbuser.Password = hashed
		if err := database.UpdateUser(db, dbuser); err != nil {
			fmt.Printf("Warning: could not migrate password hash for user %s: %v\n", dbuser.ID, err)
		}
	}
	return true
}

// ============================ USER HANDLERS ============================

func HandlerAddNewUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.AdminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		var newUser types.User
		if err := c.ShouldBindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}
		if newUser.ID == uuid.Nil {
			newUser.ID = uuid.New()
		}
		if newUser.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "password is required"})
			return
		}
		hashed, err := utils.HashPassword(newUser.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not hash password"})
			return
		}
		newUser.Password = hashed
		newUser.CreatedAt = time.Now()
		newUser.UpdatedAt = time.Now()
		if err := database.AddUser(db, newUser); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not add new user", "details": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "User added successfully"})
	}
}

func HandlerGetAllUsers(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.AdminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		users, err := database.GetAllUsers(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not fetch users", "details": err.Error()})
			return
		}
		c.JSON(http.StatusOK, users)
	}
}

func HandlerRemoveUsers(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.AdminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		//block deletion of admin account
		adminUser, err := database.GetUserByUsername(db, utils.Config.AdminUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not fetch admin user", "details": err.Error()})
			return
		}
		if adminUser.ID == uuid.Nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Admin user not found"})
			return
		}

		var ids []uuid.UUID
		if err := c.ShouldBindJSON(&ids); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}

		// Check if any of the IDs are the admin user ID
		if slices.Contains(ids, adminUser.ID) {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Cannot delete admin user"})
			return
		}

		errr := database.DeleteUsersByIds(db, ids)
		if errr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not remove users", "details": errr.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Users removed successfully"})
	}
}

func HandlerUpdateUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.AdminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		var updates map[string]interface{}
		if err := c.ShouldBindJSON(&updates); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}
		idStr, ok := updates["id"].(string)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "id is required"})
			return
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id format", "details": err.Error()})
			return
		}
		delete(updates, "id")
		if len(updates) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no fields to update"})
			return
		}

		// Column names cannot be parameterized, so restrict them to a fixed
		// allowlist to prevent SQL injection via the JSON keys.
		allowedColumns := map[string]bool{"username": true, "email": true, "password": true}

		setParts := []string{}
		args := []interface{}{}
		argIdx := 1
		for key, value := range updates {
			if !allowedColumns[key] {
				c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": fmt.Sprintf("field %q cannot be updated", key)})
				return
			}
			if key == "password" {
				plain, ok := value.(string)
				if !ok || plain == "" {
					c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "password must be a non-empty string"})
					return
				}
				hashed, err := utils.HashPassword(plain)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not hash password"})
					return
				}
				value = hashed
			}
			setParts = append(setParts, fmt.Sprintf("%s = $%d", key, argIdx))
			args = append(args, value)
			argIdx++
		}
		setParts = append(setParts, fmt.Sprintf("updated_at = $%d", argIdx))
		args = append(args, time.Now())
		argIdx++
		query := fmt.Sprintf(`UPDATE users SET %s WHERE id = $%d`, strings.Join(setParts, ", "), argIdx)
		args = append(args, id)
		_, err = db.Exec(query, args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not update user", "details": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "User updated successfully"})
	}
}

// endpoint to send all game accounts of the user
func HandlerGetGameAccountsByOwner(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}

		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Unauthorized"})
			return
		}

		userIDStr, ok := userID.(string) //ok
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Invalid user ID"})
			return
		}

		userUUID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Invalid user UUID format", "details": err.Error()})
			return
		}

		gameAccounts, err := database.GetGameAccountsByOwnerLimited(db, userUUID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not fetch game accounts", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "gameAccounts": buildSimplifiedAccounts(db, gameAccounts)})
	}
}

// buildSimplifiedAccounts enriches raw game accounts with batch-computed gift
// slot status and remaining-gift counts for the API response.
func buildSimplifiedAccounts(db *sql.DB, gameAccounts []types.GameAccount) []types.SimplifiedAccount {
	accountIDs := make([]uuid.UUID, len(gameAccounts))
	for i, account := range gameAccounts {
		accountIDs[i] = account.ID
	}

	giftSlotStatusMap, err := database.BatchGetGiftSlotStatus(db, accountIDs)
	if err != nil {
		fmt.Printf("Error batch getting gift slot status: %v\n", err)
		giftSlotStatusMap = make(map[uuid.UUID]map[string]interface{})
	}

	remainingGiftsMap, err := database.BatchCalculateRemainingGifts(db, accountIDs)
	if err != nil {
		fmt.Printf("Error batch calculating remaining gifts: %v\n", err)
		remainingGiftsMap = make(map[uuid.UUID]int)
	}

	result := make([]types.SimplifiedAccount, 0, len(gameAccounts))
	for _, account := range gameAccounts {
		accountIDStr, err := utils.ConvertUUIDToString(account.ID)
		if err != nil {
			continue
		}

		// Use the minimum of the calculated and stored counts so manual
		// downward adjustments are respected; never go negative.
		remaining := remainingGiftsMap[account.ID]
		if account.RemainingGifts < remaining {
			remaining = account.RemainingGifts
		}
		if remaining < 0 {
			remaining = 0
		}

		result = append(result, types.SimplifiedAccount{
			ID:             accountIDStr,
			DisplayName:    account.DisplayName,
			Pavos:          account.PaVos,
			RemainingGifts: remaining,
			GiftSlotStatus: giftSlotStatusMap[account.ID],
		})
	}
	return result
}

func HandlerGetTransactionsAdmin(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.AdminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		rows, err := db.Query(`SELECT id, game_account_id, sender_name, receiver_id, receiver_username, object_store_id, object_store_name, regular_price, final_price, gift_image, created_at FROM transactions`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not fetch transactions", "details": err.Error()})
			return
		}
		defer rows.Close()

		var transactions []types.Transaction
		for rows.Next() {
			var tx types.Transaction
			if err := rows.Scan(&tx.ID, &tx.GameAccountID, &tx.SenderName, &tx.ReceiverID, &tx.ReceiverName, &tx.ObjectStoreID, &tx.ObjectStoreName, &tx.RegularPrice, &tx.FinalPrice, &tx.GiftImage, &tx.CreatedAt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not scan transaction", "details": err.Error()})
				return
			}
			transactions = append(transactions, tx)
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "transactions": transactions})
	}
}

func HandlerGetTransactionsByAccount(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		_, userID, err := utils.GetUserIdFromToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Unauthorized", "details": err.Error()})
			return
		}

		gameAccounts, err := database.GetGameAccountsByOwnerLimited(db, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not fetch game accounts", "details": err.Error()})
			return
		}

		accountIDs := make([]uuid.UUID, len(gameAccounts))
		for i, account := range gameAccounts {
			accountIDs[i] = account.ID
		}

		transactions, err := database.GetTransactionsByAccountIDs(db, accountIDs)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not fetch transactions", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "transactions": transactions})
	}
}

func HandlerGetAllGameAccounts(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.AdminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		gameAccounts, err := database.GetAllGameAccounts(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not fetch game accounts", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "gameAccounts": buildSimplifiedAccounts(db, gameAccounts)})
	}
}
