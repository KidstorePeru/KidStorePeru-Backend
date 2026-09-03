package fortnite

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func UpdatePavosForUser(db *sql.DB, userID uuid.UUID, admin bool) {
	var gameAccounts []types.GameAccount
	var err error

	if !admin {
		// Get game accounts for a specific user
		gameAccounts, err = database.GetGameAccountByOwner(db, userID)
		if err != nil {
			fmt.Printf("Could not fetch game accounts for user %s: %v\n", userID, err)
			return
		}
	} else {
		// Get all game accounts
		gameAccounts, err = database.GetAllGameAccounts(db)
		if err != nil {
			fmt.Printf("Could not fetch all game accounts: %v\n", err)
			return
		}
	}

	for _, account := range gameAccounts {
		//wait 1s+1rand(5) seconds before updating each account
		if utils.FetchPavos {
			time.Sleep(time.Duration(rand.Float32()+0.2) * time.Second)
		}
		_, err := UpdatePavosGameAccount(db, account.ID)
		if err != nil {
			fmt.Printf("Could not update PaVos for account %s: %v\n", account.ID, err)
			continue
		}
		fmt.Printf("Successfully updated PaVos for account %s\n", account.ID)
	}
}

func HandlerUpdatePavosForUser(db *sql.DB, userID uuid.UUID, admin bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}

		var gameAccounts []types.GameAccount
		var err error

		//get all game accounts for the user
		if !admin {
			//get user ID from context
			gameAccounts, err = database.GetGameAccountByOwner(db, userID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not fetch game accounts", "details": err.Error()})
				return
			}

		} else {
			//get all game accounts
			gameAccounts, err = database.GetAllGameAccounts(db)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not fetch game accounts", "details": err.Error()})
				return
			}

		}

		for _, account := range gameAccounts {
			//wait 1s+1rand(5) seconds before updating each account
			if utils.FetchPavos {
				time.Sleep(time.Duration(rand.Float32()+0.2) * time.Second)
			}
			_, err := UpdatePavosGameAccount(db, account.ID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"success": false,
					"error":   fmt.Sprintf("Could not update PaVos for account %s: %s", account.ID, err.Error()),
				})
				continue
			}
		}
		c.JSON(http.StatusOK, gin.H{"success": true})

	}
}

func UpdatePavosGameAccount(db *sql.DB, accountID uuid.UUID) (int, error) {
	if utils.FetchPavos {

		pavos, err := GetAccountPavos(db, accountID)
		if err != nil {
			fmt.Printf("Could not get PaVos for account %s.: %v\n", accountID, err)
			return 0, fmt.Errorf("could not get PaVos for account %s.: %s", accountID, err)
		}

		err = database.UpdatePaVos(db, accountID, pavos)
		if err != nil {
			fmt.Printf("Could not update PaVos for account %s.: %v\n", accountID, err)
			return 0, fmt.Errorf("could not update PaVos for account %s.: %s", accountID, err)
		}

		fmt.Printf("Successfully updated PaVos for account %s: %d\n", accountID, pavos)
		return pavos, nil

	} else {
		fmt.Printf("Skipping PaVos update for account %s due to FETCH_PAVOS=false\n", accountID)
		return 0, nil
	}
}

// UpdatePavosGameAccountManually manually updates pavos by subtracting a specific amount
func UpdatePavosGameAccountManually(db *sql.DB, accountID uuid.UUID, amountToSubtract int) (int, error) {
	// Get current pavos from database
	currentPavos, err := database.GetPavos(db, accountID)
	if err != nil {
		fmt.Printf("Could not get current PaVos for account %s: %v\n", accountID, err)
		return 0, fmt.Errorf("could not get current PaVos for account %s: %w", accountID, err)
	}

	// Calculate new pavos amount
	newPavos := currentPavos - amountToSubtract

	// Ensure pavos don't go negative
	if newPavos < 0 {
		fmt.Printf("Warning: Attempted to subtract %d pavos from account %s, but only %d pavos available. Setting to 0.\n",
			amountToSubtract, accountID, currentPavos)
		newPavos = 0
	}

	// Update pavos in database
	err = database.UpdatePaVos(db, accountID, newPavos)
	if err != nil {
		fmt.Printf("Could not manually update PaVos for account %s: %v\n", accountID, err)
		return 0, fmt.Errorf("could not manually update PaVos for account %s: %w", accountID, err)
	}

	fmt.Printf("Successfully manually updated PaVos for account %s: %d -> %d (subtracted %d)\n",
		accountID, currentPavos, newPavos, amountToSubtract)

	return newPavos, nil
}

// func HandlerUpdatePavosBulk(db *sql.DB, refreshList *RefreshList) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		result := utils.ProtectedEndpointHandler(c)
// 		if result != 200 {
// 			return
// 		}

// 		var req struct {
// 			Accounts []string `json:"accounts" binding:"required"`
// 		}
// 		if err := c.ShouldBindJSON(&req); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 			return
// 		}
// 		if len(req.Accounts) == 0 {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": "No accounts provided"})
// 			return
// 		}

// 		for _, accountIDStr := range req.Accounts {
// 			//parse the account ID
// 			accountID, err := uuid.Parse(accountIDStr)
// 			if err != nil {
// 				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid account ID format: %s", accountIDStr)})
// 				return
// 			}
// 			//get the access token from the refresh list
// 			accessToken := (*refreshList)[accountID].AccessToken
// 			if err != nil {
// 				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Could not get access token for account %s: %s", accountIDStr, err.Error())})
// 				return
// 			}
// 			//get the pavos from the account
// 			pavos, err := GetAccountPavos(accessToken)
// 			if err != nil {
// 				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Could not get PaVos for account %s: %s", accountIDStr, err.Error())})
// 				return
// 			}

// 			//update the pavos in the database
// 			err = UpdatePaVos(db, accountID, pavos)
// 			if err != nil {
// 				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Could not update PaVos for account %s: %s", accountIDStr, err.Error())})
// 				return
// 			}
// 			fmt.Printf("Updated PaVos for account %s: %d\n", accountIDStr, pavos)

// 		}

// 	}
// }

func GetAccountPavos(db *sql.DB, AccountID uuid.UUID) (int, error) {
	req, err := http.NewRequest("GET", "https://www.epicgames.com/account/v2/api/wallet/fortnite", nil)
	if err != nil {
		fmt.Printf("Could not create request for account %s: %v\n", AccountID, err)
		return 0, fmt.Errorf("could not create request: %w", err)
	}

	resp, err := ExecuteOperationWithRefresh(req, db, AccountID, "pavos")
	if err != nil {
		fmt.Printf("Could not send request for account %s: %v\n", AccountID, err)
		return 0, fmt.Errorf("could not send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Unexpected status code for account %s: %d\n", AccountID, resp.StatusCode)
		return 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response types.PavosResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		fmt.Printf("Could not decode response for account %s: %v\n", AccountID, err)
		return 0, fmt.Errorf("could not decode response: %w", err)
	}

	if !response.Success {
		fmt.Printf("API call was not successful for account %s\n", AccountID)
		return 0, fmt.Errorf("API call was not successful")
	}

	pavos := 0
	for _, purchase := range response.Data.Wallet.Purchased {
		if purchase.Type == "Currency:MtxPurchased" || purchase.Type == "Currency:MtxPurchaseBonus" {
			pavos += purchase.Values.Shared
		}
	}

	if pavos < 0 {
		fmt.Printf("Negative PaVos value received for account %s: %d\n", AccountID, pavos)
		return 0, fmt.Errorf("negative PaVos value received: %d", pavos)
	}

	fmt.Printf("Fetched PaVos for account %s: %d\n", AccountID, pavos)
	return pavos, nil
}

// endpoint handler to send gift
func HandlerSendGift(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			fmt.Printf("Protected endpoint rejected request, status: %d\n", result)
			return
		}

		var req types.GiftRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			fmt.Printf("Failed to bind JSON: %v\n", err)
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}

		AccountId, err := uuid.Parse(req.AccountID)
		if err != nil {
			fmt.Printf("Failed to parse game ID: %v\n", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Invalid account ID format",
				"details": err.Error(),
			})
			return
		}

		// Only the account owner (or an admin) may gift from this account.
		gameAccount, err := database.GetGameAccount(db, AccountId)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Game account not found"})
			return
		}
		if !authorizeAccountAccess(c, gameAccount) {
			return
		}

		// Serialize gifts for this account so concurrent requests can't both
		// pass the slot check below.
		unlock := lockAccount(AccountId)
		defer unlock()

		remainingGifts, err := database.GetRemainingGifts(db, AccountId)
		fmt.Printf("Remaining gifts for account %s: %d\n", AccountId, remainingGifts)
		if err != nil {
			fmt.Printf("Error fetching remaining gifts: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Could not fetch remaining gifts",
				"details": err.Error(),
			})
			return
		}
		if remainingGifts <= 0 {

			fmt.Printf("No gifts remaining for account %s: %d\n", AccountId, remainingGifts)
			c.JSON(http.StatusForbidden, gin.H{
				"success":        false,
				"error":          "You have no gifts left to send",
				"remainingGifts": remainingGifts,
			})
			return
		}

		// Normalize IDs
		req.AccountID = strings.ReplaceAll(req.AccountID, "-", "")
		req.ReceiverID = strings.ReplaceAll(req.ReceiverID, "-", "")

		giftInfo := gin.H{
			"senderName":   req.SenderName,
			"receiverName": req.ReceiverName,
			"giftName":     req.GiftName,
			"giftPrice":    req.GiftPrice,
			"giftImage":    req.GiftImage,
			"giftId":       req.GiftId,
		}

		// Send the gift. This returns an error unless Epic actually accepted it,
		// so nothing below runs (and no slot/pavos is spent) on a failed gift.
		if err := sendGiftRequest(db, req.AccountID, AccountId, req.ReceiverID, req.GiftId, req.GiftPrice, &req.SenderName, req.Message); err != nil {
			fmt.Printf("Gift send FAILED for account %s -> %s: %v\n", AccountId, req.ReceiverID, err)
			c.JSON(http.StatusBadGateway, gin.H{
				"success": false,
				"error":   "No se pudo enviar el regalo",
				"details": err.Error(),
			})
			return
		}

		// ---- Epic accepted the gift. Everything below is bookkeeping: if it
		//      fails the gift still went through, so we answer 202 with warnings,
		//      never an error. ----
		var warnings []string

		if err := database.AddTransaction(db, types.Transaction{
			ID:              uuid.New(),
			GameAccountID:   AccountId,
			SenderName:      &req.SenderName,
			ReceiverID:      &req.ReceiverID,
			ReceiverName:    &req.ReceiverName,
			ObjectStoreID:   req.GiftId,
			ObjectStoreName: req.GiftName,
			RegularPrice:    float64(req.GiftPrice),
			FinalPrice:      float64(req.GiftPrice),
			GiftImage:       req.GiftImage,
			CreatedAt:       time.Now(),
		}); err != nil {
			fmt.Printf("Warning: could not record gift transaction: %v\n", err)
			warnings = append(warnings, "no se pudo registrar la transacción")
		}

		if _, err := UpdatePavosGameAccount(db, AccountId); err != nil || !utils.FetchPavos {
			if _, manualErr := UpdatePavosGameAccountManually(db, AccountId, req.GiftPrice); manualErr != nil {
				fmt.Printf("Warning: could not update pavos (auto: %v, manual: %v)\n", err, manualErr)
				warnings = append(warnings, "no se pudieron actualizar los pavos")
			}
		}

		// Recompute the cached counter from the 24h transaction history so it
		// stays consistent with the source of truth.
		newRemaining, calcErr := database.CalculateRemainingGifts(db, AccountId)
		if calcErr != nil {
			newRemaining = remainingGifts - 1
		}
		if err := database.UpdateRemainingGifts(db, AccountId, newRemaining); err != nil {
			fmt.Printf("Warning: could not update remaining-gifts counter: %v\n", err)
			warnings = append(warnings, "no se pudo actualizar el contador de regalos")
		}

		if len(warnings) > 0 {
			c.JSON(http.StatusAccepted, gin.H{
				"success":  true,
				"message":  "Regalo enviado exitosamente",
				"warnings": warnings,
				"giftInfo": giftInfo,
			})
			return
		}

		fmt.Printf("Gift sent successfully from %s to %s\n", req.AccountID, req.ReceiverID)
		c.JSON(http.StatusOK, gin.H{
			"success":  true,
			"message":  "Regalo enviado exitosamente",
			"giftInfo": giftInfo,
		})
	}
}

// sendGiftRequest sends the gift to Epic. It returns nil ONLY if Epic accepted
// the gift (2xx). Every rejection — bad price, ineligible receiver, cooldown,
// auth failure, etc. — comes back as an error so the caller does not record a
// transaction or deduct pavos for a gift that never left.
func sendGiftRequest(db *sql.DB, accountIDStr string, accountID uuid.UUID, receiverUserID, giftItem string, giftPrice int, senderName *string, personalMessage string) error {
	// Epic rejects personal messages longer than 100 characters.
	if utf8.RuneCountInString(personalMessage) > 100 {
		personalMessage = string([]rune(personalMessage)[:100])
	}

	payload := map[string]interface{}{
		"offerId":            giftItem,
		"currency":           "MtxCurrency",
		"currencySubType":    "",
		"expectedTotalPrice": giftPrice,
		"gameContext":        "Frontend.CatabaScreen",
		"receiverAccountIds": []string{receiverUserID},
		"giftWrapTemplateId": "",
		"personalMessage":    personalMessage,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("could not build gift payload: %w", err)
	}

	url := fmt.Sprintf("https://fngw-mcp-gc-livefn.ol.epicgames.com/fortnite/api/game/v2/profile/%s/client/GiftCatalogEntry?profileId=common_core", accountIDStr)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("could not create gift request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ExecuteOperationWithRefresh(req, db, accountID, "gift")
	if err != nil {
		return fmt.Errorf("could not reach Epic: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Gift response for account %s: HTTP %d\n", accountID, resp.StatusCode)

	// 2xx = Epic accepted the gift.
	if resp.StatusCode >= 200 && resp.StatusCode <= 204 {
		return nil
	}

	// Rejection — surface Epic's reason.
	var epicErr struct {
		ErrorCode    string `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
	}
	_ = json.Unmarshal(body, &epicErr)

	// Per-account gift cap: the account genuinely cannot send more for 24h.
	// Record it the same way a real gift would so the cooldown is tracked.
	if epicErr.ErrorCode == "errors.com.epicgames.modules.gamesubcatalog.purchase_not_allowed" {
		if uerr := database.UpdateRemainingGifts(db, accountID, 0); uerr != nil {
			fmt.Printf("could not zero remaining gifts for %s: %v\n", accountID, uerr)
		}
		for i := 0; i < 5; i++ {
			_ = database.AddTransaction(db, types.Transaction{
				ID:              uuid.New(),
				GameAccountID:   accountID,
				SenderName:      senderName,
				ReceiverID:      &receiverUserID,
				ObjectStoreID:   giftItem,
				ObjectStoreName: "External Gift",
				RegularPrice:    float64(giftPrice),
				FinalPrice:      float64(giftPrice),
				GiftImage:       "",
				CreatedAt:       time.Now(),
			})
		}
		return fmt.Errorf("esta cuenta no tiene envíos disponibles por ahora (Epic: %s)", strings.TrimSpace(epicErr.ErrorMessage))
	}

	if epicErr.ErrorMessage != "" {
		return fmt.Errorf("Epic rechazó el regalo [%s]: %s", epicErr.ErrorCode, epicErr.ErrorMessage)
	}
	return fmt.Errorf("Epic rechazó el regalo (HTTP %d)", resp.StatusCode)
}

func SmartUpdatePavos(db *sql.DB, accountID uuid.UUID, pavos int) error {
	currentPavos, err := database.GetPavos(db, accountID)
	if err != nil {
		return fmt.Errorf("could not get current PaVos: %w", err)
	}

	if pavos < 0 && currentPavos+pavos < 0 {
		return fmt.Errorf("not enough PaVos to deduct")
	}

	newPavos := currentPavos + pavos
	if newPavos < 0 {
		newPavos = 0 // Ensure PaVos don't go negative
	}

	return database.UpdatePaVos(db, accountID, newPavos)

}

// func send_gift_request(account_id, access_token, offer_id, final_price, user_id):
//   url = f"https://fngw-mcp-gc-livefn.ol.epicgames.com/fortnite/api/game/v2/profile/{account_id}/client/GiftCatalogEntry?profileId=common_core"
//   payload = {
//       "offerId": offer_id,
//       "currency": "MtxCurrency",
//       "currencySubType": "",
//       "expectedTotalPrice": final_price,
//       "gameContext": "Frontend.CatabaScreen",
//       "receiverAccountIds": [user_id],
//       "giftWrapTemplateId": "",
//       "personalMessage": ""
//   }
//   headers = {
//       "Content-Type": "application/json",
//       "Authorization": f"Bearer {access_token}"
//   }

//   response = requests.post(url, json=payload, headers=headers)
//   with open('config.json', 'r') as file:
//     account_data = json.load(file)
//   for account_info in account_data:
//     device_id = account_info['deviceId']
//     secret = account_info['secret']
//   if response.status_code == 200:
//     print(f"[{account_info['accountId']}] Sent cosmetic gift to {user_id}")

// Handle Authorization_Code login  (input authorization code) output:
//raw example

// UpdateRemainingGiftsInAccounts periodically recalculates every account's
// remaining gift slots from the 24h transaction history. It runs forever and is
// meant to be started as a goroutine.
func UpdateRemainingGiftsInAccounts(db *sql.DB) {
	const interval = 5 * time.Minute

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if err := database.UpdateAllRemainingGifts(db); err != nil {
			fmt.Printf("Gift slot refresh failed: %v\n", err)
			continue
		}
		fmt.Println("Gift slot refresh completed successfully")
	}
}

// HandlerRefreshPavosForAccount handles refreshing pavos for a specific game account
func HandlerRefreshPavosForAccount(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}

		var req struct {
			AccountID string `json:"account_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Invalid request format",
				"details": err.Error(),
			})
			return
		}

		// Parse the account ID
		accountID, err := uuid.Parse(req.AccountID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Invalid account ID format",
				"details": err.Error(),
			})
			return
		}

		// Check if the account exists and user has access to it
		gameAccount, err := database.GetGameAccount(db, accountID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error":   "Game account not found",
				"details": err.Error(),
			})
			return
		}

		// Get user ID from token
		_, userID, err := utils.GetUserIdFromToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "Could not get user ID from token",
				"details": err.Error(),
			})
			return
		}

		// Check if user is admin or owns the account
		isAdmin := utils.IsTokenAdmin(c)
		if !isAdmin && gameAccount.OwnerUserID != userID {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   "You don't have permission to refresh pavos for this account",
			})
			return
		}

		// Update pavos for the account
		newPavos, err := UpdatePavosGameAccount(db, accountID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Could not refresh pavos",
				"details": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Pavos refreshed successfully",
			"data": gin.H{
				"account_id":   accountID.String(),
				"display_name": gameAccount.DisplayName,
				"pavos":        newPavos,
			},
		})
	}
}

// HandlerGetGiftSlotStatus returns detailed gift slot information for an account
func HandlerGetGiftSlotStatus(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}

		var req struct {
			AccountID string `json:"account_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Invalid request format",
				"details": err.Error(),
			})
			return
		}

		// Parse the account ID
		accountID, err := uuid.Parse(req.AccountID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Invalid account ID format",
				"details": err.Error(),
			})
			return
		}

		// Check if the account exists and user has access to it
		gameAccount, err := database.GetGameAccount(db, accountID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error":   "Game account not found",
				"details": err.Error(),
			})
			return
		}

		// Get user ID from token
		_, userID, err := utils.GetUserIdFromToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "Could not get user ID from token",
				"details": err.Error(),
			})
			return
		}

		// Check if user is admin or owns the account
		isAdmin := utils.IsTokenAdmin(c)
		if !isAdmin && gameAccount.OwnerUserID != userID {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   "You don't have permission to view this account's gift status",
			})
			return
		}

		// Get gift slot status
		status, err := database.GetGiftSlotStatus(db, accountID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Could not get gift slot status",
				"details": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"account_id":   accountID.String(),
				"display_name": gameAccount.DisplayName,
				"gift_status":  status,
			},
		})
	}
}

// HandlerUpdatePavosForAccount handles updating pavos for a specific game account
func HandlerUpdatePavosForAccount(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}

		var req types.UpdatePavosRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Invalid request format",
				"details": err.Error(),
			})
			return
		}

		// Parse the account ID
		accountID, err := uuid.Parse(req.AccountID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Invalid account ID format",
				"details": err.Error(),
			})
			return
		}

		// Validate type parameter
		if req.Type != "override" && req.Type != "add" {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Type must be either 'override' or 'add'",
			})
			return
		}

		// Check if the account exists and user has access to it
		gameAccount, err := database.GetGameAccount(db, accountID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"error":   "Game account not found",
				"details": err.Error(),
			})
			return
		}

		// Get user ID from token
		_, userID, err := utils.GetUserIdFromToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "Could not get user ID from token",
				"details": err.Error(),
			})
			return
		}

		// Check if user is admin or owns the account
		isAdmin := utils.IsTokenAdmin(c)
		if !isAdmin && gameAccount.OwnerUserID != userID {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   "You don't have permission to update pavos for this account",
			})
			return
		}

		// Get current pavos
		currentPavos, err := database.GetPavos(db, accountID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Could not get current pavos",
				"details": err.Error(),
			})
			return
		}

		var newPavos int
		if req.Type == "override" {
			// Set pavos to the specified amount
			newPavos = req.Amount
		} else if req.Type == "add" {
			// Add the amount to current pavos
			newPavos = currentPavos + req.Amount
		}

		// Ensure pavos don't go negative
		if newPavos < 0 {
			newPavos = 0
		}

		// Update pavos in database
		err = database.UpdatePaVos(db, accountID, newPavos)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Could not update pavos",
				"details": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Pavos updated successfully",
			"data": gin.H{
				"account_id":     accountID.String(),
				"display_name":   gameAccount.DisplayName,
				"previous_pavos": currentPavos,
				"new_pavos":      newPavos,
				"operation":      req.Type,
				"amount":         req.Amount,
			},
		})
	}

}

// HandlerUpdateRemainingGifts allows manually adjusting remaining gifts for an account.
// When subtracting slots, it also inserts fake transactions so the 24h cooldown
// is calculated identically to real gifts by the backend.
func HandlerUpdateRemainingGifts(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}

		var req struct {
			AccountID string `json:"account_id" binding:"required"`
			Type      string `json:"type" binding:"required"` // "add" | "subtract" | "override"
			Amount    int    `json:"amount"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request format", "details": err.Error()})
			return
		}

		if req.Type != "add" && req.Type != "subtract" && req.Type != "override" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Type must be 'add', 'subtract' or 'override'"})
			return
		}

		accountID, err := uuid.Parse(req.AccountID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid account ID"})
			return
		}

		gameAccount, err := database.GetGameAccount(db, accountID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Account not found"})
			return
		}

		_, userID, err := utils.GetUserIdFromToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Unauthorized"})
			return
		}

		isAdmin := utils.IsTokenAdmin(c)
		if !isAdmin && gameAccount.OwnerUserID != userID {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "No permission"})
			return
		}

		current := gameAccount.RemainingGifts
		var newVal int
		switch req.Type {
		case "add":
			newVal = current + req.Amount
		case "subtract":
			newVal = current - req.Amount
			if newVal < 0 {
				newVal = 0
			}
		case "override":
			newVal = req.Amount
		}
		if newVal > 5 {
			newVal = 5
		}

		// Calcular cuántos slots se están usando (restando)
		slotsUsed := current - newVal

		// Si se están restando slots, insertar transacciones ficticias
		// para que el cooldown de 24h funcione igual que con regalos reales
		if slotsUsed > 0 {
			senderName := gameAccount.DisplayName
			for i := 0; i < slotsUsed; i++ {
				fakeTx := types.Transaction{
					ID:              uuid.New(),
					GameAccountID:   accountID,
					SenderName:      &senderName,
					ReceiverID:      strPtr("manual-adjustment"),
					ReceiverName:    strPtr("Ajuste manual"),
					ObjectStoreID:   "manual-adjustment",
					ObjectStoreName: "Ajuste manual",
					RegularPrice:    0,
					FinalPrice:      0,
					GiftImage:       "",
				}
				if err := database.AddTransaction(db, fakeTx); err != nil {
					fmt.Printf("Warning: could not insert fake transaction: %v\n", err)
				}
			}
		}

		// Si se están agregando slots (add/override con más slots),
		// eliminar transacciones ficticias para liberar slots
		slotsFreed := newVal - current
		if slotsFreed > 0 {
			database.DeleteOldestFakeTransactions(db, accountID, slotsFreed)
		}

		err = database.UpdateRemainingGifts(db, accountID, newVal)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not update remaining gifts"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success":            true,
			"previous_remaining": current,
			"new_remaining":      newVal,
			"account_id":         req.AccountID,
			"display_name":       gameAccount.DisplayName,
		})
	}
}

// strPtr returns a pointer to a string value
func strPtr(s string) *string {
	return &s
}
