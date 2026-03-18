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

		err, err2 := sendGiftRequest(db, req.AccountID, AccountId, req.ReceiverID, req.GiftId, req.GiftPrice, &req.SenderName)
		if err != nil {
			fmt.Printf("Error sending gift request: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Could not send gift",
				"details": err.Error(),
			})
			return
		}

		// Attempt to record the transaction
		err = database.AddTransaction(db, types.Transaction{
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
		})
		if err != nil {
			fmt.Printf("Error adding transaction: %v\n", err)
			c.JSON(http.StatusAccepted, gin.H{
				"success": true,
				"message": "Regalo enviado exitosamente",
				"error":   "No se pudo registrar la transacción",
				"details": err.Error(),
				"giftInfo": gin.H{
					"senderName":   req.SenderName,
					"receiverName": req.ReceiverName,
					"giftName":     req.GiftName,
					"giftPrice":    req.GiftPrice,
					"giftImage":    req.GiftImage,
					"giftId":       req.GiftId,
				},
			})
			return
		}

		_, err = UpdatePavosGameAccount(db, AccountId)
		if err != nil || !utils.FetchPavos {
			fmt.Printf("Error updating PaVos from Epic automatically: %v\n", err)
			fmt.Printf("Attempting manual PaVos update by subtracting gift price: %d\n", req.GiftPrice)

			// Try manual update by subtracting the gift price
			_, manualErr := UpdatePavosGameAccountManually(db, AccountId, req.GiftPrice)
			if manualErr != nil {
				fmt.Printf("Error updating PaVos manually: %v\n", manualErr)
				c.JSON(http.StatusAccepted, gin.H{
					"success": true,
					"message": "Regalo enviado exitosamente",
					"error":   "No se pudieron actualizar los PaVos (automático ni manual)",
					"details": fmt.Sprintf("Automático: %v, Manual: %v", err.Error(), manualErr.Error()),
					"giftInfo": gin.H{
						"senderName":   req.SenderName,
						"receiverName": req.ReceiverName,
						"giftName":     req.GiftName,
						"giftPrice":    req.GiftPrice,
						"giftImage":    req.GiftImage,
						"giftId":       req.GiftId,
					},
				})
				return
			}

			// Manual update succeeded
			fmt.Printf("PaVos updated manually after automatic update failed\n")
		}

		err = database.UpdateRemainingGifts(db, AccountId, remainingGifts-1)
		if err != nil {
			fmt.Printf("Error updating remaining gifts: %v\n", err)
			c.JSON(http.StatusAccepted, gin.H{
				"success": true,
				"message": "Regalo enviado exitosamente",
				"error":   "No se pudo actualizar el contador de regalos restantes",
				"details": err.Error(),
				"giftInfo": gin.H{
					"senderName":   req.SenderName,
					"receiverName": req.ReceiverName,
					"giftName":     req.GiftName,
					"giftPrice":    req.GiftPrice,
					"giftImage":    req.GiftImage,
					"giftId":       req.GiftId,
				},
			})
			return
		}

		if err2 != nil {
			fmt.Printf("Gift sent with soft error: %v\n", err2)
			c.JSON(http.StatusAccepted, gin.H{
				"success": true,
				"message": "Regalo enviado exitosamente",
				"error":   "Ocurrió un error menor tras enviar el regalo",
				"details": err2.Error(),
				"giftInfo": gin.H{
					"senderName":   req.SenderName,
					"receiverName": req.ReceiverName,
					"giftName":     req.GiftName,
					"giftPrice":    req.GiftPrice,
					"giftImage":    req.GiftImage,
					"giftId":       req.GiftId,
				},
			})
			return
		}

		fmt.Printf("Gift sent successfully from %s to %s\n", req.AccountID, req.ReceiverID)
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Regalo enviado exitosamente",
			"giftInfo": gin.H{
				"senderName":   req.SenderName,
				"receiverName": req.ReceiverName,
				"giftName":     req.GiftName,
				"giftPrice":    req.GiftPrice,
				"giftImage":    req.GiftImage,
				"giftId":       req.GiftId,
			},
		})
	}
}

func sendGiftRequest(db *sql.DB, accountIDStr string, accountID uuid.UUID, receiverUserID string, giftItem string, giftPrice int, senderName *string) (error, error) {
	payload := map[string]interface{}{
		"offerId":            giftItem,
		"currency":           "MtxCurrency",
		"currencySubType":    "",
		"expectedTotalPrice": giftPrice,
		"gameContext":        "Frontend.CatabaScreen",
		"receiverAccountIds": []string{receiverUserID},
		"giftWrapTemplateId": "",
		"personalMessage":    "",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Error marshaling payload:", err)
		return err, nil
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://fngw-mcp-gc-livefn.ol.epicgames.com/fortnite/api/game/v2/profile/%s/client/GiftCatalogEntry?profileId=common_core", accountIDStr),
		bytes.NewBuffer(jsonPayload))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return err, nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ExecuteOperationWithRefresh(req, db, accountID, "gift")
	if err != nil {
		fmt.Println("Error executing request:", err)
		return err, nil
	}
	defer resp.Body.Close()

	fmt.Printf("Response status: %s\n", resp.Status)
	fmt.Printf("Response: %s\n", resp.Proto)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %w", err)
	}

	// Try to decode JSON if expected
	var errorResponse map[string]interface{}
	if err := json.Unmarshal(body, &errorResponse); err != nil {
		// Log raw body for debugging since it's not valid JSON
		fmt.Printf("Non-JSON response body: %s\n", string(body))
		return nil, fmt.Errorf("could not decode JSON, raw body: %s", string(body))
	}

	if errorCode, ok := errorResponse["errorCode"].(string); ok && errorCode == "errors.com.epicgames.modules.gamesubcatalog.purchase_not_allowed" {
		err = database.UpdateRemainingGifts(db, accountID, 0)
		if err != nil {
			fmt.Println("Error updating remaining gifts in database:", err)
			return nil, (fmt.Errorf("could not update remaining gifts in database: %s", err))
		}

		for range 5 {
			err = database.AddTransaction(db, types.Transaction{
				ID:              uuid.New(),
				GameAccountID:   accountID,
				SenderName:      senderName,
				ReceiverID:      &receiverUserID,
				ReceiverName:    nil,
				ObjectStoreID:   giftItem,
				ObjectStoreName: "External Gift",
				RegularPrice:    float64(giftPrice),
				FinalPrice:      float64(giftPrice),
				GiftImage:       "",
				CreatedAt:       time.Now(),
			})
			if err != nil {
				fmt.Println("Error adding external transaction:", err)
				return nil, (fmt.Errorf("failed to add external transaction: %s", err))
			}
		}

		msg := fmt.Sprintf("no remaining gifts available: %s", errorResponse["errorMessage"])
		fmt.Println(msg)
		return nil, (fmt.Errorf("%s", msg))
	}

	if resp.StatusCode < 200 || resp.StatusCode > 204 {
		msg := fmt.Sprintf("failed to send gift, status code: %d", resp.StatusCode)
		fmt.Println(msg)
		return nil, (fmt.Errorf("%s", msg))
	}

	return nil, nil
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

func UpdateRemainingGiftsInAccounts(db *sql.DB) error {
	// Sleep for 5 minutes (more frequent updates for better accuracy)
	time.Sleep(5 * time.Minute)

	fmt.Println("Starting gift slot refresh process...")

	// Use the new proper calculation method
	err := database.UpdateAllRemainingGifts(db)
	if err != nil {
		return fmt.Errorf("could not update remaining gifts: %w", err)
	}

	fmt.Println("Gift slot refresh completed successfully")
	return nil
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
