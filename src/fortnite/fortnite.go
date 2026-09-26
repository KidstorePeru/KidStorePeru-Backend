package fortnite

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// UpdatePavosGameAccountManually lowers the stored pavos by amountToSubtract
// (clamped at zero). It is the immediate, offline estimate applied right after
// a gift; the next sync with Epic replaces it with the real balance.
func UpdatePavosGameAccountManually(db *sql.DB, accountID uuid.UUID, amountToSubtract int) (int, error) {
	newPavos, err := database.SubtractPaVos(db, accountID, amountToSubtract)
	if err != nil {
		return 0, fmt.Errorf("could not update PaVos for account %s: %w", accountID, err)
	}
	fmt.Printf("PaVos of account %s lowered by %d -> %d (estimate until the next Epic sync)\n", accountID, amountToSubtract, newPavos)
	return newPavos, nil
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

		// Read the account from Epic first so gifts sent from inside the game are
		// already counted in the slot check below. Best effort (a failure here is
		// not fatal) and skipped if the account was read a moment ago. It takes
		// the account lock itself, so it must run before we lock it.
		freshenBeforeGift(db, AccountId)

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
			resp := gin.H{
				"success": false,
				"error":   "No se pudo enviar el regalo",
				"details": describeAccountError(err),
			}
			var rejected *giftRejectedError
			switch {
			case errors.Is(err, ErrNeedsRelink):
				resp["needs_relink"] = true
			case errors.As(err, &rejected):
				// Read the real state from Epic (pavos, gifts sent in the last
				// 24h) so the account's numbers are correct after a rejection.
				scheduleSyncAfterGift(db, AccountId)
			}
			c.JSON(http.StatusBadGateway, resp)
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

		// Immediate estimate (the price of the gift), replaced by the real
		// balance from Epic a few seconds later.
		if _, err := UpdatePavosGameAccountManually(db, AccountId, req.GiftPrice); err != nil {
			fmt.Printf("Warning: could not update pavos: %v\n", err)
			warnings = append(warnings, "no se pudieron actualizar los pavos")
		}
		scheduleSyncAfterGift(db, AccountId)

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

	url := fmt.Sprintf("%s/fortnite/api/game/v2/profile/%s/client/GiftCatalogEntry?profileId=common_core", epicMCPBase, accountIDStr)
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

	// Rejection: keep Epic's reason, and never invent gift records from it.
	rejection := parseEpicError(resp.StatusCode, body)
	fmt.Printf("Gift rejected for account %s: HTTP %d code=%q message=%q\n", accountID, resp.StatusCode, rejection.Code, rejection.Message)
	return &giftRejectedError{Status: rejection.Status, Code: rejection.Code, Message: rejection.Message}
}

// giftRejectedError is Epic refusing a gift (as opposed to a network problem).
type giftRejectedError struct {
	Status  int
	Code    string
	Message string
}

func (e *giftRejectedError) Error() string {
	return explainGiftRejection(e.Status, e.Code, e.Message)
}

// explainGiftRejection turns Epic's error into a message the operator can act
// on. purchase_not_allowed is a catch-all in Epic's API: it is returned when
// the receiver already owns the item, when the accounts have not been friends
// for 48h, when the sender reached the daily gift limit, when the item left the
// shop... so it must NOT be read as "the account used all its gifts".
func explainGiftRejection(status int, code, message string) string {
	lc := strings.ToLower(code)
	msg := strings.TrimSpace(message)
	switch {
	case strings.Contains(lc, "purchase_not_allowed"):
		return "Epic no permitió este regalo (purchase_not_allowed). Puede ser porque: el receptor ya tiene el objeto, " +
			"no son amigos desde hace 48 h, la cuenta ya envió sus 5 regalos de las últimas 24 h, o el objeto ya no está en la tienda. " +
			"Detalle de Epic: " + msg
	case strings.Contains(lc, "mismatch") || strings.Contains(lc, "price"):
		return "El precio del objeto cambió en Epic. Recarga la tienda e inténtalo de nuevo. Detalle de Epic: " + msg
	case strings.Contains(lc, "insufficient") || strings.Contains(lc, "not_enough") || strings.Contains(lc, "balance"):
		return "La cuenta no tiene pavos suficientes para este regalo. Detalle de Epic: " + msg
	case msg != "":
		return fmt.Sprintf("Epic rechazó el regalo [%s]: %s", code, msg)
	default:
		return fmt.Sprintf("Epic rechazó el regalo (HTTP %d)", status)
	}
}

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

		// Read the real pavos (and gift history) from Epic.
		res, err := SyncAccountFromEpic(db, accountID)
		if err != nil {
			resp := gin.H{
				"success": false,
				"error":   "No se pudieron leer los pavos desde Epic",
				"details": describeAccountError(err),
			}
			if errors.Is(err, ErrNeedsRelink) {
				resp["needs_relink"] = true
			}
			c.JSON(http.StatusBadGateway, resp)
			return
		}

		data := gin.H{
			"account_id":   accountID.String(),
			"display_name": gameAccount.DisplayName,
			"pavos":        res.Pavos,
		}
		if res.GiftsKnown {
			data["gifts_sent_24h"] = res.GiftsLast24h
		}
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Pavos refreshed successfully",
			"data":    data,
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

		const maxManualPavos = 100_000_000
		if req.Amount > maxManualPavos || req.Amount < -maxManualPavos {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Amount out of range"})
			return
		}

		// A manual change is applied on top of what is stored; the periodic
		// sync with Epic will replace it with the real balance.
		var newPavos int
		if req.Type == "override" {
			newPavos = req.Amount
			if newPavos < 0 {
				newPavos = 0
			}
			err = database.UpdatePaVos(db, accountID, newPavos)
		} else {
			newPavos, err = database.AddPaVos(db, accountID, req.Amount)
		}
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

		if req.Amount < 0 || req.Amount > 5 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Amount must be between 0 and 5"})
			return
		}

		// Serialize with gift sending / history syncs for this account, and start
		// from the real (24h history based) count, not the cached column.
		unlock := lockAccount(accountID)
		defer unlock()
		current, err := database.CalculateRemainingGifts(db, accountID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not read remaining gifts"})
			return
		}
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
					ReceiverID:      strPtr(database.ManualAdjustmentID),
					ReceiverName:    strPtr("Ajuste manual"),
					ObjectStoreID:   database.ManualAdjustmentID,
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

		// Store what the history now says (it is the source of truth).
		if recalculated, cerr := database.CalculateRemainingGifts(db, accountID); cerr == nil {
			newVal = recalculated
		}
		if err := database.UpdateRemainingGifts(db, accountID, newVal); err != nil {
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
