package fortnite

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// HandlerConnectFortniteAccount starts the Epic device-code flow: it returns the
// code/URL the operator must open to authorize the account.
func HandlerConnectFortniteAccount(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if utils.ProtectedEndpointHandler(c) != http.StatusOK {
			return
		}
		if _, _, err := utils.GetUserIdFromToken(c); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": err.Error()})
			return
		}

		// Step 1: client-credentials token
		tokens, err := postTokenGrant(url.Values{"grant_type": {"client_credentials"}})
		if err != nil {
			fmt.Printf("connectfaccount: client_credentials failed: %v\n", err)
			c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "No se pudo iniciar la vinculación con Epic", "details": err.Error()})
			return
		}

		// Step 2: device authorization
		req, _ := http.NewRequest("POST", epicAccountBase+"/account/api/oauth/deviceAuthorization", nil)
		req.Header.Set("Authorization", "bearer "+tokens.AccessToken)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := epicHTTPClient.Do(req)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "No se pudo contactar a Epic", "details": err.Error()})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

		if resp.StatusCode != http.StatusOK {
			ee := parseEpicError(resp.StatusCode, body)
			c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "Epic rechazó la solicitud de vinculación", "details": ee.Error()})
			return
		}

		var deviceResult types.DeviceResultResponse
		if err := json.Unmarshal(body, &deviceResult); err != nil || deviceResult.DeviceCode == "" {
			c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "Respuesta inválida de Epic al iniciar la vinculación"})
			return
		}

		// Send the verification page through Epic's logout so the operator can
		// sign in with the account they want to link.
		logoutURL := fmt.Sprintf("https://epicgames.com/id/logout?lang=en-US&redirectUrl=%s", url.QueryEscape(deviceResult.VerificationUriComplete))

		c.JSON(http.StatusOK, gin.H{
			"success":                   true,
			"message":                   "Please complete Fortnite login",
			"verification_uri_complete": logoutURL,
			"epic_url":                  deviceResult.VerificationUriComplete,
			"user_code":                 deviceResult.UserCode,
			"device_code":               deviceResult.DeviceCode,
			"expires_in":                deviceResult.Expires_in,
		})
	}
}

// HandlerFinishConnectFortniteAccount completes the device-code flow: it stores
// the account and its device-auth credentials, then reads the account's real
// pavos (and gift history) from Epic.
func HandlerFinishConnectFortniteAccount(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if utils.ProtectedEndpointHandler(c) != http.StatusOK {
			return
		}
		_, userID, err := utils.GetUserIdFromToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": err.Error()})
			return
		}

		var req types.DeviceCodeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}

		tokens, err := grantDeviceCode(req.DeviceCode)
		if err != nil {
			var ee *epicError
			if errors.As(err, &ee) && strings.Contains(ee.Code, "authorization_pending") {
				c.JSON(http.StatusConflict, gin.H{
					"success": false,
					"pending": true,
					"error":   "Todavía no autorizaste la cuenta en la página de Epic. Termina ese paso y vuelve a intentar.",
				})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Código inválido o vencido. Inicia la vinculación de nuevo.", "details": err.Error()})
			return
		}

		accountID, err := uuid.Parse(tokens.AccountId)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid account ID format", "details": err.Error()})
			return
		}

		// A different (non-admin) user must not take over an account that is
		// already linked to someone else.
		if existing, gerr := database.GetGameAccount(db, accountID); gerr == nil {
			if existing.OwnerUserID != uuid.Nil && existing.OwnerUserID != userID && !utils.IsTokenAdmin(c) {
				c.JSON(http.StatusConflict, gin.H{"success": false, "error": "Esta cuenta ya está vinculada a otro usuario"})
				return
			}
		}

		now := time.Now()
		accessTTL := tokens.AccessTokenExpiration
		if accessTTL <= 0 {
			accessTTL = 2 * 60 * 60
		}

		// Save the account right away (steps 2 and 3 below are best effort).
		// Upsert, so linking an account again (e.g. after Epic revoked its
		// credentials) refreshes it instead of failing on the duplicate key.
		if err := database.UpsertGameAccount(db, types.GameAccount{
			ID:                  accountID,
			DisplayName:         tokens.DisplayName,
			RemainingGifts:      5,
			AccessToken:         tokens.AccessToken,
			AccessTokenExp:      accessTTL,
			AccessTokenExpDate:  now.Add(time.Duration(accessTTL) * time.Second),
			RefreshToken:        tokens.RefreshToken,
			RefreshTokenExp:     tokens.RefreshTokenExpiration,
			RefreshTokenExpDate: now.Add(time.Duration(tokens.RefreshTokenExpiration) * time.Second),
			OwnerUserID:         userID,
		}); err != nil {
			fmt.Println("Error saving game account:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not save game account", "details": err.Error()})
			return
		}

		hexID := strings.ReplaceAll(tokens.AccountId, "-", "")
		displayName := tokens.DisplayName

		// Step 2: permanent device-auth credentials (keep the account alive
		// without needing the operator again).
		if secrets, derr := createDeviceAuth(hexID, tokens.AccessToken); derr != nil {
			fmt.Printf("Warning: could not create device auth for %s (the account will rely on its refresh token): %v\n", accountID, derr)
		} else {
			if serr := database.UpsertGameAccountSecrets(db, types.GameAccountSecrets{
				Owner_user_id: userID,
				DeviceId:      secrets.DeviceId,
				AccountId:     hexID,
				Secret:        secrets.Secret,
			}); serr != nil {
				fmt.Printf("Warning: could not save device secrets for %s: %v\n", accountID, serr)
			} else if fresh, gerr := grantDeviceAuth(types.GameAccountSecrets{DeviceId: secrets.DeviceId, AccountId: hexID, Secret: secrets.Secret}); gerr != nil {
				fmt.Printf("Warning: device auth login failed for %s: %v\n", accountID, gerr)
			} else {
				// Step 3: use the device-auth session from now on.
				if err := saveTokens(db, accountID, fresh); err != nil {
					fmt.Printf("Warning: could not store device-auth tokens for %s: %v\n", accountID, err)
				}
				if fresh.DisplayName != "" {
					displayName = fresh.DisplayName
				}
			}
		}

		// Read the real pavos (and gift history) from Epic.
		resp := gin.H{
			"success":      true,
			"message":      "Fortnite account connected successfully",
			"id":           tokens.AccountId,
			"username":     displayName,
			"pavos":        0,
			"pavos_synced": false,
		}
		if res, serr := SyncAccountFromEpic(db, accountID); serr != nil {
			fmt.Printf("Warning: initial sync failed for %s: %v\n", accountID, serr)
			resp["sync_error"] = serr.Error()
		} else {
			resp["pavos"] = res.Pavos
			resp["pavos_synced"] = true
			if res.GiftsKnown {
				resp["gifts_sent_24h"] = res.GiftsLast24h
			}
		}
		c.JSON(http.StatusOK, resp)
	}
}

// HandlerDisconnectFAccount unlinks (deletes) a game account.
func HandlerDisconnectFAccount(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if utils.ProtectedEndpointHandler(c) != http.StatusOK {
			return
		}

		var req struct {
			Id string `json:"id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}

		accountID, err := uuid.Parse(req.Id)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid account ID format"})
			return
		}

		// Only the owner (or an admin) may disconnect an account.
		gameAccount, err := database.GetGameAccount(db, accountID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Game account not found"})
			return
		}
		if !authorizeAccountAccess(c, gameAccount) {
			return
		}

		if err := database.DeleteGameAccountByID(db, accountID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not disconnect Fortnite account", "details": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Fortnite account disconnected successfully"})
	}
}
