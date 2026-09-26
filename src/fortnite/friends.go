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

// giftFriendshipMinAge is how long two accounts must have been friends before
// Epic allows a gift between them.
const giftFriendshipMinAge = 48 * time.Hour

// lookupAccountByDisplayName resolves an Epic display name to an account id and
// canonical display name, using the given game account's credentials.
func lookupAccountByDisplayName(db *sql.DB, viaAccount uuid.UUID, displayName string) (types.PublicAccountResult, error) {
	endpoint := fmt.Sprintf("%s/account/api/public/account/displayName/%s", epicAccountBase, url.PathEscape(displayName))
	request, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return types.PublicAccountResult{}, err
	}
	resp, err := ExecuteOperationWithRefresh(request, db, viaAccount, "displayNameLookup")
	if err != nil {
		return types.PublicAccountResult{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return types.PublicAccountResult{}, parseEpicError(resp.StatusCode, body)
	}
	var result types.PublicAccountResult
	if err := json.Unmarshal(body, &result); err != nil || result.AccountId == "" {
		return types.PublicAccountResult{}, fmt.Errorf("respuesta inválida de Epic al buscar al jugador")
	}
	return result, nil
}

// HandlerSearchOnlineFortniteAccount looks a player up by display name and
// reports whether they are a friend of the account long enough to be gifted.
func HandlerSearchOnlineFortniteAccount(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if utils.ProtectedEndpointHandler(c) != http.StatusOK {
			return
		}

		var req types.GameFriendRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}
		req.DisplayName = strings.TrimSpace(req.DisplayName)
		if req.DisplayName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Escribe el nombre del jugador"})
			return
		}

		accountID, err := uuid.Parse(req.AccountId)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid account ID format"})
			return
		}

		// Only the account owner (or an admin) may search from this account.
		gameAccount, err := database.GetGameAccount(db, accountID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Game account not found"})
			return
		}
		if !authorizeAccountAccess(c, gameAccount) {
			return
		}

		fail := func(status int, msg string, err error) {
			resp := gin.H{"success": false, "error": msg}
			if err != nil {
				resp["details"] = describeAccountError(err)
				if errors.Is(err, ErrNeedsRelink) {
					resp["needs_relink"] = true
				}
			}
			c.JSON(status, resp)
		}

		target, err := lookupAccountByDisplayName(db, accountID, req.DisplayName)
		if err != nil {
			var ee *epicError
			if errors.As(err, &ee) && ee.Status == http.StatusNotFound {
				fail(http.StatusNotFound, "No existe un jugador de Epic con ese nombre", nil)
				return
			}
			fail(http.StatusBadGateway, "No se pudo buscar al jugador en Epic", err)
			return
		}

		hexID, _ := utils.ConvertUUIDToString(accountID)
		targetHex := strings.ReplaceAll(target.AccountId, "-", "")
		reqFriends, _ := http.NewRequest("GET", fmt.Sprintf("%s/friends/api/v1/%s/friends/%s", epicFriendsBase, hexID, targetHex), nil)
		respFriends, err := ExecuteOperationWithRefresh(reqFriends, db, accountID, "friendCheck")
		if err != nil {
			fail(http.StatusBadGateway, "No se pudo consultar la lista de amigos en Epic", err)
			return
		}
		defer respFriends.Body.Close()
		friendBody, _ := io.ReadAll(io.LimitReader(respFriends.Body, 1<<20))

		if respFriends.StatusCode != http.StatusOK {
			ee := parseEpicError(respFriends.StatusCode, friendBody)
			if ee.Status == http.StatusNotFound && strings.Contains(ee.Code, "friendship_not_found") {
				c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "El usuario no está en la lista de amigos de esta cuenta", "details": ee.Message})
				return
			}
			fail(http.StatusBadGateway, "Epic no pudo confirmar la amistad", ee)
			return
		}

		var friendResult types.FriendResult
		if err := json.Unmarshal(friendBody, &friendResult); err != nil {
			fail(http.StatusBadGateway, "Respuesta inválida de Epic al consultar la amistad", err)
			return
		}
		friendCreated, err := time.Parse(time.RFC3339, friendResult.Created)
		if err != nil {
			fail(http.StatusBadGateway, "Fecha de amistad inválida en la respuesta de Epic", err)
			return
		}

		age := time.Since(friendCreated)
		reply := gin.H{
			"success":     true,
			"giftable":    age > giftFriendshipMinAge,
			"friend":      true,
			"user":        true,
			"accountId":   target.AccountId,
			"displayName": target.DisplayName,
			"created":     friendCreated.Format("02/01/2006 15:04") + " GMT-5",
		}
		if age <= giftFriendshipMinAge {
			hoursLeft := int((giftFriendshipMinAge - age).Hours()) + 1
			reply["error"] = fmt.Sprintf("Deben ser amigos por 48 horas antes de poder enviar un regalo (faltan ~%d h)", hoursLeft)
		}
		c.JSON(http.StatusOK, reply)
	}
}

func getIncomingRequests(db *sql.DB, gameAccount types.GameAccount) ([]types.FriendRequest, error) {
	hexID, err := utils.ConvertUUIDToString(gameAccount.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid game account ID: %w", err)
	}

	request, _ := http.NewRequest("GET", fmt.Sprintf("%s/friends/api/v1/%s/incoming", epicFriendsBase, hexID), nil)
	resp, err := ExecuteOperationWithRefresh(request, db, gameAccount.ID, "incomingFriends")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, parseEpicError(resp.StatusCode, body)
	}

	var friendRequests []types.FriendRequest
	if err := json.Unmarshal(body, &friendRequests); err != nil {
		return nil, err
	}
	for i := range friendRequests {
		friendRequests[i].AccountID = strings.ReplaceAll(friendRequests[i].AccountID, "-", "")
	}
	return friendRequests, nil
}

// acceptFriendRequests accepts every pending request. One failing request does
// not stop the others; the number accepted and the last error are returned.
func acceptFriendRequests(db *sql.DB, gameAccount types.GameAccount, friends []types.FriendRequest) (accepted int, lastErr error) {
	hexID, err := utils.ConvertUUIDToString(gameAccount.ID)
	if err != nil {
		return 0, fmt.Errorf("invalid game account ID: %w", err)
	}

	for _, friend := range friends {
		if err := postFriendship(db, gameAccount.ID, hexID, friend.AccountID, "acceptFriend"); err != nil {
			lastErr = err
			fmt.Printf("Failed to accept friend request from %s: %v\n", friend.AccountID, err)
			// Nothing else can succeed now: bad credentials, our friend list is
			// full, or Epic is throttling us. Stop instead of hammering Epic.
			if errors.Is(err, ErrNeedsRelink) || isFriendsFullError(err) || isThrottledError(err) {
				return accepted, err
			}
			continue
		}
		accepted++
		sleepJitter(300*time.Millisecond, 500*time.Millisecond)
	}
	return accepted, lastErr
}

// postFriendship accepts a pending request from, or sends one to, targetHex.
// (Epic uses the same call for both.)
func postFriendship(db *sql.DB, accountID uuid.UUID, hexID, targetHex, source string) error {
	request, _ := http.NewRequest("POST", fmt.Sprintf("%s/friends/api/v1/%s/friends/%s", epicFriendsBase, hexID, targetHex), nil)
	resp, err := ExecuteOperationWithRefresh(request, db, accountID, source)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent:
		return nil
	}
	return parseEpicError(resp.StatusCode, body)
}

// sendFriendRequest sends a friend request from a game account to a target account ID
func sendFriendRequest(db *sql.DB, gameAccount types.GameAccount, targetAccountID string) error {
	hexID, err := utils.ConvertUUIDToString(gameAccount.ID)
	if err != nil {
		return fmt.Errorf("invalid game account ID: %w", err)
	}
	if err := postFriendship(db, gameAccount.ID, hexID, targetAccountID, "sendFriendRequest"); err != nil {
		return fmt.Errorf("failed to send friend request from %s to %s: %w", hexID, targetAccountID, err)
	}
	return nil
}

// HandlerSendFriendRequestFromAllAccounts sends a friend request to a player
// from every linked account (admin only).
func HandlerSendFriendRequestFromAllAccounts(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if utils.ProtectedEndpointHandler(c) != http.StatusOK {
			return
		}
		// This fans out across every connected account, so it is admin-only.
		if !requireAdmin(c) {
			return
		}

		var req struct {
			DisplayName string `json:"display_name" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}

		gameAccounts, err := database.GetAllGameAccounts(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not fetch game accounts", "details": err.Error()})
			return
		}
		if len(gameAccounts) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "No game accounts found in database"})
			return
		}

		// Resolve the player once, using the first account that can do it.
		var targetUser types.PublicAccountResult
		var lookupErr error
		for _, acc := range gameAccounts {
			targetUser, lookupErr = lookupAccountByDisplayName(db, acc.ID, strings.TrimSpace(req.DisplayName))
			if lookupErr == nil {
				break
			}
			var ee *epicError
			if errors.As(lookupErr, &ee) && ee.Status == http.StatusNotFound {
				break // the player does not exist: no point trying other accounts
			}
		}
		if lookupErr != nil {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "User not found", "details": describeAccountError(lookupErr)})
			return
		}

		targetAccountID := strings.ReplaceAll(targetUser.AccountId, "-", "")

		var results []map[string]interface{}
		successCount, failureCount := 0, 0

		for _, account := range gameAccounts {
			sleepJitter(200*time.Millisecond, 500*time.Millisecond) // avoid rate limiting

			err := sendFriendRequest(db, account, targetAccountID)
			accountIDStr, _ := utils.ConvertUUIDToString(account.ID)

			entry := map[string]interface{}{
				"account_id":   accountIDStr,
				"display_name": account.DisplayName,
				"success":      err == nil,
			}
			if err != nil {
				failureCount++
				entry["error"] = describeAccountError(err)
				fmt.Printf("Failed to send friend request from %s (%s) to %s: %v\n", account.DisplayName, accountIDStr, targetAccountID, err)
			} else {
				successCount++
			}
			results = append(results, entry)
		}

		c.JSON(http.StatusOK, gin.H{
			"success":       true,
			"target_user":   targetUser.DisplayName,
			"target_id":     targetAccountID,
			"success_count": successCount,
			"failure_count": failureCount,
			"total":         len(gameAccounts),
			"results":       results,
		})
	}
}

// StartFriendRequestHandler periodically accepts the pending friend requests of
// every linked account, so customers who added the shop's accounts become
// friends without anyone doing it by hand. It blocks forever; run it with GoSafe.
func StartFriendRequestHandler(db *sql.DB, intervalSeconds int) {
	if intervalSeconds <= 0 {
		intervalSeconds = 60
	}
	// Polling every few seconds over all accounts got Epic to throttle us (429).
	if intervalSeconds < 15 {
		intervalSeconds = 15
	}
	for {
		time.Sleep(time.Duration(intervalSeconds) * time.Second)

		gameAccounts, err := database.GetAllGameAccounts(db)
		if err != nil {
			fmt.Printf("Error fetching game accounts: %v\n", err)
			continue
		}

		states := map[uuid.UUID]database.FriendsState{}
		ids := make([]uuid.UUID, 0, len(gameAccounts))
		for _, a := range gameAccounts {
			ids = append(ids, a.ID)
		}
		if m, serr := database.GetFriendsStates(db, ids); serr == nil {
			states = m
		}

		for _, account := range gameAccounts {
			processFriendRequests(db, account, states[account.ID])
		}
	}
}

// processFriendRequests accepts the pending requests of one account, unless its
// friend list is full (then it only re-checks now and then, so it resumes by
// itself once friends are removed by hand).
func processFriendRequests(db *sql.DB, account types.GameAccount, st database.FriendsState) {
	sleepJitter(time.Second, 2*time.Second) // avoid rate limiting

	stale := friendsCheckDue(account.ID, st)
	if st.Full && !stale {
		return // full and checked recently: do not bother Epic
	}
	if stale {
		friendsAttempts.Store(account.ID, time.Now())
		// Refresh the count (also detects that friends were removed).
		full, err := RefreshFriendsState(db, account.ID, 0)
		switch {
		case err == nil && full:
			fmt.Printf("Account %s has a full friend list, skipping automatic accepting\n", account.DisplayName)
			return
		case err != nil:
			// Count unavailable: fall through and let the accept itself tell.
			if errors.Is(err, ErrNeedsRelink) {
				return
			}
			if st.Full && isThrottledError(err) {
				return
			}
		}
	}

	friendRequests, err := getIncomingRequests(db, account)
	if err != nil {
		fmt.Printf("Failed to get friend requests for account %s: %v\n", account.DisplayName, err)
		return
	}
	if len(friendRequests) == 0 {
		if st.Full && stale {
			// Nothing pending, so it cannot be proven either way; keep the flag.
			_ = database.SetFriendsFull(db, account.ID, true)
		}
		return
	}

	accepted, err := acceptFriendRequests(db, account, friendRequests)
	switch {
	case err != nil && isFriendsFullError(err):
		_ = database.SetFriendsFull(db, account.ID, true)
		fmt.Printf("Account %s reached its friend limit (accepted %d): automatic accepting paused until friends are removed\n", account.DisplayName, accepted)
	case err != nil && isThrottledError(err):
		fmt.Printf("Account %s: Epic is throttling (accepted %d of %d), will continue next round\n", account.DisplayName, accepted, len(friendRequests))
		time.Sleep(5 * time.Second)
	case err != nil:
		fmt.Printf("Account %s: accepted %d of %d friend requests (last error: %v)\n", account.DisplayName, accepted, len(friendRequests), err)
	default:
		fmt.Printf("Accepted %d friend requests for account %s\n", accepted, account.DisplayName)
	}
	if accepted > 0 {
		if !isFriendsFullError(err) {
			_ = database.SetFriendsFull(db, account.ID, false)
		}
		// Update the shown count right away (also flags the account as full when
		// this batch used the last free slots).
		if _, rerr := RefreshFriendsState(db, account.ID, 0); rerr != nil && !isFriendsFullError(err) {
			fmt.Printf("Could not refresh friend count for %s: %v\n", account.DisplayName, rerr)
		}
	}
}
