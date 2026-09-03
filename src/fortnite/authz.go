package fortnite

import (
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

// authorizeAccountAccess verifies that the caller is either an admin or the
// owner of the given game account. On failure it writes the appropriate error
// response and returns false; the caller must then return immediately.
func authorizeAccountAccess(c *gin.Context, account types.GameAccount) bool {
	_, userID, err := utils.GetUserIdFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Unauthorized", "details": err.Error()})
		return false
	}

	if utils.IsTokenAdmin(c) || account.OwnerUserID == userID {
		return true
	}

	c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "You don't have permission to use this account"})
	return false
}

// requireAdmin verifies that the caller holds an admin token. On failure it
// writes a 403 response and returns false.
func requireAdmin(c *gin.Context) bool {
	if utils.IsTokenAdmin(c) {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "Admin privileges required"})
	return false
}
