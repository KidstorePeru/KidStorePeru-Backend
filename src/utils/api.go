package utils

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Read the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Authorization header missing"})
			return
		}

		// Should be "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Authorization header format must be Bearer {token}"})
			return
		}

		tokenString := parts[1]

		// Parse and validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return secretKey, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Invalid token"})
			return
		}

		// Extract userID from claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Invalid token claims"})
			return
		}
		userID, ok := claims["user_id"].(string)
		if !ok || userID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Invalid token claims"})
			return
		}

		c.Set("userID", userID)

		// Continue to handler
		c.Next()
	}
}

func GenericMiddleware(c *gin.Context) {
	// Middleware logic here
	//Options for preflight requests
	if c.Request.Method == "OPTIONS" {
		c.JSON(http.StatusOK, nil)
		c.Abort()
		return
	}
	c.Next()
}

// extractBearerToken returns the raw JWT from the "Authorization: Bearer <token>"
// header, or ("", false) if the header is missing or malformed.
func extractBearerToken(c *gin.Context) (string, bool) {
	authHeader := c.GetHeader("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// AdminProtectedEndpointHandler enforces that the caller holds a valid token
// with the admin claim. Returns 200 on success; on failure it writes the error
// response and returns the HTTP status code.
func AdminProtectedEndpointHandler(c *gin.Context) int {
	tokenString, ok := extractBearerToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Authorization header format must be Bearer {token}"})
		return http.StatusUnauthorized
	}
	if err := VerifyToken(tokenString); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Invalid token", "details": err.Error()})
		return http.StatusUnauthorized
	}
	if err := VerifyAdminToken(tokenString); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "Admin privileges required"})
		return http.StatusForbidden
	}
	return http.StatusOK
}

// ProtectedEndpointHandler enforces that the caller holds a valid token.
func ProtectedEndpointHandler(c *gin.Context) int {
	tokenString, ok := extractBearerToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Authorization header format must be Bearer {token}"})
		return http.StatusUnauthorized
	}
	if err := VerifyToken(tokenString); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Invalid token", "details": err.Error()})
		return http.StatusUnauthorized
	}
	return http.StatusOK
}

func IsTokenAdmin(c *gin.Context) bool {
	tokenString, ok := extractBearerToken(c)
	if !ok {
		return false
	}
	return VerifyAdminToken(tokenString) == nil
}
