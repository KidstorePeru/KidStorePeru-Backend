package utils

import (
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// secretKey is populated from the SECRET_KEY environment variable in config.go's
// init(). It is used to sign and verify all JWTs.
var secretKey []byte

func CreateToken(username string, userid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": username,
			"user_id":  userid,
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
		})
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", fmt.Errorf("could not sign token: %w", err)
	}
	return tokenString, nil
}

func CreateAdminToken(username string, userid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": username,
			"user_id":  userid,
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
			"admin":    true,
		})
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", fmt.Errorf("could not sign admin token: %w", err)
	}
	return tokenString, nil
}

func VerifyAdminToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	if err != nil {
		return err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims["admin"] == true {
			return nil
		}
	}
	return fmt.Errorf("invalid admin token")
}

func VerifyToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	if err != nil {
		return err
	}
	if !token.Valid {
		return fmt.Errorf("invalid token")
	}
	return nil
}

func GetUserIdFromToken(c *gin.Context) (string, uuid.UUID, error) {
	userID, exists := c.Get("userID")
	if !exists {
		return "", uuid.Nil, fmt.Errorf("no autorizado")

	}

	userIDStrTemp, ok := userID.(string)
	if !ok {
		return "", uuid.Nil, fmt.Errorf("id de usuario inválido")

	}
	userIDStr := strings.ReplaceAll(userIDStrTemp, "-", "")

	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("formato de UUID de usuario inválido: %v", err)
	}
	return userIDStr, userUUID, nil
}

func ConvertUUIDToString(uuidValue uuid.UUID) (string, error) {
	if uuidValue == uuid.Nil {
		return "", fmt.Errorf("UUID is nil")
	}
	return strings.ReplaceAll(uuidValue.String(), "-", ""), nil
}
