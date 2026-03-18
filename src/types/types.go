package types

import (
	"time"

	"github.com/google/uuid"
)

// General backend
type EnvConfigType struct {
	Host                   string `envconfig:"DB_HOST" default:"postgres.railway.internal"`
	Port                   int    `envconfig:"DB_PORT" default:"5432"`
	User                   string `envconfig:"DB_USER"`
	Password               string `envconfig:"DB_PASSWORD"`
	DBName                 string `envconfig:"DB_NAME"`
	SecretKey              string `envconfig:"SECRET_KEY"`
	AdminUser              string `envconfig:"ADMIN_USER"`
	AdminPass              string `envconfig:"ADMIN_PASS"`
	AcceptFriendsInMinutes int    `envconfig:"ACCEPT_FRIENDS_IN_SECONDS" default:"5"`
	RefreshTokensInMinutes int    `envconfig:"REFRESH_TOKENS_IN_MINUTES" default:"13"`
	Epic_client            string `envconfig:"EPIC_CLIENT" default:""`
	Epic_secret            string `envconfig:"EPIC_SECRET" default:""`
	Fetch_pavos            bool   `envconfig:"FETCH_PAVOS" default:"true"`
}

// Fortnite API Login
// response from client credentials grant
type AccessTokenResult struct {
	AccessToken string `json:"access_token"`
}

// response from deviceAuthorization
type DeviceResultResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationUriComplete string `json:"verification_uri_complete"`
	Expires_in              int    `json:"expires_in"`
}

// request from page for device code grant
type DeviceCodeRequest struct {
	DeviceCode string `json:"device_code"`
}

// response from device code grant
type LoginResultResponse struct {
	AccessToken                string `json:"access_token"`
	AccessTokenExpiration      int    `json:"expires_in"`
	AccessTokenExpirationDate  string `json:"expires_at"`
	RefreshToken               string `json:"refresh_token"`
	RefreshTokenExpiration     int    `json:"refresh_expires"`
	RefreshTokenExpirationDate string `json:"refresh_expires_at"`
	AccountId                  string `json:"account_id"`
	DisplayName                string `json:"displayName"`
	InAppId                    string `json:"in_app_id"`
}

// response from Account Device secrets grant
type DeviceSecretsResponse struct {
	DeviceId  string `json:"deviceId"`
	AccountId string `json:"accountId"`
	Secret    string `json:"secret"`
}

// Fortnite Account

type PavosResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Wallet struct {
			Purchased []struct {
				Type   string `json:"type"`
				Values struct {
					Shared  int `json:"Shared"`
					Switch  int `json:"Switch"`
					PCKorea int `json:"PCKorea"`
				} `json:"values"`
			} `json:"purchased"`
			Earned int `json:"earned"`
		} `json:"wallet"`
		LastUpdated string `json:"lastUpdated"`
	} `json:"data"`
}

// DB models
type User struct {
	ID        uuid.UUID
	Username  string
	Email     *string
	Password  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type GameAccount struct {
	ID                  uuid.UUID
	DisplayName         string
	RemainingGifts      int
	PaVos               int
	AccessToken         string
	AccessTokenExp      int
	AccessTokenExpDate  time.Time
	RefreshToken        string
	RefreshTokenExp     int
	RefreshTokenExpDate time.Time
	OwnerUserID         uuid.UUID
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type GameAccountSecrets struct {
	Owner_user_id uuid.UUID
	DeviceId      string
	AccountId     string
	Secret        string
}

type Transaction struct {
	ID              uuid.UUID
	GameAccountID   uuid.UUID
	SenderName      *string
	ReceiverID      *string
	ReceiverName    *string
	ObjectStoreID   string
	ObjectStoreName string
	RegularPrice    float64
	FinalPrice      float64
	GiftImage       string
	CreatedAt       time.Time
}

type FriendRequest struct {
	AccountID string `json:"accountId"`
	Groups    []any  `json:"groups"`
	Mutual    int    `json:"mutual"`
	Alias     string `json:"alias"`
	Note      string `json:"note"`
	Favorite  bool   `json:"favorite"`
	Created   string `json:"created"`
}

type AccountTokens struct {
	ID             uuid.UUID
	AccessTokenExp time.Time
	RefreshToken   string
	AccessToken    string
}

type RefreshList map[uuid.UUID]AccountTokens

// Map to simplified response
type SimplifiedAccount struct {
	ID             string                 `json:"id"`
	DisplayName    string                 `json:"displayName"`
	Pavos          int                    `json:"pavos"`
	RemainingGifts int                    `json:"remainingGifts"`
	GiftSlotStatus map[string]interface{} `json:"giftSlotStatus,omitempty"`
}

type GameFriendRequest struct {
	DisplayName string `json:"display_name" binding:"required"`
	AccountId   string `json:"account_id" binding:"required"`
}

type PublicAccountResult struct {
	AccountId   string `json:"id"`
	DisplayName string `json:"displayName"`
}

type FriendResult struct {
	AccountId string `json:"accountId"`
	Alias     string `json:"alias"`
	Created   string `json:"created"`
}

// Page
type AccountsToConnect struct {
	User_id     uuid.UUID `json:"user_id"`
	Device_code string    `json:"device_code"`
}

type Login struct {
	User     string `form:"user" json:"user" xml:"user" binding:"required"`
	Password string `form:"password" json:"password" xml:"password" binding:"required"`
}

type GiftRequest struct {
	AccountID    string `json:"account_id" binding:"required"`
	SenderName   string `json:"sender_username" binding:"required"`
	ReceiverID   string `json:"receiver_id" binding:"required"`
	ReceiverName string `json:"receiver_username" binding:"required"`
	GiftId       string `json:"gift_id" binding:"required"`
	GiftPrice    int    `json:"gift_price" binding:"required"`
	GiftName     string `json:"gift_name" binding:"required"`
	Message      string `json:"message" binding:"required"`
	GiftImage    string `json:"gift_image" binding:"required"`
}

type UpdatePavosRequest struct {
	AccountID string `json:"account_id" binding:"required"`
	Type      string `json:"type" binding:"required"` // "override" or "add"
	Amount    int    `json:"amount"`
}

// Other types
type AuthorizationCode struct {
	Code string `json:"code"`
}

type AccountIdStr struct {
	AccountId string
}
