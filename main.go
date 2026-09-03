package main

import (
	"KidStoreBotBE/src/fortnite"
	page "KidStoreBotBE/src/page"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

// ============================ MAIN ============================
func main() {
	gin.SetMode(gin.ReleaseMode)

	// Configuration (including .env loading) is processed once in
	// utils' package init(). See src/utils/config.go.
	cfg := utils.Config

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		fmt.Printf("Error connecting to the database: %v", err)
		panic(err)
	}

	router := gin.Default() // includes Logger + Recovery

	allowedOrigins := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, origin := range cfg.AllowedOrigins {
		if o := strings.TrimSpace(origin); o != "" {
			allowedOrigins[o] = true
		}
	}

	router.Use(cors.New(cors.Config{
		AllowOriginFunc: func(origin string) bool {
			return allowedOrigins[origin]
		},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Content-Length", "Accept", "Authorization"},
		ExposeHeaders:    []string{"X-Total-Count"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	router.Use(utils.GenericMiddleware)

	authorized := router.Group("/", utils.AuthMiddleware())

	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome Gin Server")
	})

	authorized.GET("/protected", func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		_, dUserID, err := utils.GetUserIdFromToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": err.Error()})
			return
		}
		IsTokenAdmin := utils.IsTokenAdmin(c)
		if IsTokenAdmin {
			fortnite.UpdatePavosForUser(db, dUserID, true)
		} else {
			fortnite.UpdatePavosForUser(db, dUserID, false)
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Welcome to the protected area"})
	})

	// login endpoint
	router.POST("/loginform", page.HandlerLoginForm(db, cfg.AdminUser))

	// user endpoints
	authorized.POST("/addnewuser", page.HandlerAddNewUser(db))
	authorized.POST("/removeusers", page.HandlerRemoveUsers(db))
	authorized.POST("/updateuser", page.HandlerUpdateUser(db))
	authorized.GET("/getalluser", page.HandlerGetAllUsers(db))
	authorized.GET("/fortniteaccountsofuser", page.HandlerGetGameAccountsByOwner(db))
	authorized.GET("/allfortniteaccounts", page.HandlerGetAllGameAccounts(db))

	// fortnite account endpoints
	authorized.POST("/connectfaccount", fortnite.HandlerConnectFortniteAccount(db))
	authorized.POST("/finishconnectfaccount", fortnite.HandlerFinishConnectFortniteAccount(db))
	authorized.POST("/disconnectfortniteaccount", fortnite.HandlerDisconnectFAccount(db))
	authorized.POST("/sendGift", fortnite.HandlerSendGift(db))
	authorized.POST("/searchfortnitefriend", fortnite.HandlerSearchOnlineFortniteAccount(db))
	authorized.POST("/sendfriendrequest", fortnite.HandlerSendFriendRequestFromAllAccounts(db))
	authorized.POST("/refreshpavos", fortnite.HandlerRefreshPavosForAccount(db))
	authorized.POST("/giftslotstatus", fortnite.HandlerGetGiftSlotStatus(db))
	authorized.POST("/updatepavos", fortnite.HandlerUpdatePavosForAccount(db))
	authorized.POST("/updateremaininggifts", fortnite.HandlerUpdateRemainingGifts(db)) // nueva ruta

	// fetch transactions
	authorized.GET("/transactions", page.HandlerGetTransactionsByAccount(db))
	authorized.GET("/alltransactions", page.HandlerGetTransactionsAdmin(db))

	go fortnite.StartFriendRequestHandler(db, cfg.AcceptFriendsInSeconds)
	go fortnite.UpdateRemainingGiftsInAccounts(db)

	if err := router.Run(":" + cfg.Port_HTTP); err != nil {
		panic(err)
	}
}
