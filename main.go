package main

import (
	"KidStoreBotBE/src/fortnite"
	page "KidStoreBotBE/src/page"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	_ "github.com/lib/pq" // <--- add this
)

// ============================ MAIN ============================
func main() {
	// Load environment variables from .env file

	//first check if the file exists and then load it
	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(); err != nil {
			log.Fatalf("Error loading .env file: %v", err)
		}
	}
	// Process environment variables into Config struct
	var cfg types.EnvConfigType
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatalf("Error processing environment variables: %v", err)
	}

	// Construct the PostgreSQL connection string
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName)
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

	router := gin.Default()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	allowedOrigins := map[string]bool{
		"*":                                true,
		"http://localhost:5173":            true,
		"http://localhost:3000":            true,
		"https://your-production-site.com": true,
		"chrome-extension://gmmkjpcadciiokjpikmkkmapphbmdjok":    true,
		"https://kidstoreperu-frontend-react-production.up.railway.app": true,
	}

	router.Use(cors.New(cors.Config{
		AllowOriginFunc: func(origin string) bool {
			fmt.Println("CORS Origin Check:", origin)
			return allowedOrigins[origin]
		},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Content-Length", "Accept", "Authorization"},
		ExposeHeaders:    []string{"X-Total-Count"},
		AllowWildcard:    true,
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	router.Use(utils.GenericMiddleware)

	gin.SetMode(gin.ReleaseMode)

	authorized := router.Group("/", utils.AuthMiddleware())
	authorized.Use(utils.GenericMiddleware)

	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome Gin Server")
	})

	authorized.GET("/protected", func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		//Get user from db
		_, dUserID, err := utils.GetUserIdFromToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": err})
		}
		IsTokenAdmin := utils.IsTokenAdmin(c)
		if IsTokenAdmin {
			fortnite.UpdatePavosForUser(db, dUserID, true)
		} else {
			fortnite.UpdatePavosForUser(db, dUserID, false)
		}

		// If the token is valid, proceed with the request to refresh pavos
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Welcome to the protected area"})
	})

	//login endpoint
	router.POST("/loginform", page.HandlerLoginForm(db, cfg.AdminUser))

	//user endpoints
	authorized.POST("/addnewuser", page.HandlerAddNewUser(db))
	authorized.POST("/removeusers", page.HandlerRemoveUsers(db))
	authorized.POST("/updateuser", page.HandlerUpdateUser(db))
	authorized.GET("/getalluser", page.HandlerGetAllUsers(db))
	authorized.GET("/fortniteaccountsofuser", page.HandlerGetGameAccountsByOwner(db))
	authorized.GET("/allfortniteaccounts", page.HandlerGetAllGameAccounts(db))

	//fortnite account endpoints
	authorized.POST("/connectfaccount", fortnite.HandlerConnectFortniteAccount(db))
	authorized.POST("/finishconnectfaccount", fortnite.HandlerFinishConnectFortniteAccount(db))

	authorized.POST("/disconnectfortniteaccount", fortnite.HandlerDisconnectFAccount(db))
	//authorized.GET("/faccountstate", fortnite.HandlerGetFAccountState(db))
	//authorized.POST("/connectfaccount", fortnite.HandlerAuthorizationCodeLogin(db, &refreshTokenList))
	authorized.POST("/sendGift", fortnite.HandlerSendGift(db))
	authorized.POST("/searchfortnitefriend", fortnite.HandlerSearchOnlineFortniteAccount(db))
	authorized.POST("/sendfriendrequest", fortnite.HandlerSendFriendRequestFromAllAccounts(db))
	authorized.POST("/refreshpavos", fortnite.HandlerRefreshPavosForAccount(db))
	authorized.POST("/giftslotstatus", fortnite.HandlerGetGiftSlotStatus(db))
	authorized.POST("/updatepavos", fortnite.HandlerUpdatePavosForAccount(db))
	//authorized.POST("/updatepavos", fortnite.HandlerUpdatePavosBulk(db))
	//fetch transactions
	authorized.GET("/transactions", page.HandlerGetTransactionsByAccount(db))
	authorized.GET("/alltransactions", page.HandlerGetTransactionsAdmin(db))

	go fortnite.StartFriendRequestHandler(db, cfg.AcceptFriendsInMinutes) // Check every 5 minutes
	//go fortnite.StartTokenRefresher(db)                                   // Check every 10 minutes
	go fortnite.UpdateRemainingGiftsInAccounts(db) // Check every 15 minutes

	router.Run(":8080")
}
