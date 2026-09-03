package main

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/fortnite"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	// Configuration comes from the environment (or a local .env file), the same
	// way the main server loads it. See src/utils/config.go.
	//
	// Required: DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, SECRET_KEY.
	// When connecting over the public internet (e.g. a Railway proxy host)
	// set DB_SSLMODE=require.
	cfg := utils.Config

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatalf("Error opening database connection: %v", err)
	}
	defer db.Close()

	// Test the connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}

	fmt.Println("Successfully connected to the database")

	// Update pavos for all accounts
	fmt.Println("Starting pavos update for all accounts...")
	updateAllPavos(db)
	fmt.Println("Pavos update completed")
}

// updateAllPavos updates the pavos for all game accounts in the database
func updateAllPavos(db *sql.DB) {
	// Get all game accounts from the database
	gameAccounts, err := database.GetAllGameAccounts(db)
	if err != nil {
		log.Fatalf("Could not fetch all game accounts: %v", err)
	}

	if len(gameAccounts) == 0 {
		fmt.Println("No game accounts found in the database")
		return
	}

	fmt.Printf("Found %d game accounts to update\n", len(gameAccounts))

	// Update pavos for each account
	successCount := 0
	errorCount := 0

	for i, account := range gameAccounts {
		fmt.Printf("Updating pavos for account %d/%d: %s (ID: %s)\n",
			i+1, len(gameAccounts), account.DisplayName, account.ID)

		_, err := fortnite.UpdatePavosGameAccount(db, account.ID)
		if err != nil {
			fmt.Printf("Error updating pavos for account %s: %v\n", account.ID, err)
			errorCount++
		} else {
			fmt.Printf("Successfully updated pavos for account %s\n", account.ID)
			successCount++
		}
	}

	fmt.Printf("\nUpdate summary:\n")
	fmt.Printf("- Total accounts: %d\n", len(gameAccounts))
	fmt.Printf("- Successfully updated: %d\n", successCount)
	fmt.Printf("- Errors: %d\n", errorCount)
}
