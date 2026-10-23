package utils

import (
	"KidStoreBotBE/src/types"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

// Config holds the fully-processed application configuration. It is populated
// once during package initialization and is the single source of truth for
// environment-derived settings.
var Config types.EnvConfigType

// Convenience globals kept for existing call sites.
var (
	EpicClient string
	EpicSecret string
)

func init() {
	// Load .env only when the file is present (local dev). In production the
	// hosting platform injects the variables directly.
	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(); err != nil {
			log.Fatalf("Error loading .env file: %v", err)
		}
	}

	if err := envconfig.Process("", &Config); err != nil {
		log.Fatalf("Error processing environment variables: %v", err)
	}

	secretKey = []byte(Config.SecretKey)
	EpicClient = Config.Epic_client
	EpicSecret = Config.Epic_secret
}

// ValidateConfig checks that the required configuration is present. Call it from
// main() and abort on error. It is not run automatically so tests can load the
// package without a full environment.
func ValidateConfig() error {
	var missing []string
	if Config.SecretKey == "" {
		missing = append(missing, "SECRET_KEY")
	}
	if Config.User == "" {
		missing = append(missing, "DB_USER")
	}
	if Config.Password == "" {
		missing = append(missing, "DB_PASSWORD")
	}
	if Config.DBName == "" {
		missing = append(missing, "DB_NAME")
	}
	// Without the Epic app credentials nothing that talks to Epic can work
	// (linking, refreshing tokens, gifting): fail at startup, not at 3 a.m.
	if Config.Epic_client == "" {
		missing = append(missing, "EPIC_CLIENT")
	}
	if Config.Epic_secret == "" {
		missing = append(missing, "EPIC_SECRET")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %v", missing)
	}
	if len(Config.SecretKey) < 32 {
		log.Printf("WARNING: SECRET_KEY has only %d characters. Use at least 32 random ones (openssl rand -hex 32): anyone who guesses it can forge login tokens.", len(Config.SecretKey))
	}
	return nil
}
