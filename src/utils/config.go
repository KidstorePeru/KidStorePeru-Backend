package utils

import (
	"KidStoreBotBE/src/types"
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
	FetchPavos bool
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

	if Config.SecretKey == "" {
		log.Fatal("SECRET_KEY environment variable is required but not set")
	}
	secretKey = []byte(Config.SecretKey)

	EpicClient = Config.Epic_client
	EpicSecret = Config.Epic_secret
	FetchPavos = Config.Fetch_pavos
}
