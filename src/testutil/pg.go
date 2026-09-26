// Package testutil starts a throw-away PostgreSQL for integration tests, so the
// SQL of the backend is exercised against a real database instead of mocks.
package testutil

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	_ "github.com/lib/pq"
)

// Schema mirrors the production tables (see db/schema.sql) as they were BEFORE
// the startup upgrade, so EnsureSchema is tested on an "old" database.
const Schema = `
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    password TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE game_accounts (
    id UUID PRIMARY KEY NOT NULL,
    display_name TEXT NOT NULL,
    remaining_gifts INTEGER DEFAULT 0,
    pavos INTEGER DEFAULT 0,
    owner_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    access_token TEXT NOT NULL,
    access_token_exp INTEGER DEFAULT 0,
    access_token_exp_date TIMESTAMPTZ DEFAULT now(),
    refresh_token TEXT NOT NULL,
    refresh_token_exp INTEGER DEFAULT 0,
    refresh_token_exp_date TIMESTAMPTZ DEFAULT now(),
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT unique_game_account_per_user UNIQUE (display_name, owner_user_id)
);
CREATE TABLE transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    game_account_id UUID,
    sender_name TEXT,
    receiver_id TEXT,
    receiver_username TEXT,
    object_store_id TEXT NOT NULL,
    object_store_name TEXT NOT NULL,
    regular_price NUMERIC NOT NULL,
    final_price NUMERIC NOT NULL,
    gift_image TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE secrets (
    account_id TEXT PRIMARY KEY,
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    secret TEXT NOT NULL
);
`

func freePort() (uint32, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return uint32(l.Addr().(*net.TCPAddr).Port), nil
}

// StartPostgres boots a temporary PostgreSQL with the production schema loaded
// and returns a connection plus a function that shuts it down.
func StartPostgres() (*sql.DB, func(), error) {
	port, err := freePort()
	if err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp("", "kidstore-pg-*")
	if err != nil {
		return nil, nil, err
	}

	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Port(port).
		Username("postgres").Password("postgres").Database("kidstore").
		RuntimePath(filepath.Join(dir, "rt")).
		DataPath(filepath.Join(dir, "data")).
		Logger(nil).
		StartTimeout(90 * time.Second))
	if err := pg.Start(); err != nil {
		os.RemoveAll(dir)
		return nil, nil, fmt.Errorf("could not start embedded postgres: %w", err)
	}
	stop := func() {
		_ = pg.Stop()
		os.RemoveAll(dir)
	}

	dsn := fmt.Sprintf("host=127.0.0.1 port=%d user=postgres password=postgres dbname=kidstore sslmode=disable", port)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		stop()
		return nil, nil, err
	}
	if _, err := db.Exec(Schema); err != nil {
		db.Close()
		stop()
		return nil, nil, fmt.Errorf("could not create schema: %w", err)
	}
	return db, func() { db.Close(); stop() }, nil
}
