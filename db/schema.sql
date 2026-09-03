-- KidStorePeru backend — database schema.
-- Apply once to a fresh database:  psql "$DATABASE_URL" -f db/schema.sql

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username   TEXT UNIQUE NOT NULL,
    email      TEXT,
    password   TEXT NOT NULL,               -- bcrypt hash
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS game_accounts (
    id                     UUID PRIMARY KEY NOT NULL,
    display_name           TEXT NOT NULL,
    remaining_gifts        INTEGER DEFAULT 0,
    pavos                  INTEGER DEFAULT 0,
    owner_user_id          UUID REFERENCES users(id) ON DELETE CASCADE,
    access_token           TEXT NOT NULL,
    access_token_exp       INTEGER DEFAULT 0,
    access_token_exp_date  TIMESTAMPTZ DEFAULT now(),
    refresh_token          TEXT NOT NULL,
    refresh_token_exp      INTEGER DEFAULT 0,
    refresh_token_exp_date TIMESTAMPTZ DEFAULT now(),
    created_at             TIMESTAMPTZ DEFAULT now(),
    updated_at             TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT unique_game_account_per_user UNIQUE (display_name, owner_user_id)
);

-- No FK on game_account_id: rows are kept for cooldown history even after an
-- account is disconnected.
CREATE TABLE IF NOT EXISTS transactions (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    game_account_id   UUID,
    sender_name       TEXT,
    receiver_id       TEXT,
    receiver_username TEXT,
    object_store_id   TEXT NOT NULL,
    object_store_name TEXT NOT NULL,
    regular_price     NUMERIC NOT NULL,
    final_price       NUMERIC NOT NULL,
    gift_image        TEXT NOT NULL,
    created_at        TIMESTAMPTZ DEFAULT now()
);

-- Speeds up the 24h cooldown / remaining-slots queries.
CREATE INDEX IF NOT EXISTS idx_transactions_account_created
    ON transactions (game_account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS secrets (
    account_id    TEXT PRIMARY KEY,
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id     TEXT NOT NULL,
    secret        TEXT NOT NULL
);

-- Seed the admin user. Replace the username with $ADMIN_USER and generate the
-- bcrypt hash yourself, e.g.:
--   htpasswd -bnBC 10 "" 'your-password' | tr -d ':\n' | sed 's/$2y/$2b/'
-- (a plaintext value here still works and is upgraded to bcrypt on first login).
-- INSERT INTO users (username, password) VALUES ('admin', '<bcrypt-hash>');
