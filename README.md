# KidStorePeru — Backend

Go + Gin API that powers the KidStorePeru Fortnite gifting dashboard. It manages
users, connected Fortnite (Epic) accounts, gift sending with a 24h per-account
cooldown, pavos (V-Bucks) tracking and transaction history.

## Stack

- Go 1.24, [Gin](https://github.com/gin-gonic/gin)
- PostgreSQL (`lib/pq`)
- JWT auth (`golang-jwt/jwt/v5`), bcrypt password hashing
- Epic Games OAuth (device-code + device-auth grants)

## Running locally

```bash
cp .env.example .env      # then fill in the values
go run .
```

The server listens on `$PORT` (default `8080`).

Database schema: [`db/schema.sql`](db/schema.sql).

## Configuration

All configuration comes from the environment (or `.env` locally). See
[`.env.example`](.env.example) for the full list. Required:

`DB_HOST` `DB_PORT` `DB_USER` `DB_PASSWORD` `DB_NAME` `SECRET_KEY`
`EPIC_CLIENT` `EPIC_SECRET`

## Layout

```
main.go                 server bootstrap, routing, CORS, graceful shutdown
src/types/              config + DTO structs
src/utils/              config loading, JWT, password hashing, auth middleware
src/db/                 all SQL
src/page/               auth + user/account/transaction handlers
src/fortnite/           Epic OAuth, gifting, pavos, friends, per-account locks
pavos_updater/          standalone CLI to refresh pavos for every account
```

## Deployment

Deployed on Railway, built with Railpack (auto-detects the Go version from
`go.mod`). Set the environment variables listed above in the service settings.
For the database, prefer the private network host (`postgres.railway.internal`,
port `5432`) over the public proxy.

## API

All routes except `GET /` and `POST /loginform` require
`Authorization: Bearer <jwt>`. Admin-only routes additionally require a token
with the `admin` claim (issued when logging in as `ADMIN_USER`).

| Method | Path | Notes |
|---|---|---|
| POST | `/loginform` | returns `{ token }` |
| GET | `/fortniteaccountsofuser` | caller's connected accounts |
| POST | `/connectfaccount` / `/finishconnectfaccount` | Epic device-code flow |
| POST | `/disconnectfortniteaccount` | owner/admin only |
| POST | `/sendGift` | owner/admin only, 5 gifts / 24h / account |
| POST | `/searchfortnitefriend` | owner/admin only |
| POST | `/refreshpavos` / `/updatepavos` / `/giftslotstatus` / `/updateremaininggifts` | owner/admin only |
| GET | `/transactions` | caller's transactions |
| POST | `/sendfriendrequest` | **admin only** (fans out over all accounts) |
| POST | `/addnewuser` `/removeusers` `/updateuser`, GET `/getalluser` `/allfortniteaccounts` `/alltransactions` | **admin only** |
