package fortnite

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Base URLs of the Epic services we talk to. They are variables (not consts) so
// tests can point them at an httptest server.
var (
	epicAccountBase = "https://account-public-service-prod.ol.epicgames.com"
	epicMCPBase     = "https://fngw-mcp-gc-livefn.ol.epicgames.com"
	epicFriendsBase = "https://friends-public-service-prod.ol.epicgames.com"
)

// ErrNeedsRelink is returned (wrapped) when Epic definitively rejected the
// stored credentials of an account: the operator has to link it again. The
// account is NOT deleted automatically anymore.
var ErrNeedsRelink = errors.New("la cuenta necesita volver a vincularse")

// epicError is an error response from an Epic endpoint.
type epicError struct {
	Status  int
	Code    string
	Message string
}

func (e *epicError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("Epic %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("Epic HTTP %d", e.Status)
}

// parseEpicError builds an epicError from a response body (best effort).
func parseEpicError(status int, body []byte) *epicError {
	e := &epicError{Status: status}
	var parsed struct {
		ErrorCode    string `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
	}
	if json.Unmarshal(body, &parsed) == nil {
		e.Code = parsed.ErrorCode
		e.Message = parsed.ErrorMessage
	}
	return e
}

// isCredentialRejection reports whether err means Epic rejected the credentials
// themselves (as opposed to a network problem, rate limit or server error).
func isCredentialRejection(err error) bool {
	var ee *epicError
	if !errors.As(err, &ee) {
		return false
	}
	return (ee.Status == http.StatusBadRequest || ee.Status == http.StatusUnauthorized) && ee.Code != ""
}

func epicBasicAuth() string {
	return "basic " + base64.StdEncoding.EncodeToString([]byte(utils.EpicClient+":"+utils.EpicSecret))
}

// postTokenGrant performs an OAuth token request against Epic.
func postTokenGrant(form url.Values) (types.LoginResultResponse, error) {
	req, err := http.NewRequest("POST", epicAccountBase+"/account/api/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return types.LoginResultResponse{}, err
	}
	req.Header.Set("Authorization", epicBasicAuth())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := epicHTTPClient.Do(req)
	if err != nil {
		return types.LoginResultResponse{}, fmt.Errorf("could not reach Epic: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return types.LoginResultResponse{}, parseEpicError(resp.StatusCode, body)
	}

	var tokens types.LoginResultResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return types.LoginResultResponse{}, fmt.Errorf("invalid token response: %w", err)
	}
	if tokens.AccessToken == "" {
		return types.LoginResultResponse{}, fmt.Errorf("token response without access_token")
	}
	return tokens, nil
}

func grantDeviceCode(deviceCode string) (types.LoginResultResponse, error) {
	return postTokenGrant(url.Values{"grant_type": {"device_code"}, "device_code": {deviceCode}})
}

func grantDeviceAuth(s types.GameAccountSecrets) (types.LoginResultResponse, error) {
	return postTokenGrant(url.Values{
		"grant_type": {"device_auth"},
		"device_id":  {s.DeviceId},
		"secret":     {s.Secret},
		"account_id": {s.AccountId},
	})
}

func grantRefreshToken(refreshToken string) (types.LoginResultResponse, error) {
	return postTokenGrant(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
}

// createDeviceAuth registers a permanent device-auth credential for the account
// using a fresh access token.
func createDeviceAuth(accountIDHex, accessToken string) (types.DeviceSecretsResponse, error) {
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/account/api/public/account/%s/deviceAuth", epicAccountBase, accountIDHex), nil)
	if err != nil {
		return types.DeviceSecretsResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := epicHTTPClient.Do(req)
	if err != nil {
		return types.DeviceSecretsResponse{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return types.DeviceSecretsResponse{}, parseEpicError(resp.StatusCode, body)
	}
	var secrets types.DeviceSecretsResponse
	if err := json.Unmarshal(body, &secrets); err != nil {
		return types.DeviceSecretsResponse{}, err
	}
	if secrets.DeviceId == "" || secrets.Secret == "" {
		return types.DeviceSecretsResponse{}, fmt.Errorf("device auth response without credentials")
	}
	return secrets, nil
}

// saveTokens persists a fresh token set for the account.
func saveTokens(db *sql.DB, accountID uuid.UUID, t types.LoginResultResponse) error {
	accessTTL := t.AccessTokenExpiration
	if accessTTL <= 0 {
		accessTTL = 2 * 60 * 60
	}
	now := time.Now()
	return database.UpdateGameAccount(db, types.GameAccount{
		ID:                  accountID,
		AccessToken:         t.AccessToken,
		AccessTokenExp:      accessTTL,
		AccessTokenExpDate:  now.Add(time.Duration(accessTTL) * time.Second),
		RefreshToken:        t.RefreshToken,
		RefreshTokenExp:     t.RefreshTokenExpiration,
		RefreshTokenExpDate: now.Add(time.Duration(t.RefreshTokenExpiration) * time.Second),
		UpdatedAt:           now,
	})
}

// ---------- token refresh (serialized per account) ----------

var refreshLocks sync.Map // map[uuid.UUID]*sync.Mutex

func refreshLockFor(id uuid.UUID) *sync.Mutex {
	m, _ := refreshLocks.LoadOrStore(id, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// tokenNeedsRefresh reports whether the stored access token is expired or about
// to expire.
func tokenNeedsRefresh(a types.GameAccount, now time.Time) bool {
	if a.AccessToken == "" {
		return true
	}
	if a.AccessTokenExpDate.IsZero() {
		return false // unknown expiry: use it and let a 401 trigger the refresh
	}
	return now.After(a.AccessTokenExpDate.Add(-2 * time.Minute))
}

// refreshAccountToken obtains and stores a fresh access token for the account
// and returns it. Refreshes are serialized per account: Epic refresh tokens are
// single-use, so two concurrent refreshes used to make one of them fail (and,
// before, that got the account deleted). staleToken is the token the caller
// just used; if another goroutine already replaced it, that newer token is
// returned without hitting Epic again.
func refreshAccountToken(db *sql.DB, accountID uuid.UUID, staleToken string) (string, error) {
	mu := refreshLockFor(accountID)
	mu.Lock()
	defer mu.Unlock()

	acc, err := database.GetGameAccount(db, accountID)
	if err != nil {
		return "", fmt.Errorf("could not load account: %w", err)
	}
	if staleToken != "" && acc.AccessToken != staleToken && !tokenNeedsRefresh(acc, time.Now()) {
		return acc.AccessToken, nil // already refreshed by someone else
	}

	hexID, err := utils.ConvertUUIDToString(accountID)
	if err != nil {
		return "", err
	}

	var lastErr, deviceErr error
	hadDeviceAuth := false
	credentialsRejected := true // flips to false if any failure could be transient

	// 1) Device auth: long-lived and not single-use, preferred when available.
	secrets, serr := database.GetGameAccountSecrets(db, hexID)
	switch {
	case serr == nil:
		hadDeviceAuth = true
		tokens, err := grantDeviceAuth(secrets)
		if err == nil {
			if err := saveTokens(db, accountID, tokens); err != nil {
				return "", fmt.Errorf("could not store refreshed tokens: %w", err)
			}
			return tokens.AccessToken, nil
		}
		lastErr, deviceErr = err, err
		if !isCredentialRejection(err) {
			credentialsRejected = false
		}
	case errors.Is(serr, sql.ErrNoRows):
		// no device auth stored: fall through to the refresh token
	default:
		lastErr = serr
		credentialsRejected = false
	}

	// 2) Refresh token.
	if acc.RefreshToken != "" {
		tokens, err := grantRefreshToken(acc.RefreshToken)
		if err == nil {
			if err := saveTokens(db, accountID, tokens); err != nil {
				return "", fmt.Errorf("could not store refreshed tokens: %w", err)
			}
			if !hadDeviceAuth {
				ensureDeviceAuth(db, acc, hexID, tokens.AccessToken)
			}
			return tokens.AccessToken, nil
		}
		lastErr = err
		if !isCredentialRejection(err) {
			credentialsRejected = false
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no credentials available to refresh the token")
	}
	if credentialsRejected {
		fmt.Printf("Account %s: Epic rejected the stored credentials (had device auth: %v, device auth error: %v, last error: %v) - it must be linked again\n", accountID, hadDeviceAuth, deviceErr, lastErr)
		return "", fmt.Errorf("%w (Epic: %v)", ErrNeedsRelink, lastErr)
	}
	fmt.Printf("Account %s: could not refresh token (will retry later): %v\n", accountID, lastErr)
	return "", fmt.Errorf("could not refresh the Epic token: %w", lastErr)
}

// ---------- authorized requests ----------

// doAuthorized sends the request with the given bearer token and returns the
// response with its body fully buffered (so it can be inspected and still read
// by the caller).
func doAuthorized(request *http.Request, token string) (*http.Response, []byte, error) {
	request.Header.Set("Authorization", "Bearer "+token)
	resp, err := epicHTTPClient.Do(request)
	if err != nil {
		return nil, nil, err
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	resp.Body.Close()
	if rerr != nil {
		return nil, nil, fmt.Errorf("could not read Epic response: %w", rerr)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, body, nil
}

// looksLikeExpiredToken reports whether a response means the access token was
// rejected (as opposed to a normal 403 such as "not allowed").
func looksLikeExpiredToken(status int, body []byte) bool {
	if status == http.StatusUnauthorized {
		return true
	}
	if status == http.StatusForbidden {
		code := strings.ToLower(parseEpicError(status, body).Code)
		return strings.Contains(code, "token") || strings.Contains(code, "authentication")
	}
	return false
}

// ExecuteOperationWithRefresh sends an authorized request on behalf of a game
// account. The token is refreshed proactively when it is about to expire and
// reactively (once) if Epic answers that it is invalid; the request body is
// rewound before the retry. source is only used for logging.
func ExecuteOperationWithRefresh(request *http.Request, db *sql.DB, accountID uuid.UUID, source string) (*http.Response, error) {
	account, err := database.GetGameAccount(db, accountID)
	if err != nil {
		return nil, fmt.Errorf("could not load game account: %w", err)
	}

	token := account.AccessToken
	if tokenNeedsRefresh(account, time.Now()) {
		fresh, rerr := refreshAccountToken(db, accountID, token)
		switch {
		case rerr == nil:
			token = fresh
		case errors.Is(rerr, ErrNeedsRelink):
			return nil, rerr
		default:
			fmt.Printf("[%s] proactive refresh failed for %s, trying the stored token: %v\n", source, accountID, rerr)
		}
	}

	resp, body, err := doAuthorized(request, token)
	if err != nil {
		return nil, fmt.Errorf("request to Epic failed: %w", err)
	}
	if !looksLikeExpiredToken(resp.StatusCode, body) {
		return resp, nil
	}

	fmt.Printf("[%s] token rejected for %s (HTTP %d), refreshing\n", source, accountID, resp.StatusCode)
	fresh, rerr := refreshAccountToken(db, accountID, token)
	if rerr != nil {
		return nil, rerr
	}
	rewindRequestBody(request)
	resp, _, err = doAuthorized(request, fresh)
	if err != nil {
		return nil, fmt.Errorf("retry after token refresh failed: %w", err)
	}
	return resp, nil
}

// rewindRequestBody resets request.Body so the request can be sent again after
// the first attempt drained it. This matters for requests that carry a body
// (the gift POST): without it, the retry after a token refresh would send an
// empty body and Epic would reject the gift. http.NewRequest populates GetBody
// for bytes/strings readers, which is what the callers use.
func rewindRequestBody(request *http.Request) {
	if request.Body == nil || request.GetBody == nil {
		return
	}
	if body, err := request.GetBody(); err == nil {
		request.Body = body
	}
}

// ensureDeviceAuth gives an account that only had a refresh token permanent
// device-auth credentials, so it no longer depends on a token that Epic can
// revoke (e.g. when the account signs in to the game). Best effort.
func ensureDeviceAuth(db *sql.DB, acc types.GameAccount, hexID, accessToken string) {
	secrets, err := createDeviceAuth(hexID, accessToken)
	if err != nil {
		fmt.Printf("Account %s: could not create device auth: %v\n", acc.ID, err)
		return
	}
	if err := database.UpsertGameAccountSecrets(db, types.GameAccountSecrets{
		Owner_user_id: acc.OwnerUserID,
		DeviceId:      secrets.DeviceId,
		AccountId:     hexID,
		Secret:        secrets.Secret,
	}); err != nil {
		fmt.Printf("Account %s: could not save device auth: %v\n", acc.ID, err)
		return
	}
	fmt.Printf("Account %s: device auth created, it no longer depends on the refresh token\n", acc.ID)
}
