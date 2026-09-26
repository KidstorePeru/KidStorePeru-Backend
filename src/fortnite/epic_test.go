package fortnite

import (
	"KidStoreBotBE/src/types"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLooksLikeExpiredToken(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   bool
	}{
		{401, ``, true},
		{403, `{"errorCode":"errors.com.epicgames.common.authentication.token_verification_failed"}`, true},
		{403, `{"errorCode":"errors.com.epicgames.friends.cannot_friend_due_to_target_settings"}`, false},
		{400, `{"errorCode":"x"}`, false},
		{200, `{}`, false},
	}
	for _, c := range cases {
		if got := looksLikeExpiredToken(c.status, []byte(c.body)); got != c.want {
			t.Errorf("status %d body %s: got %v want %v", c.status, c.body, got, c.want)
		}
	}
}

func TestTokenNeedsRefresh(t *testing.T) {
	now := time.Now()
	if !tokenNeedsRefresh(types.GameAccount{}, now) {
		t.Error("an account without token needs one")
	}
	if tokenNeedsRefresh(types.GameAccount{AccessToken: "t", AccessTokenExpDate: now.Add(time.Hour)}, now) {
		t.Error("a token valid for an hour must not be refreshed")
	}
	if !tokenNeedsRefresh(types.GameAccount{AccessToken: "t", AccessTokenExpDate: now.Add(time.Minute)}, now) {
		t.Error("a token expiring in 1 minute should be refreshed proactively")
	}
	if !tokenNeedsRefresh(types.GameAccount{AccessToken: "t", AccessTokenExpDate: now.Add(-time.Hour)}, now) {
		t.Error("an expired token must be refreshed")
	}
	if tokenNeedsRefresh(types.GameAccount{AccessToken: "t"}, now) {
		t.Error("unknown expiry: use the token and let a 401 trigger the refresh")
	}
}

func TestIsCredentialRejection(t *testing.T) {
	rej := &epicError{Status: 400, Code: "errors.com.epicgames.account.invalid_account_credentials"}
	if !isCredentialRejection(rej) || !isCredentialRejection(fmt.Errorf("wrapped: %w", rej)) {
		t.Error("400 with an error code is a credential rejection")
	}
	for _, e := range []error{
		&epicError{Status: 500, Code: "x"},
		&epicError{Status: 429, Code: "errors.com.epicgames.common.throttled"},
		&epicError{Status: 403},
		errors.New("dial tcp: i/o timeout"),
	} {
		if isCredentialRejection(e) {
			t.Errorf("%v must NOT be treated as a rejection (it would tell the operator to re-link a healthy account)", e)
		}
	}
}

func TestExplainGiftRejection(t *testing.T) {
	msg := explainGiftRejection(400, "errors.com.epicgames.modules.gamesubcatalog.purchase_not_allowed", "Purchase not allowed")
	if !strings.Contains(msg, "48 h") || !strings.Contains(msg, "ya tiene el objeto") {
		t.Errorf("purchase_not_allowed must list the possible causes, got %q", msg)
	}
	if !strings.Contains(explainGiftRejection(400, "errors.com.epicgames.modules.gamesubcatalog.price_mismatch", "x"), "precio") {
		t.Error("price mismatch should mention the price")
	}
	if got := explainGiftRejection(500, "", ""); !strings.Contains(got, "500") {
		t.Errorf("fallback = %q", got)
	}
}
