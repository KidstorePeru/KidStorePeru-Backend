package utils

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestTokenRoundTrip(t *testing.T) {
	secretKey = []byte("test-secret-key")

	userTok, err := CreateToken("alice", "id-1")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if err := VerifyToken(userTok); err != nil {
		t.Errorf("VerifyToken(user): %v", err)
	}
	if err := VerifyAdminToken(userTok); err == nil {
		t.Error("VerifyAdminToken accepted a non-admin token")
	}

	adminTok, err := CreateAdminToken("root", "id-0")
	if err != nil {
		t.Fatalf("CreateAdminToken: %v", err)
	}
	if err := VerifyToken(adminTok); err != nil {
		t.Errorf("VerifyToken(admin): %v", err)
	}
	if err := VerifyAdminToken(adminTok); err != nil {
		t.Errorf("VerifyAdminToken(admin): %v", err)
	}
}

func TestVerifyTokenRejectsWrongKey(t *testing.T) {
	secretKey = []byte("key-a")
	tok, _ := CreateToken("bob", "id-2")
	secretKey = []byte("key-b")
	if err := VerifyToken(tok); err == nil {
		t.Error("VerifyToken accepted a token signed with a different key")
	}
}

func TestConvertUUIDToString(t *testing.T) {
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	got, err := ConvertUUIDToString(id)
	if err != nil {
		t.Fatalf("ConvertUUIDToString: %v", err)
	}
	if got != "11111111222233334444555555555555" {
		t.Errorf("got %q", got)
	}
	if _, err := ConvertUUIDToString(uuid.Nil); err == nil {
		t.Error("expected error for nil UUID")
	}
}

func TestVerifyTokenRejectsForgedOrExpiredTokens(t *testing.T) {
	secretKey = []byte("test-secret-key")
	future := time.Now().Add(time.Hour).Unix()

	sign := func(m jwt.SigningMethod, claims jwt.MapClaims, key interface{}) string {
		s, err := jwt.NewWithClaims(m, claims).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	good := sign(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": "u", "exp": future}, secretKey)
	if err := VerifyToken(good); err != nil {
		t.Fatalf("a normal token must verify: %v", err)
	}

	for name, tok := range map[string]string{
		"another HMAC algorithm": sign(jwt.SigningMethodHS512, jwt.MapClaims{"user_id": "u", "exp": future}, secretKey),
		"alg none":               sign(jwt.SigningMethodNone, jwt.MapClaims{"user_id": "u", "exp": future, "admin": true}, jwt.UnsafeAllowNoneSignatureType),
		"no expiry":              sign(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": "u"}, secretKey),
		"expired":                sign(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": "u", "exp": time.Now().Add(-time.Hour).Unix()}, secretKey),
		"garbage":                "not.a.jwt",
	} {
		if VerifyToken(tok) == nil {
			t.Errorf("%s: token was accepted", name)
		}
		if VerifyAdminToken(tok) == nil {
			t.Errorf("%s: token was accepted as admin", name)
		}
	}
}
