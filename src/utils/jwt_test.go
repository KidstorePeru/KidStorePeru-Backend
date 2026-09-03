package utils

import (
	"testing"

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
