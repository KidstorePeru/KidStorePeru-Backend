package utils

import "testing"

func TestHashAndCheckPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "correct horse battery staple" {
		t.Fatal("password was not hashed")
	}
	if !CheckPassword(hash, "correct horse battery staple") {
		t.Error("CheckPassword rejected the correct password")
	}
	if CheckPassword(hash, "wrong") {
		t.Error("CheckPassword accepted a wrong password")
	}
}

func TestIsHashed(t *testing.T) {
	hash, _ := HashPassword("x")
	cases := map[string]bool{
		hash:             true,
		"$2b$10$abcdefg": true,
		"$2y$10$abcdefg": true,
		"plaintext":      false,
		"":               false,
		"md5:deadbeef":   false,
	}
	for in, want := range cases {
		if got := IsHashed(in); got != want {
			t.Errorf("IsHashed(%q) = %v, want %v", in, got, want)
		}
	}
}
