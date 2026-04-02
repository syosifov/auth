package auth

import "testing"

func TestHashPasswordAndCheckPasswordHash(t *testing.T) {
	password := "S3cureP@ss"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}

	if hash == password {
		t.Fatalf("expected hashed value to differ from plain password")
	}

	if !CheckPasswordHash(password, hash) {
		t.Fatalf("expected password to match hash")
	}

	if CheckPasswordHash("wrong-password", hash) {
		t.Fatalf("expected wrong password to not match hash")
	}
}
