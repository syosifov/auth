package auth

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateTokenAndValidateToken(t *testing.T) {
	t.Setenv(APP_SECRET, "test-secret")
	t.Setenv(EXP_TOKEN_MIN, "2")

	nowBefore := time.Now().Unix()
	token, exp, err := GenerateToken(M{"id": uint(42), "role": "admin"})
	if err != nil {
		t.Fatalf("GenerateToken returned error: %v", err)
	}
	if token == "" {
		t.Fatalf("expected non-empty token")
	}

	claims, err := ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}

	if claims["role"] != "admin" {
		t.Fatalf("expected role claim to be admin, got %v", claims["role"])
	}

	tokenExp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("expected exp claim to be numeric, got %T", claims["exp"])
	}

	if int64(tokenExp) != int64(exp) {
		t.Fatalf("expected returned exp (%d) to match claim exp (%d)", exp, int64(tokenExp))
	}

	if int64(tokenExp) <= nowBefore {
		t.Fatalf("expected exp to be in the future")
	}
}

func TestGenerateTokenInvalidExpEnv(t *testing.T) {
	t.Setenv(APP_SECRET, "test-secret")
	t.Setenv(EXP_TOKEN_MIN, "invalid")

	_, _, err := GenerateToken(M{"id": uint(1)})
	if err == nil {
		t.Fatalf("expected error for invalid EXP_TOKEN_MIN")
	}
}

func TestParseTokenInvalidSignature(t *testing.T) {
	t.Setenv(APP_SECRET, "secret-a")
	token, _, err := GenerateToken(M{"id": uint(1)})
	if err != nil {
		t.Fatalf("GenerateToken returned error: %v", err)
	}

	t.Setenv(APP_SECRET, "secret-b")
	_, err = ParseToken(token)
	if err == nil {
		t.Fatalf("expected ParseToken to fail for invalid signature")
	}
}

func TestParseTokenMalformed(t *testing.T) {
	t.Setenv(APP_SECRET, "test-secret")
	_, err := ParseToken("not-a-jwt")
	if err == nil {
		t.Fatalf("expected ParseToken to fail for malformed token")
	}
}

func TestGenerateRefreshTokenAndParse(t *testing.T) {
	t.Setenv(APP_SECRET, "test-secret")
	t.Setenv(EXP_REF_TOKEN_MIN, "3")

	token, err := GenerateRefreshToken(7)
	if err != nil {
		t.Fatalf("GenerateRefreshToken returned error: %v", err)
	}

	claims, err := ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken returned error: %v", err)
	}

	refresh, ok := claims[TO_REFRESH].(bool)
	if !ok || !refresh {
		t.Fatalf("expected to_refresh claim to be true, got %v", claims[TO_REFRESH])
	}

	id, ok := claims["id"].(float64)
	if !ok || int(id) != 7 {
		t.Fatalf("expected id claim to be 7, got %v", claims["id"])
	}
}

func TestGenerateRefreshTokenInvalidExpEnv(t *testing.T) {
	t.Setenv(APP_SECRET, "test-secret")
	t.Setenv(EXP_REF_TOKEN_MIN, "invalid")

	_, err := GenerateRefreshToken(1)
	if err == nil {
		t.Fatalf("expected error for invalid EXP_REF_TOKEN_MIN")
	}
}

func TestGetTokensSuccess(t *testing.T) {
	t.Setenv(APP_SECRET, "test-secret")
	t.Setenv(EXP_TOKEN_MIN, "2")
	t.Setenv(EXP_REF_TOKEN_MIN, "3")

	access, exp, refresh, err := GetTokens(M{"id": uint(55), "name": "john"})
	if err != nil {
		t.Fatalf("GetTokens returned error: %v", err)
	}

	if access == "" || refresh == "" {
		t.Fatalf("expected non-empty access and refresh tokens")
	}

	if exp <= int(time.Now().Unix()) {
		t.Fatalf("expected access token expiration to be in the future")
	}
}

func TestGetTokensFailsWhenIDIsNotUint(t *testing.T) {
	t.Setenv(APP_SECRET, "test-secret")

	_, _, _, err := GetTokens(M{"id": int64(1)})
	if err == nil {
		t.Fatalf("expected GetTokens to fail when id is not uint")
	}
	if !strings.Contains(err.Error(), "id is not of type") {
		t.Fatalf("expected type error, got: %v", err)
	}
}
