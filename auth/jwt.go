package auth

import (
	"cmp"
	"fmt"
	"maps"
	"os"
	"reflect"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateToken(m M) (string, int, error) {
	secretKey := os.Getenv(APP_SECRET)
	sMin := cmp.Or(os.Getenv(EXP_TOKEN_MIN), "60")
	expMin, err := strconv.Atoi(sMin)
	if err != nil {
		return "", 0, err
	}
	t := time.Now().Add(time.Minute * time.Duration(expMin))
	claims := jwt.MapClaims{
		"exp":        t.Unix(), // Expiration time in seconds since Unix epoch
		"expires_at": t,
		"iat":        time.Now().Unix(),
		"issued_at":  time.Now(),
	}

	maps.Copy(claims, m)
	fmt.Println(claims)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	s, err := token.SignedString([]byte(secretKey))
	return s, int(t.Unix()), err
}

func GenerateRefreshToken(userId uint) (string, error) {
	secretKey := os.Getenv(APP_SECRET)
	sMin := cmp.Or(os.Getenv(EXP_REF_TOKEN_MIN), "60")
	expMin, err := strconv.Atoi(sMin)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		TO_REFRESH:   true,
		"id":         userId,
		"exp":        time.Now().Add(time.Minute * time.Duration(expMin)).Unix(),
		"expires_at": time.Now().Add(time.Minute * time.Duration(expMin)),
		"iat":        time.Now().Unix(),
		"issued_at":  time.Now(),
	})

	return token.SignedString([]byte(secretKey))
}

func ValidateToken(tokenString string) (jwt.MapClaims, error) {
	claims, err := ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func ParseToken(tokenString string) (jwt.MapClaims, error) {
	secretKey := os.Getenv(APP_SECRET)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}

	return claims, nil
}

func GetTokens(m M) (string, int /*seconds */, string, error) {
	accessToken, exp, err := GenerateToken(m)
	if err != nil {
		return "", exp, "", err
	}
	id, ok := m["id"].(uint)
	fmt.Println(reflect.TypeOf(id))
	if !ok {
		return "", 0, "", fmt.Errorf("id is not of type int64")
	}
	refreshToken, err := GenerateRefreshToken(id)
	if err != nil {
		return "", exp, "", err
	}
	return accessToken, exp, refreshToken, nil
}
