# auth

Small Go auth helpers for password hashing and JWT access/refresh token generation.

Module path:

```go
github.com/syosifov/auth
```

## Features

- Bcrypt password hashing and verification
- HS256 JWT access token generation
- HS256 JWT refresh token generation
- Token parsing and validation helpers
- Simple claim payload type: `auth.M`

## Install

```bash
go get github.com/syosifov/auth
```

## Requirements

- Go 1.25+
- A non-empty `APP_SECRET` environment variable for JWT signing

## Environment Variables

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `APP_SECRET` | Yes | none | Secret used to sign and validate JWTs |
| `EXP_TOKEN_MIN` | No | `60` | Access token expiration in minutes |
| `EXP_REF_TOKEN_MIN` | No | `60` | Refresh token expiration in minutes |

If `EXP_TOKEN_MIN` or `EXP_REF_TOKEN_MIN` cannot be parsed as integers, token generation returns an error.

## Usage

### Password Hashing

```go
package main

import (
    "fmt"

    "github.com/syosifov/auth/auth"
)

func main() {
    hash, err := auth.HashPassword("S3cureP@ss")
    if err != nil {
        panic(err)
    }

    fmt.Println(auth.CheckPasswordHash("S3cureP@ss", hash))
    // true
}
```

### Generate an Access Token

```go
package main

import (
    "fmt"
    "os"

    "github.com/syosifov/auth/auth"
)

func main() {
    os.Setenv(auth.APP_SECRET, "my-secret")
    os.Setenv(auth.EXP_TOKEN_MIN, "30")

    token, exp, err := auth.GenerateToken(auth.M{
        "id":   uint(42),
        "role": "admin",
    })
    if err != nil {
        panic(err)
    }

    fmt.Println(token)
    fmt.Println(exp)
}
```

Generated access tokens include these standard claims in addition to your custom payload:

- `exp`
- `expires_at`
- `iat`
- `issued_at`

### Generate a Refresh Token

```go
package main

import (
    "fmt"
    "os"

    "github.com/syosifov/auth/auth"
)

func main() {
    os.Setenv(auth.APP_SECRET, "my-secret")
    os.Setenv(auth.EXP_REF_TOKEN_MIN, "1440")

    refreshToken, err := auth.GenerateRefreshToken(42)
    if err != nil {
        panic(err)
    }

    fmt.Println(refreshToken)
}
```

Refresh tokens include:

- `id`
- `to_refresh=true`
- `exp`
- `expires_at`
- `iat`
- `issued_at`

### Generate Both Tokens Together

Use `GetTokens` when you want an access token, its expiration timestamp, and a refresh token in one call.

```go
package main

import (
    "fmt"
    "os"

    "github.com/syosifov/auth/auth"
)

func main() {
    os.Setenv(auth.APP_SECRET, "my-secret")

    accessToken, exp, refreshToken, err := auth.GetTokens(auth.M{
        "id":   uint(42),
        "name": "john",
    })
    if err != nil {
        panic(err)
    }

    fmt.Println(accessToken)
    fmt.Println(exp)
    fmt.Println(refreshToken)
}
```

Important: `GetTokens` expects the `id` claim to be of type `uint`. If `id` is a different type, it returns an error.

### Parse and Validate a Token

```go
package main

import (
    "fmt"
    "os"

    "github.com/syosifov/auth/auth"
)

func main() {
    os.Setenv(auth.APP_SECRET, "my-secret")

    token, _, err := auth.GenerateToken(auth.M{"id": uint(42)})
    if err != nil {
        panic(err)
    }

    claims, err := auth.ValidateToken(token)
    if err != nil {
        panic(err)
    }

    fmt.Println(claims["id"])
}
```

`ValidateToken` currently delegates to `ParseToken` and returns `jwt.MapClaims`.

## API

```go
type M map[string]any

func HashPassword(password string) (string, error)
func CheckPasswordHash(password, hash string) bool

func GenerateToken(m M) (string, int, error)
func GenerateRefreshToken(userId uint) (string, error)
func GetTokens(m M) (string, int, string, error)

func ParseToken(tokenString string) (jwt.MapClaims, error)
func ValidateToken(tokenString string) (jwt.MapClaims, error)
```

## Notes

- JWT signing uses `HS256`.
- Validation uses the same `APP_SECRET` that was used for signing.
- Parsing fails for malformed tokens or invalid signatures.
- Claim values parsed from JWTs may come back as `float64` for numeric fields, which is standard for `jwt.MapClaims`.
