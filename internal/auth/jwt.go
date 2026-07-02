package auth

import (
	"errors"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the JWT payload. UserID identifies the authenticated user.
type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
    UserID int `json:"user_id"`
    Type string `json:"type"`
    jwt.RegisteredClaims
}
// Manager issues and validates HS256 JWTs signed with a shared secret.
type Manager struct {
	secret []byte
	accessTTL    time.Duration
	refreshTTL   time.Duration

}

// NewManager builds a token manager. ttl is the token lifetime.
func NewManager(secret string, accessTTL time.Duration, refreshTTL time.Duration) *Manager {
	return &Manager{secret: []byte(secret), accessTTL: accessTTL, refreshTTL: refreshTTL}
}

// Generate returns a signed JWT for the given user ID.
func (m *Manager) Generate(userID int) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.Itoa(userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}



func (m *Manager) GenerateRefresh(userID int) (string, error) {
	now := time.Now()
	claims := RefreshClaims{
		UserID: userID,
		Type: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.Itoa(userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.refreshTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}
// Parse validates a token string and returns its claims. It rejects tokens
// signed with an unexpected algorithm (alg-confusion protection), as well as
// expired or otherwise invalid tokens.
func (m *Manager) Parse(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

func (m *Manager) ParseRefresh(tokenStr string) (*RefreshClaims, error) {
	claims := &RefreshClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}
	if claims.Type != "refresh" {
		return nil, errors.New("not a refresh token")
	}
	return claims, nil
}
