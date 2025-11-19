package jwtutil

import (
	"errors"
	"time"

	"auth_demo/pkg/models"

	"github.com/golang-jwt/jwt/v5"
)

// Claims wraps the standard registered claims with user specific data.
type Claims struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	jwt.RegisteredClaims
}

// Manager handles signing and validating JWT tokens.
type Manager struct {
	secret []byte
	issuer string
	expiry time.Duration
}

// NewManager constructs a new JWT manager.
func NewManager(secret, issuer string, expiry time.Duration) *Manager {
	return &Manager{
		secret: []byte(secret),
		issuer: issuer,
		expiry: expiry,
	}
}

// Generate creates a signed JWT for the provided user.
func (m *Manager) Generate(user models.User) (string, time.Time, error) {
	expiresAt := time.Now().Add(m.expiry)
	claims := Claims{
		Email: user.Email,
		Name:  user.FullName,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID.String(),
			Issuer:    m.issuer,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

// Verify parses and validates an incoming JWT returning the claims when valid.
func (m *Manager) Verify(tokenString string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}
