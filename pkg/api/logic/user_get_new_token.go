package logic

import (
	"fmt"
	"time"

	"github.com/lazybark/go-testing-authservice/pkg/sec"
)

var (
	parseRefreshToken = sec.ParseRefreshToken
	formAuthToken     = sec.FormAuthToken
)

// TokenGet returns JWT token if refreshTokenString is correct.
func TokenGet(refreshTokenString, jwtSecret string) (*sec.Token, error) {
	valid, err := checkToken(refreshTokenString, jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("[TokenGet] %w", err)
	}
	if !valid {
		return nil, ErrBadRefreshToken
	}

	_, claims, err := parseRefreshToken(refreshTokenString, jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("[TokenGet] %w", err)
	}
	if !claims.IsRefreshToken {
		return nil, ErrNotRefreshToken
	}

	// For more security here can be session ID checker (from some fast session data cache).
	// But not today.

	authToken, err := formAuthToken(
		claims.AuthClaims.UserID,
		claims.AuthClaims.SessionID,
		claims.AuthClaims.Name,
		claims.AuthClaims.Email,
		jwtSecret,
		time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("[TokenGet] %w", err)
	}

	t := &sec.Token{
		AuthToken:    authToken,
		RefreshToken: refreshTokenString,
	}

	return t, nil
}
