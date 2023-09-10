package sec

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	AuthServerName = "test.test.com"
	AuthServerRole = "auth server"
)

var (
	parseWithClaims  = jwt.ParseWithClaims
	signedString     = (*jwt.Token).SignedString
	newWithClaims    = jwt.NewWithClaims
	stringifyToken   = StringifyToken
	formAuthToken    = FormAuthToken
	formRefreshToken = FormRefreshToken
)

// AuthClaims struct has all info about user session.
type AuthClaims struct {
	UserID    string
	SessionID string
	Email     string
	Name      string
	jwt.RegisteredClaims
}

// RefreshClaims struct is embedding AuthClaims and uses IsRefreshToken field
// to determine token as refreshing.
type RefreshClaims struct {
	AuthClaims
	IsRefreshToken bool
}

// Token holds AuthToken & RefreshToken.
type Token struct {
	AuthToken    string `json:"auth_token"`
	RefreshToken string `json:"refresh_token"`
}

// StringifyToken returns hashed string out of t.
func StringifyToken(t *jwt.Token, jwtSecret string) (string, error) {
	tokenString, err := signedString(t, []byte(jwtSecret))
	if err != nil {
		return "", fmt.Errorf("[StringifyToken] %w", err)
	}

	return tokenString, nil
}

// FormAuthToken returns new AuthToken in string form.
func FormAuthToken(uid, sid, uname, email, jwtSecret string, t time.Time) (string, error) {
	authClaims := &AuthClaims{
		UserID:    uid,
		SessionID: sid,
		Email:     email,
		Name:      uname,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    AuthServerName,
			Subject:   AuthServerRole,
			IssuedAt:  jwt.NewNumericDate(t),
			ExpiresAt: jwt.NewNumericDate(t.Add(time.Minute * 120)),
		},
	}

	authToken := newWithClaims(jwt.SigningMethodHS256, authClaims)
	authTokenString, err := stringifyToken(authToken, jwtSecret)
	if err != nil {
		return "", fmt.Errorf("[FormAuthToken] %w", err)
	}

	return authTokenString, nil
}

// FormRefreshToken returns new RefreshToken in string form.
func FormRefreshToken(uid, sid, uname, email, jwtSecret string, t time.Time) (string, error) {
	refreshClaims := &RefreshClaims{
		IsRefreshToken: true,
		AuthClaims: AuthClaims{
			UserID:    uid,
			SessionID: sid,
			Email:     email,
			Name:      uname,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    AuthServerName,
				Subject:   AuthServerRole,
				IssuedAt:  jwt.NewNumericDate(t),
				ExpiresAt: jwt.NewNumericDate(t.Add(time.Hour * 24 * 30)),
			},
		},
	}
	refreshToken := newWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := stringifyToken(refreshToken, jwtSecret)
	if err != nil {
		return "", fmt.Errorf("[FormRefreshToken] %w", err)
	}

	return refreshTokenString, nil
}

// FormJWT creates full JWT token with auth & refresh part. SecurityError is returned if siganture invalid.
func FormJWT(uid, sid, uname, email, jwtSecret string) (*Token, error) {
	t := time.Now()

	authTokenString, err := formAuthToken(uid, sid, uname, email, jwtSecret, t)
	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) || errors.Is(err, ErrBadToken) {
			return nil, ErrBadToken
		}

		return nil, fmt.Errorf("[FormJWT]%w", err)
	}

	refreshTokenString, err := formRefreshToken(uid, sid, uname, email, jwtSecret, t)
	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) || errors.Is(err, ErrBadToken) {
			return nil, ErrBadToken
		}

		return nil, fmt.Errorf("[FormJWT]%w", err)
	}

	token := &Token{
		AuthToken:    authTokenString,
		RefreshToken: refreshTokenString,
	}

	return token, nil
}

// ParseToken returns token, claims or error. SecurityError is returned if siganture invalid.
func ParseToken(token, jwtSecret string) (*jwt.Token, *AuthClaims, error) {
	claims := &AuthClaims{}

	tkn, err := parseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil {
		return nil, nil, ErrBadToken
	}

	return tkn, claims, err
}

// ParseRefreshToken returns token and RefreshClaims. SecurityError is returned if siganture invalid.
func ParseRefreshToken(token, jwtSecret string) (*jwt.Token, *RefreshClaims, error) {
	claims := &RefreshClaims{}

	tkn, err := parseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil {
		return nil, nil, ErrBadToken
	}

	return tkn, claims, err
}

// CheckToken returns true if token is valid or error. SecurityError is returned if
// token is broken / siganture invalid.
func CheckToken(token, jwtSecret string) (bool, error) {
	tkn, _, err := ParseToken(token, jwtSecret)
	if err != nil {
		return false, ErrBadToken
	}
	if !tkn.Valid {
		return false, nil
	}

	return true, nil
}
