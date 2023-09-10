package sec

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lazybark/go-testing-authservice/pkg/ds"
	"github.com/lazybark/go-testing-authservice/pkg/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*
There will be no parallel tests, because we're switching function values on package level
and it can kill other tests.
*/

var (
	testSecret = "testSecret"
)

func assertTokenEqual(
	t *testing.T,
	uid, sid, name, email string,
	now time.Time,
	claims *AuthClaims,
) {
	assert.Equal(t, uid, claims.UserID)
	assert.Equal(t, sid, claims.SessionID)
	assert.Equal(t, name, claims.Name)
	assert.Equal(t, email, claims.Email)

	// We can's simply check time because jwt.NumericDate loses monotonic time during conversion.
	assert.WithinRange(t, claims.IssuedAt.Time, now.Add(time.Minute*-1), now.Add(time.Minute))
	assert.WithinRange(t, claims.ExpiresAt.Time, now.Add(time.Minute*-1), now.Add(time.Hour*24*30))
}

func TestStringifyToken(t *testing.T) {
	uid := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	sid := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	name := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	email := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))

	now := time.Now()
	authClaims := &AuthClaims{
		UserID:    uid,
		SessionID: sid,
		Email:     email,
		Name:      name,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    AuthServerName,
			Subject:   AuthServerRole,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute * 120)),
		},
	}

	authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, authClaims)
	authTokenString, err := StringifyToken(authToken, testSecret)
	require.NoError(t, err)

	ok, err := CheckToken(authTokenString, testSecret)
	require.NoError(t, err)
	assert.True(t, ok)

	fn := func() {
		_, _ = StringifyToken(nil, testSecret)
	}
	require.Panics(t, fn)

	t.Run("signedString => error", func(t *testing.T) {
		orig := signedString
		t.Cleanup(func() {
			signedString = orig
		})

		signedString = func(t *jwt.Token, key interface{}) (string, error) {
			return "", fmt.Errorf("some_error")
		}
		token, err := StringifyToken(nil, testSecret)
		require.Error(t, err)
		assert.Empty(t, token)
	})
}

func TestCheckToken(t *testing.T) {
	uid := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	sid := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	name := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	email := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))

	token1, err := FormAuthToken(
		uid,
		sid,
		name,
		email,
		testSecret,
		time.Now(),
	)
	require.NoError(t, err)
	token2, err := FormAuthToken(
		uid,
		sid,
		name,
		email,
		"otherTestSecret",
		time.Now(),
	)
	require.NoError(t, err)

	ok, err := CheckToken(token1, testSecret)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = CheckToken(token1, "yetANotherTestSecret")
	require.ErrorIs(t, err, ErrBadToken)
	assert.False(t, ok)

	ok, err = CheckToken(token2, testSecret)
	require.ErrorIs(t, err, ErrBadToken)
	assert.False(t, ok)

	t.Run("parseWithClaims => error", func(t *testing.T) {
		orig := parseWithClaims
		t.Cleanup(func() {
			parseWithClaims = orig
		})

		parseWithClaims = func(
			tokenString string,
			claims jwt.Claims,
			keyFunc jwt.Keyfunc,
			options ...jwt.ParserOption,
		) (*jwt.Token, error) {
			return &jwt.Token{Valid: false}, fmt.Errorf("some_error")
		}

		ok, err = CheckToken(token2, testSecret)
		require.Error(t, err)
		assert.False(t, ok)

		parseWithClaims = func(
			tokenString string,
			claims jwt.Claims,
			keyFunc jwt.Keyfunc,
			options ...jwt.ParserOption,
		) (*jwt.Token, error) {
			return &jwt.Token{Valid: false}, nil
		}

		ok, err = CheckToken(token2, testSecret)
		require.Nil(t, err)
		assert.False(t, ok)

	})
}

func TestParseRefreshToken(t *testing.T) {
	uid := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	sid := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	name := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	email := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))

	now := time.Now()
	token1, err := FormRefreshToken(
		uid,
		sid,
		name,
		email,
		testSecret,
		now,
	)
	require.NoError(t, err)

	_, claims, err := ParseRefreshToken(token1, testSecret)
	require.NoError(t, err)
	assert.True(t, claims.IsRefreshToken)

	assertTokenEqual(t, uid, sid, name, email, now, &claims.AuthClaims)

	t.Run("parseWithClaims => error", func(t *testing.T) {
		orig := parseWithClaims
		t.Cleanup(func() {
			parseWithClaims = orig
		})

		parseWithClaims = func(
			tokenString string,
			claims jwt.Claims,
			keyFunc jwt.Keyfunc,
			options ...jwt.ParserOption,
		) (*jwt.Token, error) {
			return &jwt.Token{Valid: false}, fmt.Errorf("some_error")
		}

		_, _, err = ParseRefreshToken(token1, testSecret)
		require.Error(t, err)
	})
}

func TestParseToken(t *testing.T) {
	uid := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	sid := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	name := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	email := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))

	now := time.Now()
	token1, err := FormAuthToken(
		uid,
		sid,
		name,
		email,
		testSecret,
		now,
	)
	require.NoError(t, err)

	_, claims, err := ParseToken(token1, testSecret)
	require.NoError(t, err)

	assertTokenEqual(t, uid, sid, name, email, now, claims)
}

func TestFormJWT(t *testing.T) {
	udata := ds.GetRandomUserData(t)
	jwtSecret := "jwtSecret"

	token, err := FormJWT(udata.UserID, "session_id", udata.FirstName, udata.Email, jwtSecret)
	require.NoError(t, err)

	ok, err := CheckToken(token.AuthToken, jwtSecret)
	require.NoError(t, err)
	assert.Equal(t, true, ok)

	ok, err = CheckToken(token.RefreshToken, jwtSecret)
	require.NoError(t, err)
	assert.Equal(t, true, ok)

	// Must NOT run in parallel
	t.Run("newWithClaims => nil", func(t *testing.T) {
		orig := newWithClaims
		t.Cleanup(func() {
			newWithClaims = orig
		})

		newWithClaims = func(method jwt.SigningMethod, claims jwt.Claims) *jwt.Token {
			return nil
		}

		require.Panics(t, func() {
			_, _ = FormJWT(udata.UserID, "session_id", udata.FirstName, udata.Email, jwtSecret)
		})

	})

	// Must NOT run in parallel
	t.Run("stringifyToken => error", func(t *testing.T) {
		orig := stringifyToken
		t.Cleanup(func() {
			stringifyToken = orig
		})

		stringifyToken = func(t *jwt.Token, jwtSecret string) (string, error) {
			return "", fmt.Errorf("some_error")
		}

		authTokenString, err := FormAuthToken(udata.UserID, "session_id", udata.FirstName, udata.Email, jwtSecret, time.Now())
		require.Error(t, err)
		assert.Empty(t, authTokenString)

		refrTokenString, err := FormRefreshToken(udata.UserID, "session_id", udata.FirstName, udata.Email, jwtSecret, time.Now())
		require.Error(t, err)
		assert.Empty(t, refrTokenString)
	})

	// Must NOT run in parallel
	t.Run("formAuthToken => error", func(t *testing.T) {
		orig := formAuthToken
		t.Cleanup(func() {
			formAuthToken = orig
		})

		formAuthToken = func(uid string, sid string, uname string, email string, jwtSecret string, t time.Time) (string, error) {
			return "", fmt.Errorf("some_error")
		}
		token, err := FormJWT(udata.UserID, "session_id", udata.FirstName, udata.Email, jwtSecret)
		require.Error(t, err)
		assert.Nil(t, token)

		formAuthToken = func(uid string, sid string, uname string, email string, jwtSecret string, t time.Time) (string, error) {
			return "", jwt.ErrSignatureInvalid
		}
		token, err = FormJWT(udata.UserID, "session_id", udata.FirstName, udata.Email, jwtSecret)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBadToken)
		assert.Nil(t, token)

		formAuthToken = func(uid string, sid string, uname string, email string, jwtSecret string, t time.Time) (string, error) {
			return "", ErrBadToken
		}
		token, err = FormJWT(udata.UserID, "session_id", udata.FirstName, udata.Email, jwtSecret)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBadToken)
		assert.Nil(t, token)
	})

	// Must NOT run in parallel
	t.Run("formRefreshToken => error", func(t *testing.T) {
		orig := formRefreshToken
		t.Cleanup(func() {
			formRefreshToken = orig
		})

		formRefreshToken = func(uid string, sid string, uname string, email string, jwtSecret string, t time.Time) (string, error) {
			return "", fmt.Errorf("some_error")
		}
		token, err := FormJWT(udata.UserID, "session_id", udata.FirstName, udata.Email, jwtSecret)
		require.Error(t, err)
		assert.Nil(t, token)

		formRefreshToken = func(uid string, sid string, uname string, email string, jwtSecret string, t time.Time) (string, error) {
			return "", jwt.ErrSignatureInvalid
		}
		token, err = FormJWT(udata.UserID, "session_id", udata.FirstName, udata.Email, jwtSecret)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBadToken)
		assert.Nil(t, token)

		formRefreshToken = func(uid string, sid string, uname string, email string, jwtSecret string, t time.Time) (string, error) {
			return "", ErrBadToken
		}
		token, err = FormJWT(udata.UserID, "session_id", udata.FirstName, udata.Email, jwtSecret)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBadToken)
		assert.Nil(t, token)
	})
}
