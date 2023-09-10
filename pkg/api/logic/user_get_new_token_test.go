package logic

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lazybark/go-testing-authservice/pkg/ds"
	"github.com/lazybark/go-testing-authservice/pkg/sec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenGet(t *testing.T) {
	udata := ds.GetRandomUserData()
	jwtSecret := "jwtSecret"

	token, err := sec.FormJWT(udata.UserID, "session_id", udata.FirstName, udata.Email, jwtSecret)
	require.NoError(t, err)

	tokenNew, err := TokenGet(token.RefreshToken, jwtSecret)
	require.NoError(t, err)

	ok, err := TokenCheck(tokenNew.AuthToken, jwtSecret)
	require.NoError(t, err)
	assert.Equal(t, "true", ok)

	ok, err = TokenCheck(tokenNew.RefreshToken, jwtSecret)
	require.NoError(t, err)
	assert.Equal(t, "true", ok)

	// Only refresh token is accepted
	tokenNew, err = TokenGet(token.AuthToken, jwtSecret)
	require.ErrorIs(t, err, ErrNotRefreshToken)
	assert.Nil(t, tokenNew)

	// Must NOT run in parallel
	// checkToken  => error
	t.Run("checkToken  => error", func(t *testing.T) {
		orig := checkToken
		t.Cleanup(func() {
			checkToken = orig
		})

		checkToken = func(token string, jwtSecret string) (bool, error) {
			return false, fmt.Errorf("not SecurityError")
		}

		tokenNew, err = TokenGet(token.AuthToken, jwtSecret)
		require.Error(t, err)
		assert.Nil(t, tokenNew)

		checkToken = func(token string, jwtSecret string) (bool, error) {
			return false, nil
		}

		tokenNew, err = TokenGet(token.AuthToken, jwtSecret)
		require.ErrorIs(t, err, ErrBadRefreshToken)
		assert.Nil(t, tokenNew)
	})

	// Must NOT run in parallel
	// parseRefreshToken => error
	t.Run("parseRefreshToken => error", func(t *testing.T) {
		orig := parseRefreshToken
		t.Cleanup(func() {
			parseRefreshToken = orig
		})

		parseRefreshToken = func(token string, jwtSecret string) (*jwt.Token, *sec.RefreshClaims, error) {
			return nil, nil, fmt.Errorf("some_error")
		}

		tokenNew, err = TokenGet(token.AuthToken, jwtSecret)
		require.Error(t, err)
		assert.Nil(t, tokenNew)
	})

	// Must NOT run in parallel
	// formAuthToken => error
	t.Run("formAuthToken => error", func(t *testing.T) {
		orig := formAuthToken
		t.Cleanup(func() {
			formAuthToken = orig
		})

		formAuthToken = func(uid string, sid string, uname string, email string, jwtSecret string, t time.Time) (string, error) {
			return "", fmt.Errorf("some_error")
		}

		tokenNew, err := TokenGet(token.AuthToken, jwtSecret)
		require.ErrorAs(t, err, new(LogicError))
		require.Error(t, err)
		assert.Nil(t, tokenNew)
	})
}
