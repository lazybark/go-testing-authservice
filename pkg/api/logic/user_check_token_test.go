package logic

import (
	"errors"
	"fmt"
	"testing"

	"github.com/lazybark/go-testing-authservice/pkg/ds"
	"github.com/lazybark/go-testing-authservice/pkg/sec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenCheck(t *testing.T) {
	udata := ds.GetRandomUserData()
	jwtSecret := "jwtSecret"

	token, err := sec.FormJWT(udata.UserID, "session_id", udata.FirstName, udata.Email, jwtSecret)
	require.NoError(t, err)

	ok, err := TokenCheck(token.AuthToken, jwtSecret)
	require.NoError(t, err)
	assert.Equal(t, "true", ok)

	ok, err = TokenCheck(token.RefreshToken, jwtSecret)
	require.NoError(t, err)
	assert.Equal(t, "true", ok)

	ok, err = TokenCheck(token.AuthToken, jwtSecret+"a")
	require.ErrorIs(t, err, sec.ErrBadToken)
	require.ErrorAs(t, err, new(sec.SecurityError))
	assert.Equal(t, "false", ok)

	ok, err = TokenCheck(token.RefreshToken, "bb"+jwtSecret)
	require.ErrorIs(t, err, sec.ErrBadToken)
	assert.Equal(t, "false", ok)

	// Must NOT run in parallel
	// checkToken => error
	t.Run("checkToken => error", func(t *testing.T) {
		orig := checkToken
		t.Cleanup(func() {
			checkToken = orig
		})

		checkToken = func(token string, jwtSecret string) (bool, error) {
			return false, fmt.Errorf("not SecurityError")
		}

		ok, err = TokenCheck(token.RefreshToken, "bb"+jwtSecret)
		assert.Equal(t, "false", ok)
		require.False(t, errors.As(err, new(sec.SecurityError)))
	})
}
