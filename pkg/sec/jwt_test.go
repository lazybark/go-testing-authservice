package sec

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lazybark/go-testing-authservice/pkg/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	t.Parallel()

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
		// Just harcoding
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test.test.com",
			Subject:   "auth server",
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
}

func TestCheckToken(t *testing.T) {
	t.Parallel()

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
}

func TestParseRefreshToken(t *testing.T) {
	t.Parallel()

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
}

func TestParseToken(t *testing.T) {
	t.Parallel()

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
