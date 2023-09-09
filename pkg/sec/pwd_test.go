package sec

import (
	"errors"
	"fmt"
	"testing"

	"github.com/lazybark/go-testing-authservice/pkg/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	unicodePwd := helpers.GenerateRandomStringFromSet(15, helpers.DigitsAndEnglish)
	nonUnicodePwd := helpers.GenerateRandomStringFromSet(15, helpers.DigitsAndGerman)
	longUnicodePwd := helpers.GenerateRandomStringFromSet(100, helpers.DigitsAndEnglish)
	longNonUnicodePwd := helpers.GenerateRandomStringFromSet(100, helpers.DigitsAndGerman)

	tests := map[string]struct {
		pwd         string
		cost        int
		errRequired error
	}{
		"unicode pass, normal length":                 {pwd: unicodePwd, cost: bcrypt.DefaultCost},
		"non-unicode pass, normal length":             {pwd: nonUnicodePwd, cost: bcrypt.DefaultCost},
		"long unicode pass":                           {pwd: longUnicodePwd, cost: bcrypt.DefaultCost, errRequired: bcrypt.ErrPasswordTooLong},
		"long non-unicode pass":                       {pwd: longNonUnicodePwd, cost: bcrypt.DefaultCost, errRequired: bcrypt.ErrPasswordTooLong},
		"negative cost, unicode pass, normal length":  {pwd: unicodePwd, cost: -5},
		"zero cost, unicode pass, normal length":      {pwd: unicodePwd, cost: 0},
		"too small cost, unicode pass, normal length": {pwd: unicodePwd, cost: bcrypt.MinCost - 1},
		"empty password":                              {pwd: "", cost: bcrypt.DefaultCost},
		// Not testing with clear MaxCost here: takes too long and should be used only in big projects
		"too big cost, unicode pass, normal length": {pwd: unicodePwd, cost: bcrypt.MaxCost + 5},
	}

	for name, tCase := range tests {
		hash, err := HashPasswordString(tCase.pwd, tCase.cost)
		if tCase.errRequired != nil {
			require.Error(t, err)
			assert.True(t, errors.Is(err, tCase.errRequired), name)
		} else {
			require.NoError(t, err, fmt.Errorf("[%s] hashing error", name))

			assert.Greater(t, len(hash), 0, name)
			assert.NotEqual(t, len(hash), len(tCase.pwd), name)
			assert.NotEqual(t, hash, tCase.pwd, name)
		}

	}
}

func TestComparePasswords(t *testing.T) {
	unicodePwd := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	nonUnicodePwd := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndGerman))

	tests := map[string]struct {
		pwd  string
		cost int
	}{
		"unicode pass, normal length":                 {pwd: unicodePwd, cost: bcrypt.DefaultCost},
		"non-unicode pass, normal length":             {pwd: nonUnicodePwd, cost: bcrypt.DefaultCost},
		"negative cost, unicode pass, normal length":  {pwd: unicodePwd, cost: -5},
		"zero cost, unicode pass, normal length":      {pwd: unicodePwd, cost: 0},
		"too small cost, unicode pass, normal length": {pwd: unicodePwd, cost: bcrypt.MinCost - 1},
		"empty password":                              {pwd: "", cost: bcrypt.DefaultCost},
		// Not testing with MaxCost here: takes too long and should be used only in big projects
	}

	for name, tCase := range tests {
		hash, err := HashPasswordString(tCase.pwd, tCase.cost)
		require.NoError(t, err, fmt.Errorf("[%s] hashing error", name))

		yes, err := ComparePasswordStrings(hash, tCase.pwd)
		require.NoError(t, err, fmt.Errorf("[%s] comparing error", name))
		assert.True(t, yes)

		no, err := ComparePasswordStrings(hash, tCase.pwd+"extra")
		require.NoError(t, err, fmt.Errorf("[%s] comparing error", name))
		assert.False(t, no)
	}

	no, err := ComparePasswordStrings("", "")
	require.Error(t, err)
	assert.False(t, no)

	no, err = ComparePasswordBytes(nil, nil)
	require.Error(t, err)
	assert.False(t, no)

}
