package sec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecurityError(t *testing.T) {
	t.Parallel()

	assert.Equal(t, string(ErrBadToken), ErrBadToken.Error())
	assert.ErrorAs(t, ErrBadToken, new(SecurityError))

	e := SecurityError("some_err")
	assert.Equal(t, string(e), e.Error())
}
