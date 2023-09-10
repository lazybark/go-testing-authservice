package logic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecurityError(t *testing.T) {
	assert.Equal(t, string(ErrUserExists), ErrUserExists.Error())
	assert.ErrorAs(t, ErrUserExists, new(LogicError))
	assert.ErrorAs(t, ErrEmptyFields, new(LogicError))
	assert.ErrorAs(t, ErrUnknownUser, new(LogicError))
	assert.ErrorAs(t, ErrUserBlocked, new(LogicError))
	assert.ErrorAs(t, ErrBadRefreshToken, new(LogicError))
	assert.ErrorAs(t, ErrNotRefreshToken, new(LogicError))

	e := LogicError("some_err")
	assert.Equal(t, string(e), e.Error())
	assert.ErrorAs(t, e, new(LogicError))
}
