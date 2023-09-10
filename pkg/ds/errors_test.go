package ds

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetStorageError(t *testing.T) {
	e := getStorageError(fmt.Errorf("some_err"))
	assert.ErrorAs(t, e, new(StorageError))

	e = getStorageError(fmt.Errorf(patternErrViolation))
	assert.ErrorAs(t, e, new(StorageError))
	assert.ErrorIs(t, e, ErrRelationViolation)

	e = getStorageError(fmt.Errorf(patternErrExists))
	assert.ErrorAs(t, e, new(StorageError))
	assert.ErrorIs(t, e, ErrDuplicateKey)
}
