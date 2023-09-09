package helpers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTestContainerDatabase(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbContainer, dsn, err := NewTestContainerDatabase(ctx)
	require.NoError(t, err)

	assert.NotEmpty(t, dsn)
	assert.NotNil(t, dbContainer)

	err = dbContainer.Terminate(ctx)
	require.NoError(t, err)
}
