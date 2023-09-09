package helpers

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
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

	// Must NOT run in parallel
	t.Run("genericContainer error", func(t *testing.T) {
		orig := genericContainer
		t.Cleanup(func() {
			genericContainer = orig
		})

		genericContainer = func(ctx context.Context, req testcontainers.GenericContainerRequest) (testcontainers.Container, error) {
			return nil, fmt.Errorf("some_error")
		}

		dbContainer, dsn, err := NewTestContainerDatabase(ctx)
		require.Error(t, err)
		assert.Empty(t, dsn)
		assert.Nil(t, dbContainer)
	})
}
