package helpers

import (
	"context"
	"fmt"
	"testing"

	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

/*
There will be no parallel tests, because we're switching function values on package level
and it can kill other tests.
*/

func TestNewTestContainerDatabase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbContainer, dsn, err := NewTestContainerDatabase(ctx)
	require.NoError(t, err)

	assert.NotEmpty(t, dsn)
	assert.NotNil(t, dbContainer)

	err = dbContainer.Terminate(ctx)
	require.NoError(t, err)

	// Must NOT run in parallel
	t.Run("genericContainer => error", func(t *testing.T) {
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

	// Must NOT run in parallel
	t.Run("genericContainer => error", func(t *testing.T) {
		orig := mappedPort
		t.Cleanup(func() {
			mappedPort = orig
		})

		mappedPort = func(testcontainers.Container, context.Context, nat.Port) (nat.Port, error) {
			return "", fmt.Errorf("some_error")
		}

		dbContainer, dsn, err := NewTestContainerDatabase(ctx)
		require.Error(t, err)
		assert.Empty(t, dsn)
		assert.Nil(t, dbContainer)
	})
}
