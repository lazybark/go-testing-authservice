package ds

import (
	"context"
	"fmt"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lazybark/go-testing-authservice/pkg/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorageConnectClose(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbContainer, dsn, err := helpers.NewTestContainerDatabase(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		dbContainer.Terminate(ctx)
	})

	ds := DataStorageUsers{}

	err = ds.Connect(ctx, dsn)
	require.NoError(t, err)

	err = ds.Close()
	require.NoError(t, err)

	// parseConfig = > error
	t.Run("exec = > error", func(t *testing.T) {
		orig := parseConfig
		t.Cleanup(func() {
			parseConfig = orig
		})

		parseConfig = func(connString string) (*pgxpool.Config, error) {
			return nil, fmt.Errorf("some_error")
		}

		err = ds.Connect(ctx, dsn)
		require.Error(t, err)
	})

	t.Run("newWithConfig = > error", func(t *testing.T) {
		orig := newWithConfig
		t.Cleanup(func() {
			newWithConfig = orig
		})

		newWithConfig = func(ctx context.Context, config *pgxpool.Config) (*pgxpool.Pool, error) {
			return nil, fmt.Errorf("some_error")
		}

		err = ds.Connect(ctx, dsn)
		require.Error(t, err)
	})

}

func TestRollback(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbContainer, dsn, err := helpers.NewTestContainerDatabase(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		dbContainer.Terminate(ctx)
	})

	ds := DataStorageUsers{}

	err = ds.Connect(ctx, dsn)
	require.NoError(t, err)

	t.Cleanup(func() {
		ds.Close()
	})

	err = ds.Migrate(ctx)
	require.NoError(t, err)

	tx, err := ds.GetTransaction(ctx)
	require.NoError(t, err)

	udata := GetRandomUserData()
	id, err := uuid.NewV4()
	require.NoError(t, err)
	insertID := id.String()

	err = tx.exec(
		`INSERT INTO user_data 
		(user_id, login, password_hash, first_name, last_name, email)
		VALUES ($1, $2, $3, $4, $5, $6);
		`, insertID, udata.Login, udata.PasswordHash, udata.FirstName, udata.LastName, udata.Email,
	)

	err = tx.rollback()
	require.NoError(t, err)

	usr, err := ds.GetUserByLogin(ctx, udata.Login)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotExists)
	assert.Equal(t, "", usr.UserID)

}
