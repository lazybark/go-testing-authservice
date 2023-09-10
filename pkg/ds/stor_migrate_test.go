package ds

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lazybark/go-testing-authservice/pkg/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*
There will be no parallel tests, because we're switching function values on package level
and it can kill other tests.
*/

func TestStorageMigrate(t *testing.T) {
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

	var count int

	err = ds.pool.QueryRow(context.Background(),
		`SELECT count(*)
		FROM pg_catalog.pg_tables
		WHERE schemaname != 'pg_catalog' 
		AND schemaname != 'information_schema'
		AND tablename = 'user_data'
		`,
	).Scan(&count)
	require.NoError(t, err)

	assert.Equal(t, 1, count, "no user_data table")

	err = ds.pool.QueryRow(context.Background(),
		`SELECT count(*)
		FROM pg_catalog.pg_tables
		WHERE schemaname != 'pg_catalog' 
		AND schemaname != 'information_schema'
		AND tablename = 'user_sessions'
		`,
	).Scan(&count)
	require.NoError(t, err)

	assert.Equal(t, 1, count, "no user_sessions table")

	err = ds.pool.QueryRow(context.Background(),
		`SELECT count(*)
		FROM pg_catalog.pg_tables
		WHERE schemaname != 'pg_catalog' 
		AND schemaname != 'information_schema'
		AND tablename = 'user_failed_login_attempts'
		`,
	).Scan(&count)
	require.NoError(t, err)

	assert.Equal(t, 1, count, "no user_failed_login_attempts table")

	err = ds.pool.QueryRow(context.Background(),
		`SELECT count(*)
		FROM pg_catalog.pg_tables
		WHERE schemaname != 'pg_catalog' 
		AND schemaname != 'information_schema'
		AND tablename = 'user_password_restore_codes'
		`,
	).Scan(&count)
	require.NoError(t, err)

	assert.Equal(t, 1, count, "no user_password_restore_codes table")

	// And call again to be sure there is no error in case of double migration.
	err = ds.Migrate(ctx)
	require.NoError(t, err)

	// Must NOT run in parallel
	// execConnection => error
	t.Run("execConnection => error", func(t *testing.T) {
		orig := eexecConnection
		t.Cleanup(func() {
			eexecConnection = orig
		})

		eexecConnection = func(c *pgxpool.Conn, ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, fmt.Errorf("some_error")
		}

		conn, err := ds.pool.Acquire(ctx)
		require.NoError(t, err)
		t.Cleanup(func() {
			conn.Release()
		})

		err = migrateUser(conn, ctx)
		require.Error(t, err)

		err = migrateSession(conn, ctx)
		require.Error(t, err)

		err = migrateLoginAttempts(conn, ctx)
		require.Error(t, err)

		err = migrateRestoreCodes(conn, ctx)
		require.Error(t, err)
	})

	// Must NOT run in parallel
	// migration functions => error
	t.Run("migration functions => error", func(t *testing.T) {
		conn, err := ds.pool.Acquire(ctx)
		require.NoError(t, err)
		t.Cleanup(func() {
			conn.Release()
		})

		// restoreCodesTableMigrate
		origCTM := restoreCodesTableMigrate
		t.Cleanup(func() {
			restoreCodesTableMigrate = origCTM
		})

		restoreCodesTableMigrate = func(conn *pgxpool.Conn, ctx context.Context) error {
			return fmt.Errorf("some_error")
		}

		err = ds.Migrate(ctx)
		require.Error(t, err)

		// loginAttemptsTableMigrate
		origLTM := loginAttemptsTableMigrate
		t.Cleanup(func() {
			loginAttemptsTableMigrate = origLTM
		})

		loginAttemptsTableMigrate = func(conn *pgxpool.Conn, ctx context.Context) error {
			return fmt.Errorf("some_error")
		}

		err = ds.Migrate(ctx)
		require.Error(t, err)

		// sessionsTableMigrate
		origSTM := sessionsTableMigrate
		t.Cleanup(func() {
			sessionsTableMigrate = origSTM
		})

		sessionsTableMigrate = func(conn *pgxpool.Conn, ctx context.Context) error {
			return fmt.Errorf("some_error")
		}

		err = ds.Migrate(ctx)
		require.Error(t, err)

		// usersTableMigrate
		origUTM := usersTableMigrate
		t.Cleanup(func() {
			usersTableMigrate = origUTM
		})

		usersTableMigrate = func(conn *pgxpool.Conn, ctx context.Context) error {
			return fmt.Errorf("some_error")
		}

		err = ds.Migrate(ctx)
		require.Error(t, err)
	})
}
