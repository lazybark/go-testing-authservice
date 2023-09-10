package ds

import (
	"context"
	"fmt"
	"testing"

	"github.com/lazybark/go-testing-authservice/pkg/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*
There will be no parallel tests, because we're switching function values on package level
and it can kill other tests.
*/

func TestAddUserSession(t *testing.T) {
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

	udata := GetRandomUserData()
	uid, err := ds.CreateUser(ctx, udata)
	require.NoError(t, err)
	require.NotEmpty(t, uid)

	sid, err := ds.AddUserSession(ctx, uid)
	require.NoError(t, err)
	require.NotEmpty(t, sid)

	var s UserSession
	err = ds.pool.QueryRow(context.Background(),
		`SELECT 
		s.session_id, s.user_id, s.created_at, s.closed_at
		FROM user_sessions s 
		WHERE s.session_id = $1
		`, sid,
	).Scan(&s.SessionID, &s.UserID, &s.CreatedAt, &s.ClosedAt)
	require.NoError(t, err)

	assert.Equal(t, sid, s.SessionID)
	assert.True(t, s.CreatedAt.Valid)
	assert.False(t, s.ClosedAt.Valid)

	// exec = > error
	origExec := eexec
	t.Cleanup(func() {
		eexec = origExec
	})

	eexec = func(_ executor, sql string, arguments ...any) error {
		return fmt.Errorf("some_error")
	}

	sid, err = ds.AddUserSession(ctx, uid)
	require.Error(t, err, "exec = > error")
	require.ErrorAs(t, err, new(StorageError), "exec = > error")
	require.Empty(t, sid, "exec = > error")

	// Must NOT run in parallel
	t.Run("getTransaction => error", func(t *testing.T) {
		orig := getTransaction
		t.Cleanup(func() {
			getTransaction = orig
		})

		getTransaction = func(ds *DataStorageUsers, ctx context.Context) (executor, error) {
			return nil, fmt.Errorf("some_error")
		}

		sid, err = ds.AddUserSession(ctx, uid)
		require.Error(t, err)
		require.Empty(t, sid)
	})
}
