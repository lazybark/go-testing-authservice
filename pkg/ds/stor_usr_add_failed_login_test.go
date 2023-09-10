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

func TestAddFailedLoginAttempt(t *testing.T) {
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

	addr := "192.168.0.1"
	_, err = ds.AddFailedLoginAttempt(ctx, uid, addr)
	require.NoError(t, err)

	var a UserFailedLoginAttempt
	err = ds.pool.QueryRow(context.Background(),
		`SELECT 
		a.user_id, a.created_at, a.ip_addr
		FROM user_failed_login_attempts a 
		WHERE a.user_id = $1
		`, uid,
	).Scan(&a.UserID, &a.CreatedAt, &a.IPAddr)
	require.NoError(t, err)

	assert.Equal(t, uid, a.UserID)
	assert.Equal(t, addr, a.IPAddr)
	assert.True(t, a.CreatedAt.Valid)

	// exec = > error
	origExec := eexec
	t.Cleanup(func() {
		eexec = origExec
	})

	eexec = func(_ executor, sql string, arguments ...any) error {
		return fmt.Errorf("some_error")
	}

	_, err = ds.AddFailedLoginAttempt(ctx, uid, addr)
	require.Error(t, err, "exec = > error")

	// Must NOT run in parallel
	// getTransaction => error
	t.Run("getTransaction => error", func(t *testing.T) {
		orig := getTransaction
		t.Cleanup(func() {
			getTransaction = orig
		})

		getTransaction = func(ds *DataStorageUsers, ctx context.Context) (executor, error) {
			return nil, fmt.Errorf("some_error")
		}

		_, err = ds.AddFailedLoginAttempt(ctx, uid, addr)
		require.Error(t, err)
	})
}
