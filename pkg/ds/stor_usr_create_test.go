package ds

import (
	"context"
	"fmt"
	"testing"

	"github.com/lazybark/go-testing-authservice/pkg/helpers"
	"github.com/lazybark/go-testing-authservice/pkg/sec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*
There will be no parallel tests, because we're switching function values on package level
and it can kill other tests.
*/

func TestCreateUser(t *testing.T) {
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
	pwdHash, err := sec.HashPasswordString(udata.PasswordHash, 10)
	require.NoError(t, err)
	udata.PasswordHash = pwdHash

	uid, err := ds.CreateUser(ctx, udata)
	require.NoError(t, err)
	require.NotEmpty(t, uid)

	usr, err := ds.GetUserByLogin(ctx, udata.Login)
	require.NoError(t, err)

	assert.Equal(t, udata.Login, usr.Login)
	assert.Equal(t, udata.FirstName, usr.FirstName)
	assert.Equal(t, udata.LastName, usr.LastName)
	assert.Equal(t, udata.Email, usr.Email)
	assert.Equal(t, pwdHash, usr.PasswordHash)
	assert.False(t, usr.MustChangePassword)
	assert.False(t, usr.BlockedLogin)
	assert.False(t, usr.BlockedAt.Valid)
	assert.True(t, usr.CreatedAt.Valid)

	// commit = > error
	origCommit := ecommit
	t.Cleanup(func() {
		ecommit = origCommit
	})

	ecommit = func(executor) error {
		return fmt.Errorf("some_error")
	}

	uid, err = ds.CreateUser(ctx, udata)
	require.Error(t, err, "commit = > error")
	require.ErrorAs(t, err, new(StorageError), "commit = > error")
	require.Empty(t, uid, "commit = > error")

	// exec = > error
	origExec := eexec
	t.Cleanup(func() {
		eexec = origExec
	})

	eexec = func(_ executor, sql string, arguments ...any) error {
		return fmt.Errorf("some_error")
	}

	uid, err = ds.CreateUser(ctx, udata)
	require.Error(t, err, "exec = > error")
	require.ErrorAs(t, err, new(StorageError), "exec = > error")
	require.Empty(t, uid, "exec = > error")

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

		uid, err = ds.CreateUser(ctx, udata)
		require.Error(t, err)
		require.Empty(t, uid)
	})
}
