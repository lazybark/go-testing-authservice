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

func TestMustChangePassword(t *testing.T) {
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

	err = ds.MustChangePassword(ctx, uid)
	require.NoError(t, err)

	usr, err := ds.GetUserByLogin(ctx, udata.Login)
	require.NoError(t, err)

	assert.True(t, usr.MustChangePassword)

	// exec = > error
	origExec := eexec
	t.Cleanup(func() {
		eexec = origExec
	})

	eexec = func(_ executor, sql string, arguments ...any) error {
		return fmt.Errorf("some_error")
	}

	err = ds.MustChangePassword(ctx, uid)
	require.Error(t, err, "exec = > error")

	// Must NOT run in parallel
	t.Run("getTransaction => error", func(t *testing.T) {
		orig := getTransaction
		t.Cleanup(func() {
			getTransaction = orig
		})

		getTransaction = func(ds *DataStorageUsers, ctx context.Context) (executor, error) {
			return nil, fmt.Errorf("some_error")
		}

		err = ds.MustChangePassword(ctx, uid)
		require.Error(t, err, "exec = > error")
	})
}
