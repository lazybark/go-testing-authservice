package logic

import (
	"context"
	"fmt"
	"testing"

	"github.com/lazybark/go-testing-authservice/pkg/ds"
	"github.com/lazybark/go-testing-authservice/pkg/helpers"
	"github.com/stretchr/testify/require"
)

func TestUserReg(t *testing.T) {
	udata := ds.GetRandomUserData()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbContainer, dsn, err := helpers.NewTestContainerDatabase(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { dbContainer.Terminate(ctx) })

	stor := &ds.DataStorageUsers{}
	err = stor.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { stor.Close() })

	err = stor.Migrate(ctx)
	require.NoError(t, err)

	regData := UserRegData{
		Login:     udata.Login,
		Password:  udata.PasswordHash,
		FirstName: udata.FirstName,
		LastName:  udata.LastName,
		Email:     udata.Email,
	}

	err = UserReg(regData, stor)
	require.NoError(t, err)

	wrongResults := map[string]struct {
		login    string
		password string
		name     string
		email    string
	}{
		"empty login":    {login: "", password: regData.Password, name: regData.FirstName, email: regData.Email},
		"empty password": {login: udata.Login, password: "", name: regData.FirstName, email: regData.Email},
		"wrong name":     {login: udata.Login, password: regData.Password, name: "", email: regData.Email},
		"wrong email":    {login: udata.Login, password: regData.Password, name: regData.FirstName, email: ""},
	}

	for name, tCase := range wrongResults {
		t.Run(name, func(t *testing.T) {
			tCase := tCase
			name := name

			t.Parallel()

			regDataWrong := UserRegData{
				Login:     tCase.login,
				Password:  tCase.password,
				FirstName: tCase.name,
				Email:     tCase.email,
			}

			err = UserReg(regDataWrong, stor)
			require.Error(t, err, name)
			require.ErrorIs(t, err, ErrEmptyFields, name)
		})
	}

	// Must NOT run in parallel
	// hashPasswordString => error
	t.Run("hashPasswordString => error", func(t *testing.T) {
		orig := hashPasswordString
		t.Cleanup(func() {
			hashPasswordString = orig
		})

		hashPasswordString = func(pwd string, cost int) (string, error) {
			return "", fmt.Errorf("some_error")
		}

		err = UserReg(regData, stor)
		require.Error(t, err)
	})

	// Must NOT run in parallel
	// createUser => error
	t.Run("createUser => error", func(t *testing.T) {
		orig := createUser
		t.Cleanup(func() {
			createUser = orig
		})

		createUser = func(_ UserLogicWorker, ctx context.Context, u ds.UserData) (uid string, err error) {
			return "", fmt.Errorf("some_error")
		}

		err = UserReg(regData, stor)
		require.Error(t, err)

		createUser = func(_ UserLogicWorker, ctx context.Context, u ds.UserData) (uid string, err error) {
			return "", ds.ErrDuplicateKey
		}

		err = UserReg(regData, stor)
		require.ErrorIs(t, err, ErrUserExists)
	})
}
