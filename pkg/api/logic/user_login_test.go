package logic

import (
	"context"
	"fmt"
	"testing"

	"github.com/lazybark/go-testing-authservice/pkg/ds"
	"github.com/lazybark/go-testing-authservice/pkg/helpers"
	"github.com/lazybark/go-testing-authservice/pkg/sec"
	"github.com/stretchr/testify/require"
)

func TestUserLogin(t *testing.T) {
	udata := ds.GetRandomUserData()
	jwtSecret := "jwtSecret"
	ip := "192.168.0.1"
	password := udata.PasswordHash
	pwdHash, err := hashPasswordString(udata.PasswordHash, 10)
	require.NoError(t, err)
	udata.PasswordHash = pwdHash

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

	uid, err := stor.CreateUser(ctx, udata)
	require.NoError(t, err)
	require.NotEmpty(t, uid)

	wrongResults := map[string]struct {
		login    string
		password string
		expect   error
	}{
		"empty login":    {login: "", password: password, expect: ErrEmptyFields},
		"empty password": {login: udata.Login, password: "", expect: ErrEmptyFields},
		"wrong login":    {login: "wrong", password: password, expect: ErrUnknownUser},
		"wrong password": {login: udata.Login, password: "wrong", expect: ErrUnknownUser},
	}

	// Must NOT run in parallel
	for name, tCase := range wrongResults {
		t.Run(name, func(t *testing.T) {
			tCase := tCase
			name := name

			loginData := UserLoginData{
				Login:    tCase.login,
				Password: tCase.password,
			}

			token, err := UserLogin(loginData, stor, ip, 10, jwtSecret)
			require.Error(t, err, name)
			require.ErrorIs(t, err, tCase.expect)
			require.Nil(t, token, name)

		})
	}

	correctLoginData := UserLoginData{
		Login:    udata.Login,
		Password: password,
	}

	// Now correct password
	token, err := UserLogin(correctLoginData, stor, ip, 10, jwtSecret)
	require.NoError(t, err, "correct data")
	require.NotNil(t, token, "correct data")

	valid, err := checkToken(token.AuthToken, jwtSecret)
	require.NoError(t, err, "correct data")
	require.True(t, valid, "correct data")

	valid, err = checkToken(token.RefreshToken, jwtSecret)
	require.NoError(t, err, "correct data")
	require.True(t, valid, "correct data")

	// Now let's block the user
	incorrectLoginData := UserLoginData{
		Login:    udata.Login,
		Password: "wrong",
	}
	for i := 0; i < 10; i++ {
		_, _ = UserLogin(incorrectLoginData, stor, ip, 10, jwtSecret)
	}

	token, err = UserLogin(correctLoginData, stor, ip, 10, jwtSecret)
	require.Error(t, err, "correct data")
	require.ErrorIs(t, err, ErrUserBlocked)
	require.Nil(t, token, "correct data")
}

// internal functions => error
func TestUserLogin_errors(t *testing.T) {
	udata := ds.GetRandomUserData()
	jwtSecret := "jwtSecret"
	ip := "192.168.0.1"
	password := udata.PasswordHash
	pwdHash, err := hashPasswordString(udata.PasswordHash, 10)
	require.NoError(t, err)
	udata.PasswordHash = pwdHash

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

	uid, err := stor.CreateUser(ctx, udata)
	require.NoError(t, err)
	require.NotEmpty(t, uid)

	correctLoginData := UserLoginData{
		Login:    udata.Login,
		Password: password,
	}

	// formJWT => error
	origFJ := formJWT
	t.Cleanup(func() {
		formJWT = origFJ
	})

	formJWT = func(uid string, sid string, uname string, email string, jwtSecret string) (*sec.Token, error) {
		return nil, fmt.Errorf("some_error")
	}

	token, err := UserLogin(correctLoginData, stor, ip, 10, jwtSecret)
	require.Error(t, err)
	require.Nil(t, token)

	// addUserSession => error
	origAUS := addUserSession
	t.Cleanup(func() {
		addUserSession = origAUS
	})

	addUserSession = func(_ UserLogicWorker, ctx context.Context, uid string) (sid string, err error) {
		return "", fmt.Errorf("some_error")
	}

	token, err = UserLogin(correctLoginData, stor, ip, 10, jwtSecret)
	require.Error(t, err)
	require.Nil(t, token)

	// mustChangePassword => error
	origMCP := mustChangePassword
	t.Cleanup(func() {
		mustChangePassword = origMCP
	})

	mustChangePassword = func(_ UserLogicWorker, ctx context.Context, uid string) error {
		return fmt.Errorf("some_error")
	}

	token, err = UserLogin(correctLoginData, stor, ip, 10, jwtSecret)
	require.Error(t, err)
	require.Nil(t, token)

	// blockUserLogin => error
	origBUL := blockUserLogin
	t.Cleanup(func() {
		blockUserLogin = origBUL
	})

	blockUserLogin = func(_ UserLogicWorker, ctx context.Context, uid string) error {
		return fmt.Errorf("some_error")
	}

	token, err = UserLogin(correctLoginData, stor, ip, 10, jwtSecret)
	require.Error(t, err)
	require.Nil(t, token)

	// addFailedLoginAttempt => error
	origALA := addFailedLoginAttempt
	t.Cleanup(func() {
		addFailedLoginAttempt = origALA
	})

	addFailedLoginAttempt = func(_ UserLogicWorker, ctx context.Context, uid string, ip string) (total int, err error) {
		return 0, fmt.Errorf("some_error")
	}

	token, err = UserLogin(correctLoginData, stor, ip, 10, jwtSecret)
	require.Error(t, err)
	require.Nil(t, token)

	// comparePasswordStrings => error
	origCPS := comparePasswordStrings
	t.Cleanup(func() {
		comparePasswordStrings = origCPS
	})

	comparePasswordStrings = func(hashedPwd string, plainPwd string) (bool, error) {
		return false, fmt.Errorf("some_error")
	}

	token, err = UserLogin(correctLoginData, stor, ip, 10, jwtSecret)
	require.Error(t, err)
	require.Nil(t, token)
}

// internal functions => error with !pwd.Valid
func TestUserLogin_errors_add_failed_attempt(t *testing.T) {
	udata := ds.GetRandomUserData()
	jwtSecret := "jwtSecret"
	ip := "192.168.0.1"
	password := udata.PasswordHash
	pwdHash, err := hashPasswordString(udata.PasswordHash, 10)
	require.NoError(t, err)
	udata.PasswordHash = pwdHash

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

	uid, err := stor.CreateUser(ctx, udata)
	require.NoError(t, err)
	require.NotEmpty(t, uid)

	correctLoginData := UserLoginData{
		Login:    udata.Login,
		Password: password,
	}

	// comparePasswordStrings => false
	origCPS := comparePasswordStrings
	t.Cleanup(func() {
		comparePasswordStrings = origCPS
	})

	comparePasswordStrings = func(hashedPwd string, plainPwd string) (bool, error) {
		return false, nil
	}

	// addFailedLoginAttempt => error
	origALA := addFailedLoginAttempt
	t.Cleanup(func() {
		addFailedLoginAttempt = origALA
	})

	addFailedLoginAttempt = func(_ UserLogicWorker, ctx context.Context, uid string, ip string) (total int, err error) {
		return 0, fmt.Errorf("some_error")
	}

	token, err := UserLogin(correctLoginData, stor, ip, 0, jwtSecret)
	require.Error(t, err)
	require.Nil(t, token)
}

// internal functions => error with !pwd.Valid
func TestUserLogin_errors_block_user_login(t *testing.T) {
	udata := ds.GetRandomUserData()
	jwtSecret := "jwtSecret"
	ip := "192.168.0.1"
	password := udata.PasswordHash
	pwdHash, err := hashPasswordString(udata.PasswordHash, 10)
	require.NoError(t, err)
	udata.PasswordHash = pwdHash

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

	uid, err := stor.CreateUser(ctx, udata)
	require.NoError(t, err)
	require.NotEmpty(t, uid)

	correctLoginData := UserLoginData{
		Login:    udata.Login,
		Password: password,
	}

	// comparePasswordStrings => false
	origCPS := comparePasswordStrings
	t.Cleanup(func() {
		comparePasswordStrings = origCPS
	})

	comparePasswordStrings = func(hashedPwd string, plainPwd string) (bool, error) {
		return false, nil
	}

	// addFailedLoginAttempt => error
	origALA := addFailedLoginAttempt
	t.Cleanup(func() {
		addFailedLoginAttempt = origALA
	})

	addFailedLoginAttempt = func(_ UserLogicWorker, ctx context.Context, uid string, ip string) (total int, err error) {
		return 1, nil
	}

	// blockUserLogin => error
	origBUL := blockUserLogin
	t.Cleanup(func() {
		blockUserLogin = origBUL
	})

	blockUserLogin = func(_ UserLogicWorker, ctx context.Context, uid string) error {
		return fmt.Errorf("some_error")
	}

	token, err := UserLogin(correctLoginData, stor, ip, 1, jwtSecret)
	require.Error(t, err)
	require.Nil(t, token)
}

// internal functions => error with !pwd.Valid
func TestUserLogin_errors_must_change_pwd(t *testing.T) {
	udata := ds.GetRandomUserData()
	jwtSecret := "jwtSecret"
	ip := "192.168.0.1"
	password := udata.PasswordHash
	pwdHash, err := hashPasswordString(udata.PasswordHash, 10)
	require.NoError(t, err)
	udata.PasswordHash = pwdHash

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

	uid, err := stor.CreateUser(ctx, udata)
	require.NoError(t, err)
	require.NotEmpty(t, uid)

	correctLoginData := UserLoginData{
		Login:    udata.Login,
		Password: password,
	}

	// comparePasswordStrings => false
	origCPS := comparePasswordStrings
	t.Cleanup(func() {
		comparePasswordStrings = origCPS
	})

	comparePasswordStrings = func(hashedPwd string, plainPwd string) (bool, error) {
		return false, nil
	}

	// mustChangePassword => error
	origMCP := mustChangePassword
	t.Cleanup(func() {
		mustChangePassword = origMCP
	})

	mustChangePassword = func(_ UserLogicWorker, ctx context.Context, uid string) error {
		return fmt.Errorf("some_error")
	}

	token, err := UserLogin(correctLoginData, stor, ip, 0, jwtSecret)
	require.Error(t, err)
	require.Nil(t, token)
}
