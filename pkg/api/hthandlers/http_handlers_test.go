package hthandlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lazybark/go-testing-authservice/pkg/api/logic"
	"github.com/lazybark/go-testing-authservice/pkg/api/resp"
	"github.com/lazybark/go-testing-authservice/pkg/ds"
	"github.com/lazybark/go-testing-authservice/pkg/helpers"
	"github.com/lazybark/go-testing-authservice/pkg/sec"
	"github.com/stretchr/testify/require"
)

/*
There will be no parallel tests, because we're switching function values on package level
and it can kill other tests.
*/

var (
	testJwtSecret = "jwtSecret"
	urlRegister   = "/api/users/register"
	urlLogin      = "/api/users/login"
	urlGetToken   = "/api/users/get_token"
	urlCheckToken = "/api/users/check_token/%s"
)

func TestRegister(t *testing.T) {
	regData := ds.GetRandomUserData()

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

	wrongResults := map[string]struct {
		login    string
		password string
		name     string
		email    string
	}{
		"register empty login":    {login: "", password: regData.PasswordHash, name: regData.FirstName, email: regData.Email},
		"register empty password": {login: regData.Login, password: "", name: regData.FirstName, email: regData.Email},
		"register wrong name":     {login: regData.Login, password: regData.PasswordHash, name: "", email: regData.Email},
		"register wrong email":    {login: regData.Login, password: regData.PasswordHash, name: regData.FirstName, email: ""},
	}

	for name, tCase := range wrongResults {
		t.Run(name, func(t *testing.T) {
			tCase := tCase
			name := name

			body, err := json.Marshal(logic.UserRegData{
				Login:     tCase.login,
				Password:  tCase.password,
				FirstName: tCase.name,
				Email:     tCase.email,
			})
			require.NoError(t, err)

			req, err := http.NewRequest("POST", urlRegister, bytes.NewBuffer(body))
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			Register(stor).ServeHTTP(rr, req)

			post := &resp.Response{}
			err = json.NewDecoder(rr.Body).Decode(post)
			require.NoError(t, err, name)
			require.False(t, post.Success, name)
			require.Equal(t, 200, post.Status, name)
			require.Equal(t, logic.ErrEmptyFields.Error(), post.Response, name)
		})
	}

	name := "correct register data"
	t.Run(name, func(t *testing.T) {
		body, err := json.Marshal(logic.UserRegData{
			Login:     regData.Login,
			Password:  regData.PasswordHash,
			FirstName: regData.FirstName,
			Email:     regData.Email,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlRegister, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		Register(stor).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err, name)
		require.True(t, post.Success, name)
		require.Equal(t, 200, post.Status, name)
		require.Equal(t, resp.RespOKMessage, post.Response, name)
	})

	name = "broken post"
	t.Run(name, func(t *testing.T) {
		body, err := json.Marshal(logic.UserRegData{
			Login:     regData.Login,
			Password:  regData.PasswordHash,
			FirstName: regData.FirstName,
			Email:     regData.Email,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlRegister, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		Register(stor).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err, name)
		require.False(t, post.Success, name)
		require.Equal(t, 200, post.Status, name)
	})

	// Must NOT run in parallel
	// "unmarshal => error"
	t.Run("unmarshal => error", func(t *testing.T) {
		orig := unmarshal
		t.Cleanup(func() {
			unmarshal = orig
		})

		unmarshal = func(data []byte, v any) error {
			return fmt.Errorf("some_error")
		}

		body, err := json.Marshal(logic.UserRegData{
			Login:     regData.Login,
			Password:  regData.PasswordHash,
			FirstName: regData.FirstName,
			Email:     regData.Email,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlRegister, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		Register(stor).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err)
		require.False(t, post.Success)
		require.Equal(t, 400, post.Status)
	})

	// Must NOT run in parallel
	// "readAll => error"
	t.Run("readAll => error", func(t *testing.T) {
		orig := readAll
		t.Cleanup(func() {
			readAll = orig
		})

		readAll = func(r io.Reader) ([]byte, error) {
			return nil, fmt.Errorf("some_error")
		}

		body, err := json.Marshal(logic.UserRegData{
			Login:     regData.Login,
			Password:  regData.PasswordHash,
			FirstName: regData.FirstName,
			Email:     regData.Email,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlRegister, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		Register(stor).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err)
		require.False(t, post.Success)
		require.Equal(t, 400, post.Status)
	})

	// Must NOT run in parallel
	// "readAll => 0"
	t.Run("readAll => 0", func(t *testing.T) {
		orig := readAll
		t.Cleanup(func() {
			readAll = orig
		})

		readAll = func(r io.Reader) ([]byte, error) {
			return []byte{}, nil
		}

		body, err := json.Marshal(logic.UserRegData{
			Login:     regData.Login,
			Password:  regData.PasswordHash,
			FirstName: regData.FirstName,
			Email:     regData.Email,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlRegister, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		Register(stor).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err)
		require.False(t, post.Success)
		require.Equal(t, 400, post.Status)
	})
}

func TestLogin(t *testing.T) {
	regData := ds.GetRandomUserData()
	password := regData.PasswordHash
	pwdHash, err := sec.HashPasswordString(regData.PasswordHash, 10)
	require.NoError(t, err)
	regData.PasswordHash = pwdHash

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

	uid, err := stor.CreateUser(ctx, regData)
	require.NoError(t, err)
	require.NotEmpty(t, uid)

	// Now login
	wrongLogins := map[string]struct {
		login    string
		password string
	}{
		"login empty login":    {login: "", password: password},
		"login empty password": {login: regData.Login, password: ""},
	}

	for name, tCase := range wrongLogins {
		t.Run(name, func(t *testing.T) {
			tCase := tCase
			name := name

			body, err := json.Marshal(logic.UserLoginData{
				Login:    tCase.login,
				Password: tCase.password,
			})
			require.NoError(t, err)

			req, err := http.NewRequest("POST", urlLogin, bytes.NewBuffer(body))
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			Login(testJwtSecret, 10, stor).ServeHTTP(rr, req)

			post := &resp.Response{}
			err = json.NewDecoder(rr.Body).Decode(post)
			require.NoError(t, err, name)
			require.False(t, post.Success, name)
			require.Equal(t, 200, post.Status, name)
			require.Equal(t, logic.ErrEmptyFields.Error(), post.Response, name)
		})
	}

	name := "correct login data"
	body, err := json.Marshal(logic.UserLoginData{
		Login:    regData.Login,
		Password: password,
	})
	require.NoError(t, err)

	req, err := http.NewRequest("POST", urlLogin, bytes.NewBuffer(body))
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	Login(testJwtSecret, 10, stor).ServeHTTP(rr, req)

	post := &resp.Response{}
	err = json.NewDecoder(rr.Body).Decode(post)
	require.NoError(t, err, name)
	require.True(t, post.Success, name)
	require.Equal(t, 200, post.Status, name)
	require.NotEmpty(t, post.Response, name) // Not checking token - it's done in other tests

	// Must NOT run in parallel
	// "unmarshal => err"
	t.Run("unmarshal => err", func(t *testing.T) {
		orig := unmarshal
		t.Cleanup(func() {
			unmarshal = orig
		})

		unmarshal = func(data []byte, v any) error {
			return fmt.Errorf("some_error")
		}

		body, err := json.Marshal(logic.UserLoginData{
			Login:    regData.Login,
			Password: password,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlLogin, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		Login(testJwtSecret, 10, stor).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err)
		require.False(t, post.Success)
		require.Equal(t, 400, post.Status)
	})

	// Must NOT run in parallel
	// "err => readAll"
	t.Run("err => readAll", func(t *testing.T) {
		orig := readAll
		t.Cleanup(func() {
			readAll = orig
		})

		readAll = func(r io.Reader) ([]byte, error) {
			return nil, fmt.Errorf("some_error")
		}

		body, err := json.Marshal(logic.UserLoginData{
			Login:    regData.Login,
			Password: password,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlLogin, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		Login(testJwtSecret, 10, stor).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err, name)
		require.False(t, post.Success, name)
		require.Equal(t, 400, post.Status, name)
	})

	// Must NOT run in parallel
	// "readAll => 0"
	t.Run("readAll => 0", func(t *testing.T) {
		orig := readAll
		t.Cleanup(func() {
			readAll = orig
		})

		readAll = func(r io.Reader) ([]byte, error) {
			return []byte{}, nil
		}

		body, err := json.Marshal(logic.UserLoginData{
			Login:    regData.Login,
			Password: password,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlLogin, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		Login(testJwtSecret, 10, stor).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err, name)
		require.False(t, post.Success, name)
		require.Equal(t, 400, post.Status, name)
	})

	// Must NOT run in parallel
	// "writeSuccess => error"
	t.Run("writeSuccess => error", func(t *testing.T) {
		orig := writeSuccess
		t.Cleanup(func() {
			writeSuccess = orig
		})

		writeSuccess = func(w http.ResponseWriter, response any) error {
			return fmt.Errorf("some_error")
		}

		require.NoError(t, err)
		body, err := json.Marshal(logic.UserLoginData{
			Login:    regData.Login,
			Password: password,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlLogin, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		Login(testJwtSecret, 10, stor).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.Error(t, err, name)
	})
}

// TestCheckToken - don't need to check wrong ones as it's done in other tests
func TestCheckToken(t *testing.T) {
	name := "check token"
	regData := ds.GetRandomUserData()

	token, err := sec.FormJWT(regData.UserID, "session_id", regData.FirstName, regData.Email, testJwtSecret)
	require.NoError(t, err)

	req, err := http.NewRequest("GET", fmt.Sprintf(urlCheckToken, token.AuthToken), nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	CheckToken(testJwtSecret).ServeHTTP(rr, req)

	post := &resp.Response{}
	err = json.NewDecoder(rr.Body).Decode(post)
	require.NoError(t, err, name)
	require.True(t, post.Success, name)
	require.Equal(t, 200, post.Status, name)
	require.Equal(t, "true", post.Response, name)

	// Must NOT run in parallel
	// tokenCheck => error
	t.Run("tokenCheck => error", func(t *testing.T) {
		orig := tokenCheck
		t.Cleanup(func() {
			tokenCheck = orig
		})

		tokenCheck = func(token string, jwtSecret string) (string, error) {
			return "", fmt.Errorf("some_error")
		}

		token, err := sec.FormJWT(regData.UserID, "session_id", regData.FirstName, regData.Email, testJwtSecret)
		require.NoError(t, err)

		req, err := http.NewRequest("GET", fmt.Sprintf(urlCheckToken, token.AuthToken), nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		CheckToken(testJwtSecret).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err, name)
		require.False(t, post.Success, name)
		require.Equal(t, 500, post.Status, name)

		tokenCheck = func(token string, jwtSecret string) (string, error) {
			return "", sec.SecurityError("some_error")
		}

		req, err = http.NewRequest("GET", fmt.Sprintf(urlCheckToken, token.AuthToken), nil)
		require.NoError(t, err)

		rr = httptest.NewRecorder()
		CheckToken(testJwtSecret).ServeHTTP(rr, req)

		post = &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err, name)
		require.False(t, post.Success, name)
		require.Equal(t, 200, post.Status, name)
	})

	// Must NOT run in parallel
	// writeSuccess => error
	t.Run("writeSuccess => error", func(t *testing.T) {
		orig := writeSuccess
		t.Cleanup(func() {
			writeSuccess = orig
		})

		writeSuccess = func(w http.ResponseWriter, response any) error {
			return fmt.Errorf("some_error")
		}

		req, err = http.NewRequest("GET", fmt.Sprintf(urlCheckToken, token.AuthToken), nil)
		require.NoError(t, err)

		rr = httptest.NewRecorder()
		CheckToken(testJwtSecret).ServeHTTP(rr, req)

		post = &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.Error(t, err, name)
	})
}

// TestGetToken - don't need to check wrong ones as it's done in other tests
func TestGetToken(t *testing.T) {
	name := "get token"
	regData := ds.GetRandomUserData()

	token, err := sec.FormJWT(regData.UserID, "session_id", regData.FirstName, regData.Email, testJwtSecret)
	require.NoError(t, err)

	body, err := json.Marshal(logic.TokenData{
		Token: token.RefreshToken,
	})
	require.NoError(t, err)

	req, err := http.NewRequest("POST", urlGetToken, bytes.NewBuffer(body))
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	GetToken(testJwtSecret).ServeHTTP(rr, req)

	post := &resp.Response{}
	err = json.NewDecoder(rr.Body).Decode(post)
	require.NoError(t, err, name)
	require.True(t, post.Success, name)
	require.Equal(t, 200, post.Status, name)
	require.NotEmpty(t, post.Response, name) // Not checking token - it's done in other tests

	// Must NOT run in parallel
	// unmarshal => error
	t.Run("unmarshal => error", func(t *testing.T) {
		orig := unmarshal
		t.Cleanup(func() {
			unmarshal = orig
		})

		unmarshal = func(data []byte, v any) error {
			return fmt.Errorf("some_error")
		}

		token, err := sec.FormJWT(regData.UserID, "session_id", regData.FirstName, regData.Email, testJwtSecret)
		require.NoError(t, err)

		body, err := json.Marshal(logic.TokenData{
			Token: token.RefreshToken,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlGetToken, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		GetToken(testJwtSecret).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err, name)
		require.False(t, post.Success, name)
		require.Equal(t, 400, post.Status, name)
	})

	// Must NOT run in parallel
	// writeSuccess => error
	t.Run("writeSuccess => error", func(t *testing.T) {
		orig := writeSuccess
		t.Cleanup(func() {
			writeSuccess = orig
		})

		writeSuccess = func(w http.ResponseWriter, response any) error {
			return fmt.Errorf("some_error")
		}

		token, err := sec.FormJWT(regData.UserID, "session_id", regData.FirstName, regData.Email, testJwtSecret)
		require.NoError(t, err)

		body, err := json.Marshal(logic.TokenData{
			Token: token.RefreshToken,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlGetToken, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		GetToken(testJwtSecret).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.Error(t, err, name)
	})

	// Must NOT run in parallel
	// readAll => error
	t.Run("readAll => error", func(t *testing.T) {
		orig := readAll
		t.Cleanup(func() {
			readAll = orig
		})

		readAll = func(r io.Reader) ([]byte, error) {
			return nil, fmt.Errorf("some_error")
		}

		token, err := sec.FormJWT(regData.UserID, "session_id", regData.FirstName, regData.Email, testJwtSecret)
		require.NoError(t, err)

		body, err := json.Marshal(logic.TokenData{
			Token: token.RefreshToken,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlGetToken, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		GetToken(testJwtSecret).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err, name)
		require.False(t, post.Success, name)
		require.Equal(t, 400, post.Status, name)
	})

	// Must NOT run in parallel
	// readAll => 0
	t.Run("readAll => 0", func(t *testing.T) {
		orig := readAll
		t.Cleanup(func() {
			readAll = orig
		})

		readAll = func(r io.Reader) ([]byte, error) {
			return []byte{}, nil
		}

		token, err := sec.FormJWT(regData.UserID, "session_id", regData.FirstName, regData.Email, testJwtSecret)
		require.NoError(t, err)

		body, err := json.Marshal(logic.TokenData{
			Token: token.RefreshToken,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlGetToken, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		GetToken(testJwtSecret).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err, name)
		require.False(t, post.Success, name)
		require.Equal(t, 400, post.Status, name)
	})

	// Must NOT run in parallel
	// tokenGet => error
	t.Run("tokenGet => error", func(t *testing.T) {
		token, err := sec.FormJWT(regData.UserID, "session_id", regData.FirstName, regData.Email, testJwtSecret)
		require.NoError(t, err)

		body, err := json.Marshal(logic.TokenData{
			Token: token.RefreshToken,
		})
		require.NoError(t, err)

		req, err := http.NewRequest("POST", urlGetToken, bytes.NewBuffer(body))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		orig := tokenGet
		t.Cleanup(func() {
			tokenGet = orig
		})

		tokenGet = func(refreshTokenString string, jwtSecret string) (*sec.Token, error) {
			return nil, fmt.Errorf("some_error")
		}

		GetToken(testJwtSecret).ServeHTTP(rr, req)

		post := &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err, name)
		require.False(t, post.Success, name)
		require.Equal(t, 500, post.Status, name)

		tokenGet = func(refreshTokenString string, jwtSecret string) (*sec.Token, error) {
			return nil, logic.ErrBadRefreshToken
		}

		GetToken(testJwtSecret).ServeHTTP(rr, req)

		post = &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err, name)
		require.False(t, post.Success, name)
		require.Equal(t, 400, post.Status, name)

		tokenGet = func(refreshTokenString string, jwtSecret string) (*sec.Token, error) {
			return nil, sec.ErrBadToken
		}

		GetToken(testJwtSecret).ServeHTTP(rr, req)

		post = &resp.Response{}
		err = json.NewDecoder(rr.Body).Decode(post)
		require.NoError(t, err, name)
		require.False(t, post.Success, name)
		require.Equal(t, 400, post.Status, name)
	})
}
