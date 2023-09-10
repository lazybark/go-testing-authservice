package hthandlers

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	"github.com/lazybark/go-testing-authservice/pkg/api/logic"
	"github.com/lazybark/go-testing-authservice/pkg/api/resp"
	"github.com/lazybark/go-testing-authservice/pkg/ds"
	"github.com/lazybark/go-testing-authservice/pkg/sec"
)

var (
	unmarshal    = json.Unmarshal    // Placeholder for json.Unmarshal
	tokenCheck   = logic.TokenCheck  // Placeholder for logic.TokenCheck
	writeSuccess = resp.WriteSuccess // Placeholder for resp.WriteSuccess
	readAll      = io.ReadAll        // Placeholder for io.ReadAll

	userReg   = logic.UserReg   // Placeholder for logic.UserReg
	userLogin = logic.UserLogin // Placeholder for logic.UserLogin
	tokenGet  = logic.TokenGet  // Placeholder for logic.TokenGet
)

// Register returns http.HandlerFunc to process user registration.
func Register(uw ds.UserWorker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readAll(r.Body)
		if err != nil {
			resp.RespErrorBadRequest(w)

			return
		}

		if len(body) == 0 {
			resp.RespErrorBadRequest(w)

			return
		}

		var data logic.UserRegData
		err = unmarshal(body, &data)
		if err != nil {
			resp.RespErrorBadRequest(w)

			return
		}

		err = userReg(data, uw)
		if err != nil {
			if errors.As(err, new(logic.LogicError)) {
				resp.WriteError(w, 200, err)

				return
			}

			log.Println(err)
			resp.RespErrorInternal(w)

			return
		}

		resp.RespOK(w)
	}
}

// Login returns http.HandlerFunc to process user login.
func Login(jwtSecret string, maxWrongLogins int, uw ds.UserWorker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readAll(r.Body)
		if err != nil {
			resp.RespErrorBadRequest(w)

			return
		}

		if len(body) == 0 {
			resp.RespErrorBadRequest(w)

			return
		}

		var data logic.UserLoginData
		err = unmarshal(body, &data)
		if err != nil {
			resp.RespErrorBadRequest(w)

			return
		}

		t, err := userLogin(data, uw, r.RemoteAddr, maxWrongLogins, jwtSecret)
		if err != nil {
			if errors.As(err, new(logic.LogicError)) {
				resp.WriteError(w, 200, err)

				return
			}

			log.Println(err)
			resp.RespErrorInternal(w)

			return
		}

		err = writeSuccess(w, t)
		if err != nil {
			log.Println(err)

			return
		}
	}
}

// CheckToken returns http.HandlerFunc to process token check request.
func CheckToken(jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := chi.URLParam(r, "token")

		// Little hack for tests (will not be used in real app)
		if token == "" {
			token, _ = strings.CutPrefix(r.URL.Path, "/api/users/check_token/")
		}

		ok, err := tokenCheck(token, jwtSecret)
		if err != nil {
			if errors.As(err, new(logic.LogicError)) || errors.As(err, new(sec.SecurityError)) {
				resp.WriteError(w, 200, err)

				return
			}

			log.Println(err)
			resp.RespErrorInternal(w)

			return
		}

		err = writeSuccess(w, ok)
		if err != nil {
			log.Println(err)
			return
		}
	}
}

// GetToken returns http.HandlerFunc to process refresh token request.
func GetToken(jwtSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readAll(r.Body)
		if err != nil {
			resp.RespErrorBadRequest(w)

			return
		}

		if len(body) == 0 {
			resp.RespErrorBadRequest(w)

			return
		}

		var data logic.TokenData
		err = unmarshal(body, &data)
		if err != nil {
			resp.RespErrorBadRequest(w)

			return
		}

		t, err := tokenGet(data.Token, jwtSecret)
		if err != nil {
			if errors.As(err, new(logic.LogicError)) || errors.As(err, new(sec.SecurityError)) {
				resp.WriteError(w, 200, err)

				return
			}

			log.Println(err)
			resp.RespErrorInternal(w)

			return
		}

		err = writeSuccess(w, t)
		if err != nil {
			log.Println(err)

			return
		}
	}
}
