package logic

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lazybark/go-testing-authservice/pkg/ds"
	"github.com/lazybark/go-testing-authservice/pkg/sec"
)

var (
	comparePasswordStrings = sec.ComparePasswordStrings
	formJWT                = sec.FormJWT
	addUserSession         = UserLogicWorker.AddUserSession
	mustChangePassword     = UserLogicWorker.MustChangePassword
	blockUserLogin         = UserLogicWorker.BlockUserLogin
	addFailedLoginAttempt  = UserLogicWorker.AddFailedLoginAttempt
)

type UserLoginData struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// UserLogin returns JWT token if login creds are correct.
func UserLogin(data UserLoginData, uds UserLogicWorker, ip string, maxWrongLogins int, jwtSecret string) (*sec.Token, error) {
	if data.Login == "" || data.Password == "" {
		return nil, ErrEmptyFields
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Second*30))
	defer cancel()

	usr, err := uds.GetUserByLogin(ctx, data.Login)
	if err != nil {
		if errors.Is(err, ds.ErrNotExists) {
			return nil, ErrUnknownUser
		}
		return nil, fmt.Errorf("[UserLogin] %w", err)
	}

	if usr.BlockedLogin {
		return nil, ErrUserBlocked
	}

	// Check that credentials match
	match, err := comparePasswordStrings(usr.PasswordHash, data.Password)
	if err != nil {
		return nil, fmt.Errorf("[UserLogin] %w", err)
	}
	if !match {
		total, err := addFailedLoginAttempt(uds, ctx, usr.UserID, ip)
		if err != nil {
			return nil, fmt.Errorf("[UserLogin] %w", err)
		}

		if total >= maxWrongLogins {
			err = blockUserLogin(uds, ctx, usr.UserID)
			if err != nil {
				return nil, fmt.Errorf("[UserLogin] %w", err)
			}

			err = mustChangePassword(uds, ctx, usr.UserID)
			if err != nil {
				return nil, fmt.Errorf("[UserLogin] %w", err)
			}

			return nil, ErrUserBlocked
		}

		return nil, ErrUnknownUser
	}

	sid, err := addUserSession(uds, ctx, usr.UserID)
	if err != nil {
		return nil, fmt.Errorf("[UserLogin] %w", err)
	}

	t, err := formJWT(usr.UserID, sid, strings.Join([]string{usr.FirstName, usr.LastName}, " "), usr.Email, jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("[UserLogin] %w", err)
	}

	return t, nil
}
