package logic

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lazybark/go-testing-authservice/pkg/ds"
	"github.com/lazybark/go-testing-authservice/pkg/sec"
)

var (
	hashPasswordString = sec.HashPasswordString // Placeholder for sec.HashPasswordString
	createUser         = UserLogicWorker.CreateUser
)

type UserRegData struct {
	Login     string `json:"login"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
}

// UserReg returns nil if registration data is correct.
func UserReg(data UserRegData, uds UserLogicWorker) error {
	if data.Login == "" || data.Password == "" || data.FirstName == "" || data.Email == "" {
		return ErrEmptyFields
	}

	pwdHash, err := hashPasswordString(data.Password, 10)
	if err != nil {
		return fmt.Errorf("[UserReg] %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Second*30))
	defer cancel()

	_, err = createUser(
		uds,
		ctx,
		ds.UserData{
			Login:        data.Login,
			FirstName:    data.FirstName,
			LastName:     data.LastName,
			PasswordHash: pwdHash,
			Email:        data.Email,
		})
	if err != nil {
		if errors.Is(err, ds.ErrDuplicateKey) {
			return ErrUserExists
		}
		return fmt.Errorf("[UserReg] %w", err)
	}

	return nil
}
