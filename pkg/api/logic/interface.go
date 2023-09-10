package logic

import (
	"context"

	"github.com/lazybark/go-testing-authservice/pkg/ds"
)

// UserLogicWorker processes all user actions
type UserLogicWorker interface {
	//CreateUser creates new user record in database.
	CreateUser(ctx context.Context, u ds.UserData) (uid string, err error)

	// GetUserByLogin returns user data if login exists or ErrNotExists
	// if it does not.
	GetUserByLogin(ctx context.Context, c string) (ds.UserData, error)

	// AddUserSession creates new session record for the user.
	AddUserSession(ctx context.Context, uid string) (sid string, err error)

	// AddFailedLoginAttempt adds new failed attempt and returns
	// total number of attempts.
	AddFailedLoginAttempt(ctx context.Context, uid, ip string) (total int, err error)

	// BlockUserLogin sets user.BlockedLogin to true.
	BlockUserLogin(ctx context.Context, uid string) error

	// MustChangePassword sets user.MustChangePassword to true.
	MustChangePassword(ctx context.Context, uid string) error
}
