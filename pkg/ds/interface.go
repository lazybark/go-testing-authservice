package ds

import (
	"context"
)

// UserWorker processes all actions on user database.
type UserWorker interface {
	// Connect inits connecton(s) with database.
	Connect(ctx context.Context, dsn string) error

	// Migrate creates all necessary tables & relations in database.
	Migrate(ctx context.Context) error

	//CreateUser creates new user record in database.
	CreateUser(ctx context.Context, u UserData) (uid string, err error)

	// GetUserByLogin returns user data if login exists or ErrNotExists
	// if it does not.
	GetUserByLogin(ctx context.Context, c string) (UserData, error)

	// AddUserSession creates new session record for the user.
	AddUserSession(ctx context.Context, uid string) (sid string, err error)

	// AddFailedLoginAttempt adds new failed attempt and returns
	// total number of attempts.
	AddFailedLoginAttempt(ctx context.Context, uid, ip string) (total int, err error)

	// BlockUserLogin sets user.BlockedLogin to true.
	BlockUserLogin(ctx context.Context, uid string) error

	// MustChangePassword sets user.MustChangePassword to true.
	MustChangePassword(ctx context.Context, uid string) error

	// Close closes the database connection.
	Close() error
}
