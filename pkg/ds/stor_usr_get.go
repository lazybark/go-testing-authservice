package ds

import (
	"context"
	"fmt"
	"strings"
)

// GetUserByLogin returns user data if login exists or ErrNotExists if it does not.
func (ds *DataStorageUsers) GetUserByLogin(ctx context.Context, login string) (UserData, error) {
	var u UserData
	err := ds.pool.QueryRow(context.Background(),
		`SELECT 
		u.user_id, u.login, u.password_hash, u.first_name, 
		u.last_name, u.email, u.blocked_login, u.blocked_at, 
		u.must_change_password, u.created_at
		FROM user_data u 
		WHERE u.login = $1
		`, login,
	).Scan(
		&u.UserID, &u.Login, &u.PasswordHash, &u.FirstName,
		&u.LastName, &u.Email, &u.BlockedLogin, &u.BlockedAt,
		&u.MustChangePassword, &u.CreatedAt,
	)
	if err != nil {
		// Simple way of err checking, not gonna be present in prod or important project
		if strings.Contains(err.Error(), "no rows in result set") {
			return u, fmt.Errorf("[DS][GetUserByLogin]: %w", ErrNotExists)
		}

		return u, fmt.Errorf("[DS][GetUserByLogin]: %w", err)
	}

	return u, nil
}
