package ds

import (
	"context"
	"fmt"

	"github.com/gofrs/uuid"
)

/*
There will be no parallel tests, because we're switching function values on package level
and it can kill other tests.
*/

// CreateUser creates new user record in database. It returns new user ID or error.
//
// u.PasswordHash must already be hashed.
func (ds *DataStorageUsers) CreateUser(ctx context.Context, u UserData) (string, error) {
	tx, err := getTransaction(ds, ctx)
	if err != nil {
		return "", fmt.Errorf("[DS][CreateUser] %w", err)
	}

	id, err := uuid.NewV4()
	if err != nil {
		return "", fmt.Errorf("[DS][CreateUser] %w", err)
	}
	insertID := id.String()

	err = eexec(
		tx,
		`INSERT INTO user_data 
		(user_id, login, password_hash, first_name, last_name, email)
		VALUES ($1, $2, $3, $4, $5, $6);
		`, insertID, u.Login, u.PasswordHash, u.FirstName, u.LastName, u.Email,
	)
	if err != nil {
		err = getStorageError(err)

		rollbErr := erollback(tx)
		if rollbErr != nil {
			return "", fmt.Errorf("[DS][CreateUser] %w -> %w", err, rollbErr)
		}

		return "", fmt.Errorf("[DS][CreateUser] %w", err)
	}

	err = ecommit(tx)
	if err != nil {
		return "", fmt.Errorf("[DS][CreateUser] %w", err)
	}

	return insertID, err
}
