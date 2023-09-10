package ds

import (
	"context"
	"fmt"

	"github.com/gofrs/uuid"
)

// AddUserSession creates new session record for the user and returns session UUID.
func (ds *DataStorageUsers) AddUserSession(ctx context.Context, uid string) (sid string, err error) {
	tx, err := getTransaction(ds, ctx)
	if err != nil {
		return "", fmt.Errorf("[DS][AddUserSession] %w", err)
	}

	id, err := uuid.NewV4()
	if err != nil {
		return "", fmt.Errorf("[DS][AddUserSession] %w", err)
	}
	insertID := id.String()

	err = eexec(tx,
		`INSERT INTO user_sessions 
		(session_id, user_id)
		VALUES ($1, $2);
		`, insertID, uid,
	)
	if err != nil {
		err = getStorageError(err)

		rollbErr := erollback(tx)
		if rollbErr != nil {
			return "", fmt.Errorf("[DS][AddUserSession] %w -> %w", err, rollbErr)
		}

		return "", fmt.Errorf("[DS][AddUserSession] %w", err)
	}

	err = ecommit(tx)
	if err != nil {
		return "", fmt.Errorf("[DS][AddUserSession] %w", err)
	}

	return insertID, err
}
