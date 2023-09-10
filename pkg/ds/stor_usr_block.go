package ds

import (
	"context"
	"fmt"
)

// BlockUserLogin sets user.LoginBlocked to true and user.BlockedAt to now.
func (ds *DataStorageUsers) BlockUserLogin(ctx context.Context, uid string) error {
	tx, err := getTransaction(ds, ctx)
	if err != nil {
		return fmt.Errorf("[DS][BlockUserLogin] %w", err)
	}

	err = eexec(tx,
		`UPDATE user_data 
		SET blocked_login = true, blocked_at = CURRENT_TIMESTAMP
		WHERE user_id = $1;
		`, uid,
	)
	if err != nil {
		err = getStorageError(err)

		rollbErr := erollback(tx)
		if rollbErr != nil {
			return fmt.Errorf("[DS][BlockUserLogin] %w -> %w", err, rollbErr)
		}

		return fmt.Errorf("[DS][BlockUserLogin] %w", err)
	}

	err = ecommit(tx)
	if err != nil {
		return fmt.Errorf("[DS][BlockUserLogin] %w", err)
	}

	return nil
}
