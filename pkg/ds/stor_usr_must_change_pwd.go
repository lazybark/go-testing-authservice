package ds

import (
	"context"
	"fmt"
)

// MustChangePassword sets user.MustChangePassword to true.
func (ds *DataStorageUsers) MustChangePassword(ctx context.Context, uid string) error {
	tx, err := getTransaction(ds, ctx)
	if err != nil {
		return fmt.Errorf("[DS][BlockUserLogin]: %w", err)
	}

	err = eexec(tx,
		`UPDATE user_data 
		SET must_change_password = true
		WHERE user_id = $1;
		`, uid,
	)
	if err != nil {
		err = getStorageError(err)

		rollbErr := erollback(tx)
		if rollbErr != nil {
			return fmt.Errorf("[DS][MustChangePassword] %w -> %w", err, rollbErr)
		}

		return fmt.Errorf("[DS][MustChangePassword] %w", err)
	}

	err = ecommit(tx)
	if err != nil {
		return fmt.Errorf("[DS][MustChangePassword] %w", err)
	}

	return nil
}
