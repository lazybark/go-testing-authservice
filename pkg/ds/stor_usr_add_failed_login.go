package ds

import (
	"context"
	"fmt"
)

// AddFailedLoginAttempt adds new failed attempt and returns total number of attempts.
func (ds *DataStorageUsers) AddFailedLoginAttempt(ctx context.Context, uid, ip string) (int, error) {
	tx, err := getTransaction(ds, ctx)
	if err != nil {
		return 0, fmt.Errorf("[DS][AddFailedLoginAttempt]: %w", err)
	}

	err = eexec(tx,
		`INSERT INTO user_failed_login_attempts 
		(user_id, ip_addr)
		VALUES ($1, $2);
		`, uid, ip,
	)
	if err != nil {
		err = getStorageError(err)

		rollbErr := erollback(tx)
		if rollbErr != nil {
			return 0, fmt.Errorf("[DS][AddFailedLoginAttempt] %w -> %w", err, rollbErr)
		}

		return 0, fmt.Errorf("[DS][AddFailedLoginAttempt] %w", err)
	}

	err = ecommit(tx)
	if err != nil {
		return 0, fmt.Errorf("[DS][AddFailedLoginAttempt] %w", err)
	}

	var total int
	err = ds.pool.QueryRow(
		ctx,
		`SELECT count(*) 
		FROM user_failed_login_attempts a 
		WHERE a.user_id = $1
		`, uid).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("[DS][AddFailedLoginAttempt] %w", err)
	}

	return total, err
}
