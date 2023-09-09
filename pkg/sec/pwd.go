package sec

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPasswordString returns password hash with provided cost (values between 4 & 31).
// It uses bcrypt which is more secure than regular pseudorandom numbers.
//
// If cost is < 4 or > 31, bcrypt.MinCost / bcrypt.DefaultCost will be used accordingly.
//
// Password must not be > 72 bytes (bytes != letters).
func HashPasswordString(pwd string, cost int) (string, error) {
	return HashPassword([]byte(pwd), cost)
}

// HashPassword returns password hash with provided cost (values between 4 & 31).
// It uses bcrypt which is more secure than regular pseudorandom numbers.
//
// If cost is < 4 or > 31, bcrypt.MinCost / bcrypt.DefaultCost will be used accordingly.
//
// Password must not be > 72 bytes (bytes != letters).
func HashPassword(pwd []byte, cost int) (string, error) {
	if cost < bcrypt.MinCost {
		cost = bcrypt.MinCost
	} else if cost > bcrypt.MaxCost {
		// DefaultCost is used here, because MaxCost is way too expensive for this
		// small project.
		cost = bcrypt.DefaultCost
	}

	hash, err := bcrypt.GenerateFromPassword(pwd, cost)
	if err != nil {
		return "", fmt.Errorf("[HashPassword] %w", err)
	}

	return string(hash), err
}

// ComparePasswords compares hash with password.
func ComparePasswordStrings(hashedPwd string, plainPwd string) (bool, error) {
	return ComparePasswordBytes([]byte(hashedPwd), []byte(plainPwd))
}

// ComparePasswordBytes compares hash with password.
func ComparePasswordBytes(byteHash []byte, plainPwdBytes []byte) (bool, error) {
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwdBytes)
	if err != nil {
		// Don't need to return this kind of error directly,
		// it will just make calling function more complicated.
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}

		return false, fmt.Errorf("[ComparePasswordBytes] %w", err)
	}

	return true, nil
}
