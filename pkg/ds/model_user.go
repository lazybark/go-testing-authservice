package ds

import (
	"database/sql"

	"github.com/lazybark/go-testing-authservice/pkg/helpers"
)

// UserData is the main user data struct.
//
// In a perfect world with more complicated model it would be better
// to split it into several structs and embed necessary ones.
type UserData struct {
	// UserID is UUID of the user
	UserID       string
	Login        string
	PasswordHash string
	FirstName    string
	LastName     string
	Email        string
	CreatedAt    sql.NullTime

	// BlockedLogin is set to true if user had too many failed login attempts.
	BlockedLogin bool
	BlockedAt    sql.NullTime

	// MustChangePassword is meant to be true if the password was compromised.
	MustChangePassword bool
}

// UserSession represents a session record in database
type UserSession struct {
	SessionID string
	UserID    string
	CreatedAt sql.NullTime
	ClosedAt  sql.NullTime
}

// UserFailedLoginAttempts represents a failed login attempt for specific user.
// It's not created if both login & password were incorrect.
type UserFailedLoginAttempt struct {
	AttemptID int // Don't need UUIDs here
	UserID    string
	CreatedAt sql.NullTime
	IPAddr    string
}

// UserPasswordRestoreCode would be used to init restore sequence.
// Right now there is no method to add it to DB.
type UserPasswordRestoreCode struct {
	CodeID     int // Don't need UUIDs here
	UserID     string
	Code       string
	CreatedAt  sql.NullTime
	ValidUntil sql.NullTime

	// UsedAt is meant to just mark codes for deletion.
	// Instant deletion is not user-friendly: if we have history for last hours,
	// we can notify user that the code is correct, but was used before
	// (so they might check another email in the inbox).
	UsedAt sql.NullTime
}

// GetRandomUserData returns randomly generated data (with UserID).
func GetRandomUserData() UserData {
	login := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	uid := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	sid := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	name := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))
	email := helpers.GenerateRandomStringFromSet(15, []byte(helpers.DigitsAndEnglish))

	return UserData{
		UserID:       uid,
		Login:        login,
		FirstName:    sid,
		LastName:     name,
		PasswordHash: "some_pwd_hash",
		Email:        email,
	}
}
