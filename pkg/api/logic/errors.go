package logic

// LogicError is returned to end user when there are errors with token / request data.
type LogicError string

func (e LogicError) Error() string {
	return string(e)
}

const (
	ErrUserExists      LogicError = "user_exists"
	ErrEmptyFields     LogicError = "empty_fields"
	ErrUnknownUser     LogicError = "wrong_credentials"
	ErrUserBlocked     LogicError = "user_blocked"
	ErrBadRefreshToken LogicError = "bad_refresh_token"
	ErrNotRefreshToken LogicError = "wrong_token_type"
)
