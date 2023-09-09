package sec

// SecurityError is returned by package functions in cases when error needs to be determined by external code.
type SecurityError string

func (s SecurityError) Error() string {
	return string(s)
}

const (
	// ErrBadToken is returned if JWT token is... bad
	ErrBadToken SecurityError = "bad_token"
)
