package ds

import "regexp"

// StorageError implements error to avoid using driver-specific errors
// and mitigate error comparing problems when switching database types.
type StorageError string

func (e StorageError) String() string {
	return string(e)
}

func (e StorageError) Error() string {
	return e.String()
}

const (
	// ErrMigratingTable is returned when table exists or has error in SQL code.
	ErrMigratingTable StorageError = "error migrating table"

	// ErrMigratingRelations is returned when relation exists or has error in SQL code.
	ErrMigratingRelations StorageError = "error migrating relations"

	// ErrDuplicateKey is returned when request is violating unique constraint.
	ErrDuplicateKey StorageError = "enitity exists"

	// ErrNotExists is returned when desired object does not exist.
	ErrNotExists StorageError = "entity not exists"

	// ErrRelationViolation is returned when request is violating relation constraints.
	ErrRelationViolation StorageError = "relation constraint violation"
)

// Reckless, but fine working way of checking with some non-friendly drivers.
const (
	patternErrViolation = `SQLSTATE 23503`
	patternErrExists    = "SQLSTATE 23505"
)

var (
	exp = regexp.MustCompile("SQLSTATE ([0-9]*)")

	// errs is the list of errors in PgSQL, that matter to this app.
	errs = map[string]StorageError{
		"SQLSTATE 23503": ErrRelationViolation,
		"SQLSTATE 23505": ErrDuplicateKey,
	}
)

// getStorageError returns StorageError from list of known errors
// or creates new StorageError from e.
func getStorageError(e error) StorageError {
	str := e.Error()
	errCode := exp.FindString(str)
	if code, ok := errs[errCode]; ok {
		return code
	}

	return StorageError(str)
}
