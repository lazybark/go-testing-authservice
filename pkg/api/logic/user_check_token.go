package logic

import (
	"errors"
	"fmt"

	"github.com/lazybark/go-testing-authservice/pkg/sec"
)

var checkToken = sec.CheckToken

type TokenData struct {
	Token string `json:"token"`
}

// TokenCheck returns string ("true"/"false") depending on token data.
func TokenCheck(token, jwtSecret string) (string, error) {
	valid, err := checkToken(token, jwtSecret)
	if err != nil {
		if !errors.As(err, new(sec.SecurityError)) {
			err = fmt.Errorf("[TokenCheck]%w", err)
		}
		return "false", err
	}

	return fmt.Sprint(valid), nil
}
