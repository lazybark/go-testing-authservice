package helpers

import (
	"crypto/rand"
	"math/big"
)

var (
	randInt = rand.Int

	DigitsAndEnglish = []byte(`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`)
	DigitsAndSwedish = []byte(`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖabcdefghijklmnopqrstuvwxyzåäö`)
	DigitsAndGerman  = []byte(`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÜẞabcdefghijklmnopqrstuvwxyzäöüß`)
)

// GenerateRandomStringFromSet uses provided set of characters to generate random string.
// For tests use only.
func GenerateRandomStringFromSet(n int, charSet []byte) string {
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := randInt(rand.Reader, big.NewInt(int64(len(charSet))))
		if err != nil {
			return "" // Used only in tests
		}
		ret[i] = charSet[num.Int64()]
	}

	return string(ret)
}
