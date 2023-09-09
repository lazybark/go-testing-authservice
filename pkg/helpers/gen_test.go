package helpers

import (
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRandomStringFromSet(t *testing.T) {
	t.Run("DigitsAndEnglish", func(t *testing.T) {
		t.Parallel()

		var s string
		var last string

		for i := 1; i < 500; i += 10 {
			s = GenerateRandomStringFromSet(i, DigitsAndEnglish)
			assert.Equal(t, i, len(s))
			assert.False(t, strings.ContainsAny(s, "%&*/\\|	=+ "))
			assert.False(t, s == last)

			last = s
		}

	})

	t.Run("DigitsAndGerman", func(t *testing.T) {
		t.Parallel()

		var s string
		var last string

		for i := 1; i < 500; i += 10 {
			s = GenerateRandomStringFromSet(i, []byte(DigitsAndGerman))
			assert.Equal(t, i, len(s))
			assert.False(t, strings.ContainsAny(s, "%&*/\\|	=+ "))
			assert.False(t, s == last)

			last = s
		}

	})

	// Must NOT run in parallel
	t.Run("with err", func(t *testing.T) {
		var s string

		orig := randInt
		t.Cleanup(func() {
			randInt = orig
		})

		randInt = func(rand io.Reader, max *big.Int) (n *big.Int, err error) {
			return nil, fmt.Errorf("some_error")
		}

		s = GenerateRandomStringFromSet(50, []byte(DigitsAndGerman))
		assert.Empty(t, s)

	})
}
