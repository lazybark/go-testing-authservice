package helpers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRandomStringFromSet(t *testing.T) {
	var s string
	var last string

	for i := 1; i < 500; i += 10 {
		s = GenerateRandomStringFromSet(i, DigitsAndEnglish)
		assert.Equal(t, i, len(s))
		assert.False(t, strings.ContainsAny(s, "%&*/\\|	=+ "))
		assert.False(t, s == last)

		last = s
	}

	for i := 1; i < 500; i += 10 {
		s = GenerateRandomStringFromSet(i, []byte(DigitsAndGerman))
		assert.Equal(t, i, len(s))
		assert.False(t, strings.ContainsAny(s, "%&*/\\|	=+ "))
		assert.False(t, s == last)

		last = s
	}
}
