package cfg

import (
	"fmt"

	"github.com/alexflint/go-arg"
)

func ParseParams() (Config, error) {
	var c Config
	err := arg.Parse(&c)
	if err != nil {
		return c, fmt.Errorf("[CONFIG] %w", err)
	}

	return c, nil
}
