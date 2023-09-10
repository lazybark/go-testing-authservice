package main

import (
	"log"

	"github.com/lazybark/go-testing-authservice/cfg"
	"github.com/lazybark/go-testing-authservice/pkg/api"
	"github.com/xlab/closer"
)

func main() {
	conf, err := cfg.ParseParams()
	if err != nil {
		log.Fatal(err)
	}

	srv, err := api.NewServer(conf)
	if err != nil {
		log.Fatal(err)
	}

	// Even if server dies during startup, we still might need to clear some resources.
	// Closer invoked only when process is being manually teminated. All the rest cases
	// are being handled by server internal routines.
	closer.Bind(func() {
		err := srv.Stop()
		if err != nil {
			log.Println(err)
		}
	})

	// Listen() will never return until Stop() called (internally upon error or by termination signal).
	err = srv.Listen()
	if err != nil {
		log.Fatal(err)
	}
}
