package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/go-chi/chi"
	"github.com/lazybark/go-testing-authservice/cfg"
	pb "github.com/lazybark/go-testing-authservice/pkg/api/grpc"
	"github.com/lazybark/go-testing-authservice/pkg/ds"
	"github.com/lazybark/go-testing-authservice/pkg/helpers"
	"github.com/testcontainers/testcontainers-go"
	"google.golang.org/grpc"
)

// Server runs HTTP & gRPC servers and handles the responses.
type Server struct {
	httpListenAt string
	http         *http.Server
	grpcListenAt string
	grpc         *grpc.Server
	pb.UnimplementedUserWorkerServer

	jwtSecret      string
	maxWrongLogins int
	ds             ds.UserWorker            // Datastorage for user actions
	dbContainer    testcontainers.Container // Database container (if any was launched)

	muActive *sync.Mutex
	isActive bool

	closeChan chan (bool)
}

// NewServer reutrns new API server.
func NewServer(conf cfg.Config) (*Server, error) {
	s := &Server{
		httpListenAt:   conf.HTTPListenAt,
		grpcListenAt:   conf.GRPCListenAt,
		jwtSecret:      conf.JWTSecret,
		maxWrongLogins: 10,
		muActive:       &sync.Mutex{},
		closeChan:      make(chan bool),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create new pgsql container in Docker if there is no DSN in config.
	// If container created, but next steps break the sequence, s.Stop()
	// should be called in outer routine to stop & kill container.
	if conf.UserDatabaseDSN == "" {
		log.Println("No database config: creating new database instance")

		dbContainer, dsn, err := helpers.NewTestContainerDatabase(ctx)
		if err != nil {
			return nil, fmt.Errorf("[SRV][NEW] %w", err)
		}
		s.dbContainer = dbContainer
		conf.UserDatabaseDSN = dsn
	}

	stor := &ds.DataStorageUsers{}
	err := stor.Connect(ctx, conf.UserDatabaseDSN)
	if err != nil {
		log.Fatal(err)
	}
	s.ds = stor

	if conf.MigrateDatabase {
		log.Print("Migrating tables")
		err = s.ds.Migrate(ctx)
		if err != nil {
			return nil, fmt.Errorf("[SRV][NEW] %w", err)
		}
	}

	log.Println("Server ready")

	return s, nil
}

// Listen starts HTTP & gRPC servers. Must not be called twice without Stop() before the second one.
func (s *Server) Listen() error {
	log.Print("Starting server")

	s.muActive.Lock()
	if s.isActive {
		// Don't need to get inexpected bugs.
		return fmt.Errorf("[SRV][LISTEN] server is active, need to call Stop() before listen again")
	}
	s.isActive = true
	s.muActive.Unlock()

	// Now strating servers.
	// Using reverse-proxy like grpc-gateway or grpcweb.WrapServer is too complicated
	// for purposes of this task (i think).

	lis, err := net.Listen("tcp", s.grpcListenAt)
	if err != nil {
		return fmt.Errorf("[SRV][LISTEN] %w", err)
	}
	gs := grpc.NewServer()
	pb.RegisterUserWorkerServer(gs, s)
	s.grpc = gs

	go func() {
		err := gs.Serve(lis)
		if err != nil {
			log.Printf("[SRV][gRPC] %v", err)
		}

		// And now we have to stop all the rest
		err = s.Stop()
		if err != nil {
			log.Println(err)
		}
	}()
	log.Printf("gRPC server listening at %v", lis.Addr())

	srv := &http.Server{
		Handler: s.getChiRoutes(chi.NewRouter()),
		Addr:    s.httpListenAt,
	}
	s.http = srv

	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			// This case is irrelevant.
			if !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[SRV][HTTP] %v", err)
			}
		}

		// And now we have to stop all the rest
		err = s.Stop()
		if err != nil {
			log.Println(err)
		}

	}()
	log.Printf("HTTP server listening at %v", srv.Addr)

	<-s.closeChan

	return nil
}

// Stop stops HTTP, gRPC and SQL (if any) servers.
func (s *Server) Stop() error {
	s.muActive.Lock()
	defer s.muActive.Unlock()

	if !s.isActive {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First we stop accepting new conns.
	log.Print("Breaking connections")
	s.grpc.Stop()
	err := s.http.Shutdown(ctx)
	if err != nil {
		log.Println(err)
	}

	// Then DB connections (all should already return in the pool)
	log.Print("Breaking DB connections")
	err = s.ds.Close()
	if err != nil {
		log.Println(err)
	}

	// Stop & kill DB container if any
	log.Println("Stopping database instance")
	if s.dbContainer != nil {
		if err := s.dbContainer.Terminate(ctx); err != nil {
			log.Fatal("failed to stop database instance:", err)
		}
	}

	log.Println("Server stopped")

	s.isActive = false

	close(s.closeChan)

	return nil
}
