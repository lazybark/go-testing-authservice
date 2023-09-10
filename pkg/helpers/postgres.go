package helpers

import (
	"context"
	"fmt"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	genericContainer = testcontainers.GenericContainer
	mappedPort       = (testcontainers.Container).MappedPort
)

func NewTestContainerDatabase(ctx context.Context) (testcontainers.Container, string, error) {
	uid := "postgres"
	pwd := "postgres"
	db := "usersdb"
	req1 := testcontainers.ContainerRequest{
		Image:        "postgres:latest",
		ExposedPorts: []string{"5432/tcp"},
		AutoRemove:   true,
		Env: map[string]string{
			"POSTGRES_USER":     uid,
			"POSTGRES_PASSWORD": pwd,
			"POSTGRES_DB":       db,
		},
		WaitingFor: wait.ForListeningPort("5432/tcp"),
	}
	postgres, err := genericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req1,
		Started:          true,
	})
	if err != nil {
		return nil, "", fmt.Errorf("[NewTestContainerDatabase] %w", err)
	}

	p, err := mappedPort(postgres, ctx, "5432")
	if err != nil {
		return nil, "", fmt.Errorf("[NewTestContainerDatabase] %w", err)
	}

	return postgres, fmt.Sprintf("postgres://%s:%s@localhost:%d/%s", uid, pwd, p.Int(), db), nil
}
