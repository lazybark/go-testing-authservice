.PHONY: RUN

RUN:
	go run ./cmd/server/. -s="some_secret" -m

TEST:
	go test ./... -coverprofile cover.out
	go tool cover -func=cover.out

LINT:
	golangci-lint run