PKG := github.com/devspotai/sharedkit

.PHONY: tidy lint test
tidy:
	@go mod tidy

lint:
	@golangci-lint run ./...

test:
	@go test ./... -coverprofile=coverage.out

ci: tidy lint test