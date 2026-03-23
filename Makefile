.PHONY: build test

build:
	go build -o bin/ ./cmd/retrieval-client ./cmd/sp-proxy

test:
	go test ./...
