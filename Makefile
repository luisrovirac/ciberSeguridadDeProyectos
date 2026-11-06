# SecureProjects — common tasks. On Windows use Git Bash/MSYS make, or run the
# equivalent go commands shown in README.md.

BINARY  ?= secureprojects
PKG     := github.com/luisrovirac/ciberSeguridadDeProyectos
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X $(PKG)/internal/version.Version=$(VERSION) -X $(PKG)/internal/version.Commit=$(COMMIT) -X $(PKG)/internal/version.Date=$(DATE)
EXT     := $(if $(filter Windows_NT,$(OS)),.exe,)
TARGET  ?= .
ARGS    ?= --format table,json,sarif,html

.PHONY: all build test test-race cover lint fmt vet run tools-check db-update cross clean

all: lint test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)$(EXT) ./cmd/secureprojects

test:
	go test ./...

test-race:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run ./...

fmt:
	gofmt -w cmd internal

vet:
	go vet ./...

run: build
	./bin/$(BINARY)$(EXT) scan $(TARGET) $(ARGS)

tools-check: build
	./bin/$(BINARY)$(EXT) tools check

db-update: build
	./bin/$(BINARY)$(EXT) db update

cross:
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 ./cmd/secureprojects
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 ./cmd/secureprojects
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 ./cmd/secureprojects
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64 ./cmd/secureprojects
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe ./cmd/secureprojects

clean:
	rm -rf bin dist coverage.out secureprojects-report
