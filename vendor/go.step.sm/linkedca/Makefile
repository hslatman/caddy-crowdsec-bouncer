# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
SRC=$(shell find . -type f -name '*.go')

all: lint generate test

ci: test

.PHONY: all ci

#########################################
# Build
#########################################

build: ;

#########################################
# Bootstrapping
#########################################

bootstra%:
	$Q curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v1.49.0
	$Q go install golang.org/x/vuln/cmd/govulncheck@latest
	$Q go install gotest.tools/gotestsum@v1.8.1

.PHONY: bootstrap

#########################################
# Test
#########################################

test:
	$Q $(GOFLAGS) gotestsum -- -coverpkg=./... -coverprofile=coverage.out -covermode=atomic ./...

race:
	$Q $(GOFLAGS) gotestsum -- -race ./...

.PHONY: test race

#########################################
# Linting
#########################################

fmt:
	$Q goimports -local github.com/golangci/golangci-lint -l -w $(SRC)

lint: SHELL:=/bin/bash
lint:
	$Q LOG_LEVEL=error golangci-lint run --config <(curl -s https://raw.githubusercontent.com/smallstep/workflows/master/.golangci.yml) --timeout=30m
	$Q govulncheck ./...

.PHONY: fmt lint

#########################################
# Generate
#########################################

generate:
	protoc --proto_path=. --go_out=. --go-grpc_out=. --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative provisioners.proto admin.proto config.proto eab.proto majordomo.proto policy.proto

.PHONY: generate
