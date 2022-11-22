GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build: 
	go get -u golang.org/x/sys
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/vault-plugin-secrets-vra cmd/vault-plugin-secrets-vra/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

enable:
	vault secrets enable -path=mock-secrets vault-plugin-secrets-vra

disable:
	vault secrets disable vra-secrets/


clean:
	rm -f ./vault/plugins/vault-plugin-secrets-vra

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable
