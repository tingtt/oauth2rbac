GO ?= go
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)
MODULE_NAME ?= $(shell head -n1 go.mod | cut -f 2 -d ' ')
PARALLELS ?= 10

.PHONY: test
test:
	$(GO) test ./... -parallel $(PARALLELS)

.PHONY: build
build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -o proxy cmd/proxy/main.go

.PHONY: build-docker
build-docker:
	docker build -t oauth2rbac --build-arg GO_ENTRYPOINT='cmd/proxy/main.go' .
