GO ?= $(HOME)/.local/go/bin/go
VERSION ?= dev

.PHONY: all fmt test build image clean

all: fmt test

fmt:
	$(GO) fmt ./...
	$(GO) vet ./...

test:
	$(GO) test -count=1 ./...

build:
	$(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/scrivet ./cmd/scrivet
	@echo "binary: $$(du -h bin/scrivet | cut -f1)"

image:
	docker build --build-arg VERSION=$(VERSION) -t scrivet:$(VERSION) .

clean:
	rm -rf bin
