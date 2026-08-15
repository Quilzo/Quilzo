GO ?= $(HOME)/.local/go/bin/go
VERSION ?= dev

.PHONY: all fmt test build image sbom release clean

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

# The bill of materials is produced BY the binary, not alongside it.
#
# debug.ReadBuildInfo reads what actually went into the artefact, so asking the
# built binary describes the thing being shipped. Generating it from the source
# tree would describe what would be built now, and during an incident the
# question is what is deployed. The binary's own hash goes in the document, so
# the SBOM is tied to an artefact rather than to a version string.
sbom: build
	./bin/scrivet compliance sbom bin/scrivet.cdx.json
	@./bin/scrivet compliance crypto --json > bin/scrivet.crypto.json
	@echo "sbom:   bin/scrivet.cdx.json"
	@echo "crypto: bin/scrivet.crypto.json"

# Everything a release needs, produced from the artefact being released.
#
# Under the Cyber Resilience Act this has to exist before a vulnerability
# report does -- a report has to say what is affected -- and it has to be
# retained for ten years, which a release asset does for free.
release: test sbom
	@cd bin && sha256sum scrivet scrivet.cdx.json scrivet.crypto.json > SHA256SUMS
	@echo
	@echo "release $(VERSION)"
	@sed 's/^/  /' bin/SHA256SUMS

clean:
	rm -rf bin
