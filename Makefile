# Whatever go is on PATH. This used to default to one contributor's home
# directory, which worked on exactly one machine and would have failed the
# release workflow on the first tag — where the only symptom is a job that
# cannot find a compiler.
GO ?= go
VERSION ?= dev

# The platforms a release carries. linux/arm64 is not optional any more: a
# large share of server capacity is Graviton and Ampere, and a CMS that ships
# amd64 only is one those operators cross-compile themselves.
PLATFORMS ?= linux/amd64 linux/arm64 darwin/arm64 darwin/amd64

.PHONY: all fmt test build build-all image sbom release clean

all: fmt test

fmt:
	$(GO) fmt ./...
	$(GO) vet ./...

test:
	$(GO) test -count=1 ./...

build:
	$(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/scrivet ./cmd/scrivet
	@echo "binary: $$(du -h bin/scrivet | cut -f1)"

# One binary per platform, named so a person downloading can tell which is
# which. CGO is off so these are genuinely static and genuinely
# cross-compiled — with it on, every target but the host needs a toolchain.
build-all:
	@mkdir -p bin
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath \
			-ldflags="-s -w -X main.version=$(VERSION)" \
			-o bin/scrivet-$$os-$$arch ./cmd/scrivet || exit 1; \
		echo "  $$os/$$arch  $$(du -h bin/scrivet-$$os-$$arch | cut -f1)"; \
	done

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
release: test sbom build-all
	@cd bin && sha256sum scrivet scrivet-* scrivet.cdx.json scrivet.crypto.json > SHA256SUMS
	@echo
	@echo "release $(VERSION)"
	@sed 's/^/  /' bin/SHA256SUMS

clean:
	rm -rf bin
