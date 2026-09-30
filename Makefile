# Whatever go is on PATH. This used to default to one contributor's home
# directory, which worked on exactly one machine and would have failed the
# release workflow on the first tag — where the only symptom is a job that
# cannot find a compiler.
GO ?= go
VERSION ?= dev

# The platforms a release carries. linux/arm64 is not optional any more: a
# large share of server capacity is Graviton and Ampere, and a CMS that ships
# amd64 only is one those operators cross-compile themselves.
# Windows carries a .exe suffix or it is not a program anybody can run.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64


all: fmt test

fmt:
	$(GO) fmt ./...
	$(GO) vet ./...

test:
	$(GO) test -count=1 ./...

build:
	$(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/quilzo ./cmd/quilzo
	@echo "binary: $$(du -h bin/quilzo | cut -f1)"

# One binary per platform, named so a person downloading can tell which is
# which. CGO is off so these are genuinely static and genuinely
# cross-compiled — with it on, every target but the host needs a toolchain.
build-all:
	@mkdir -p bin
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath \
			-ldflags="-s -w -X main.version=$(VERSION)" \
			-o bin/quilzo-$$os-$$arch$$ext ./cmd/quilzo || exit 1; \
		echo "  $$os/$$arch  $$(du -h bin/quilzo-$$os-$$arch$$ext | cut -f1)"; \
	done

# The GNU Coding Standards ask for these targets by name, and the reason is
# packaging: a distribution's build recipe runs `make && make check && make
# install DESTDIR=...` and does not read this file first. Missing one means a
# packager writes a bespoke recipe, and a bespoke recipe is one that breaks.
#
# prefix, DESTDIR and the exec/bin split are the standard variables. There is no
# ./configure to set them, because there is nothing to detect: no optional
# libraries, no feature switches, and go.mod has no require block.
prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
DESTDIR ?=
INSTALL ?= install
INSTALL_PROGRAM ?= $(INSTALL) -m 0755

install: build
	$(INSTALL) -d "$(DESTDIR)$(bindir)"
	$(INSTALL_PROGRAM) bin/quilzo "$(DESTDIR)$(bindir)/quilzo"
	@echo "installed $(DESTDIR)$(bindir)/quilzo"

uninstall:
	rm -f "$(DESTDIR)$(bindir)/quilzo"

# check is the standard name for what this project already spelled `test`.
# Both, because the muscle memory here is `make test` and a packager's is
# `make check`, and one of them being wrong is a build that looks broken.
check: test

# A source archive, from the committed tree rather than the working one — so a
# release tarball cannot carry somebody's local store or an editor backup.
dist:
	@git archive --format=tar.gz --prefix=quilzo-$(VERSION)/ \
		-o quilzo-$(VERSION).tar.gz HEAD
	@echo "quilzo-$(VERSION).tar.gz  $$(du -h quilzo-$(VERSION).tar.gz | cut -f1)"

distclean: clean
	rm -f quilzo-*.tar.gz

image:
	docker build --build-arg VERSION=$(VERSION) -t quilzo:$(VERSION) .

# The bill of materials is produced BY the binary, not alongside it.
#
# debug.ReadBuildInfo reads what actually went into the artefact, so asking the
# built binary describes the thing being shipped. Generating it from the source
# tree would describe what would be built now, and during an incident the
# question is what is deployed. The binary's own hash goes in the document, so
# the SBOM is tied to an artefact rather than to a version string.
sbom: build
	./bin/quilzo compliance sbom bin/quilzo.cdx.json
	@./bin/quilzo compliance crypto --json > bin/quilzo.crypto.json
	@echo "sbom:   bin/quilzo.cdx.json"
	@echo "crypto: bin/quilzo.crypto.json"

# Everything a release needs, produced from the artefact being released.
#
# Under the Cyber Resilience Act this has to exist before a vulnerability
# report does -- a report has to say what is affected -- and it has to be
# retained for ten years, which a release asset does for free.
release: test sbom build-all
	@cd bin && sha256sum quilzo quilzo-* quilzo.cdx.json quilzo.crypto.json > SHA256SUMS
	@echo
	@echo "release $(VERSION)"
	@sed 's/^/  /' bin/SHA256SUMS

clean:
	rm -rf bin

.PHONY: all fmt test check build build-all image sbom release \
	install uninstall dist clean distclean
