# A CMS that serves HTTP wants to be one static binary in a minimal image, which
# is the whole reason this is Go rather than Python. The final stage is scratch:
# no shell, no package manager, no libc — and, for a CMS specifically, nothing an
# attacker could upload and execute even if they found a write path.
#
# That last part is not incidental. WordPress's wp2shell kill chain ends in
# "upload a plugin"; an image with no interpreter and no shell has no terminal
# step to offer.

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/scrivet ./cmd/scrivet

# Checked by exit code, not by matching ldd's message: glibc says "not a dynamic
# executable" and musl says "Not a valid dynamic program". Matching the text
# fails the build on Alpine against a binary that is perfectly static, and a
# guard that fires on correct input gets deleted.
RUN if ldd /out/scrivet >/dev/null 2>&1; then \
      echo "binary is dynamically linked; it will not run on scratch" >&2; \
      ldd /out/scrivet >&2; exit 1; fi

FROM scratch
COPY --from=build /out/scrivet /scrivet
# Numeric, because scratch has no /etc/passwd to resolve a name against.
USER 65532:65532
VOLUME ["/site"]
WORKDIR /site
ENTRYPOINT ["/scrivet"]
CMD ["help"]
