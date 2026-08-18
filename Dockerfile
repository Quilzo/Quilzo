# Build.
#
# Static, CGO off. The point of a zero-dependency program is that the image can
# be a scratch image with one file in it — nothing to patch, nothing with a CVE
# feed, and an attacker who reaches code execution finds no shell to run.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/quilzo ./cmd/quilzo

# Run.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/quilzo /usr/local/bin/quilzo
# nonroot is uid 65532. The store is a volume so content survives the
# container, which is the whole point of a content store.
USER nonroot:nonroot
WORKDIR /srv
VOLUME /srv/store
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/quilzo"]
CMD ["--root", "/srv/store", "serve", "--addr", "0.0.0.0:8080"]
