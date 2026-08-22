# Build.
#
# Static, CGO off. The point of a zero-dependency program is that the image can
# be a scratch image with one file in it — nothing to patch, nothing with a CVE
# feed, and an attacker who reaches code execution finds no shell to run.
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/quilzo ./cmd/quilzo
# An empty store directory, carried into the final image so it exists there
# with the right owner. Docker seeds a named volume from whatever is at the
# mount point in the image, ownership included — and if nothing is there it
# creates the directory as root. This image runs as nonroot and has no shell,
# so that combination is unrecoverable from inside the container: `docker run
# -v store:/srv/store quilzo init` failed with "permission denied" and there
# was nothing in the image able to chown it.
RUN mkdir -p /out/store

# Run.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/quilzo /usr/local/bin/quilzo
COPY --from=build --chown=65532:65532 /out/store /srv/store
# nonroot is uid 65532, which is why the store directory above is chowned to
# that number rather than to a name — there is no /etc/passwd lookup at COPY
# time. The store is a volume so content survives the container, which is the
# whole point of a content store.
USER nonroot:nonroot
WORKDIR /srv
VOLUME /srv/store
# 8080 the admin, 8081 the public site, 8082 the Telegram Mini App.
#
# Three because they have three different exposures, which is the whole reason
# they are three processes. Only one of these should ever be reachable from the
# internet without something in front of it, and it is not the first.
EXPOSE 8080 8081 8082
ENTRYPOINT ["/usr/local/bin/quilzo"]
CMD ["--root", "/srv/store", "serve", "--addr", "0.0.0.0:8080"]
