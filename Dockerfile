# Build.
#
# Static, CGO off. The point of a zero-dependency program is that the image can
# be a scratch image with one file in it — nothing to patch, nothing with a CVE
# feed, and an attacker who reaches code execution finds no shell to run.
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/quilzo ./cmd/quilzo
# Empty store and templates directories, carried into the final image so they
# exist there with the right owner. Docker seeds a named volume from whatever
# is at the mount point in the image, ownership included — and if nothing is
# there it creates the directory as root. This image runs as nonroot and has no
# shell, so that combination is unrecoverable from inside the container:
# `docker run -v store:/srv/store quilzo init` failed with "permission denied"
# and there was nothing in the image able to chown it.
#
# The reasoning was right and was applied to one of the two directories the
# quickstart uses. `quilzo demo` writes templates beside the working directory,
# so `-v tpl:/srv/templates` hit exactly the failure described above, in the
# v0.1.0 image, in the sequence the README told people to run.
RUN mkdir -p /out/store /out/templates

# Run.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/quilzo /usr/local/bin/quilzo
COPY --from=build --chown=65532:65532 /out/store /srv/store
# The working directory is also seeded, and both are chowned, and neither of
# those is decoration.
#
# nonroot is uid 65532, which is why these are chowned to the number rather
# than the name — there is no /etc/passwd lookup at COPY time. What matters is
# that a path exists in the image before anybody mounts a volume on it: Docker
# seeds an empty named volume from the image content at that path, ownership
# included, and a volume mounted where the image has nothing is created owned
# by root. This container runs as nonroot, so that one is unwritable. That is
# the whole of the "permission denied" a first-time user hits.
#
# `quilzo demo` writes templates next to the working directory rather than
# into the store, so /srv/templates has to be one of those seeded paths or the
# quickstart cannot keep what it just made.
COPY --from=build --chown=65532:65532 /out/templates /srv/templates
USER nonroot:nonroot
WORKDIR /srv
# There is deliberately no VOLUME instruction.
#
# `VOLUME /srv/store` was here and it was worse than useless. A declared volume
# that nobody mounts gets an anonymous one, so `-v mine:/srv` silently had its
# /srv/store shadowed by a throwaway that `--rm` deleted: the store looked
# empty every run, and `demo` reported success into a volume that no longer
# existed by the time `site` looked. Nothing warns about this. It cost the
# v0.1.0 image its own documented quickstart.
#
# Declaring a volume does not make data persist. Mounting one does, and only
# the person running the container can do that.
# 8080 the admin, 8081 the public site, 8082 the Telegram Mini App.
#
# Three because they have three different exposures, which is the whole reason
# they are three processes. Only one of these should ever be reachable from the
# internet without something in front of it, and it is not the first.
EXPOSE 8080 8081 8082
ENTRYPOINT ["/usr/local/bin/quilzo"]
CMD ["--root", "/srv/store", "serve", "--addr", "0.0.0.0:8080"]
