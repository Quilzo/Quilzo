# Build.
#
# Static, CGO off. The point of a zero-dependency program is that the image can
# be a scratch image with one file in it — nothing to patch, nothing with a CVE
# feed, and an attacker who reaches code execution finds no shell to run.
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY . .
# The version the binary reports, passed in by the release workflow.
#
# This was missing while the workflow passed `--build-arg VERSION=v0.2.0`, and
# a build argument nothing declares is discarded without a word. So every image
# ever published carried a binary that answered "dev" to `--version`, while the
# OCI label beside it said the real number: the artefact and its label
# disagreed, and only the label was checked.
#
# It matters more here than it would elsewhere. This program's own argument for
# generating its bill of materials from the binary rather than from the source
# tree is that the binary knows what it is -- so `quilzo compliance sbom` run
# inside the image produced a document naming version "dev", which is the exact
# failure that reasoning exists to prevent.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" -o /out/quilzo ./cmd/quilzo
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
# And the audit log's, for the writer the reference compose runs as uid
# 65533 (deploy/compose.yaml, logd): owned by it, readable by nonroot's group
# and nobody else, so a volume seeded from it is the writer's to write.
RUN mkdir -p /out/audit && chmod 0750 /out/audit

# Run.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/quilzo /usr/local/bin/quilzo
# The licence and the notices of the third-party material in the binary go
# with every copy of it.
COPY --from=build /src/LICENSE /src/NOTICE /usr/share/doc/quilzo/
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
COPY --from=build --chown=65533:65532 /out/audit /srv/audit
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
# 8080 the admin, 8081 the public site.
#
# Two because they have two different exposures, which is the whole reason
# they are two processes. Only one of these should ever be reachable from the
# internet without something in front of it, and it is not the first.
EXPOSE 8080 8081

# The store is named in the entrypoint, not in the command.
#
# It was in the command, and the command is what `docker run IMAGE init` and
# `docker compose run --rm admin init` replace. So the one command that sets a
# store up was the one that lost where it goes: Quilzo looked for .quilzo in
# the working directory, which a read-only container refuses ("mkdir .quilzo:
# read-only file system") and a writable one keeps in its own layer until
# --rm deletes it. Every step of the reference compose's setup failed that
# way. Here, whatever command is given runs against /srv/store, the path the
# volume is mounted on; a --root given after it still wins, because the last
# one does, so `IMAGE --root /srv/store init` means what it always meant.
ENTRYPOINT ["/usr/local/bin/quilzo", "--root", "/srv/store"]
CMD ["serve", "--addr", "0.0.0.0:8080"]
