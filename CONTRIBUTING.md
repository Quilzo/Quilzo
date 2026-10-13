# Contributing to Quilzo

This project is looking for maintainers, not just patches. If you want commit
access, the path is written down in [GOVERNANCE.md](GOVERNANCE.md) and it is
short.

## Try it first, in about two minutes

You need Go 1.27 or later and nothing else. There are no dependencies to fetch.

```bash
git clone https://github.com/quilzo/quilzo   # or your fork
cd quilzo
go build -o quilzo ./cmd/quilzo

mkdir /tmp/try && cd /tmp/try
../quilzo init      # wherever you put the binary
../quilzo demo      # a complete example application
```

`quilzo demo` installs Marginalia, a small paper shop: products as structured
records, a catalogue a machine can read, claims that have to be substantiated
before they publish, a sale that starts on its own, and a wholesale enquiry form
the public server cannot read back.

### Getting a token, which you need for anything that writes

Quilzo has no default password and creates no default account. Nothing is
"admin" until you say so, and there is no state where an unconfigured install is
reachable with a known credential.

Two commands. The order matters, and the token is shown once:

```bash
../quilzo auth grant you admin          # "you" is any name you like
../quilzo token issue laptop --principal you --role admin
```

That prints a secret starting `qz_`, once. Save it where the command line looks
first, readable only by you:

```bash
mkdir -p ~/.quilzo && umask 077 && printf '%s\n' 'qz_…' > ~/.quilzo/token
```

`QUILZO_TOKEN` in the environment works too, and is looked at after the file. The
file is preferred because every program you start inherits your environment,
including an agent you are letting drive the command line.

Then start both processes:

```bash
../quilzo serve --addr 127.0.0.1:8080                                # admin
../quilzo site  --addr 127.0.0.1:8081 --base-url http://127.0.0.1:8081   # site
```

Open `http://127.0.0.1:8080` for the admin and `http://127.0.0.1:8081` for the
site. The manual is at [quilzo.github.io](https://quilzo.github.io), and every
screen's Help link opens the guide for that screen.

Things worth trying, because they are the parts that are hard to believe:

| Try | What it shows |
|---|---|
| `/catalogue.json` on the site | Everything for sale, as a shopping agent reads it |
| `/ranges?range=archive` | A declared listing with a parameter, filtered per request |
| `/sale` | 404s until 24 November: the window is checked when the page is asked for, not by a job |
| `quilzo brand check` | Every claim, and what backs it up; take `guarantee_terms` off the brass pen and publishing stops |
| Remove a page the menu points at | Refused, naming the menu entry |
| `quilzo verify` | Every object re-hashed against the id it is filed under |
| `quilzo rollback` | Instant, because it is a pointer move |

Token notes: `--role` may be narrower than the principal (a token can carry less
than the person holding it, never more), `--read-only` refuses every write
whatever the role, `--ttl` sets expiry, and `quilzo token revoke ID` kills one
immediately — revocation is checked on use, not only at issue.

## Building and testing

```bash
make test                  # the whole suite, over four thousand tests
make build                 # one binary for this platform
make build-all             # linux, darwin and windows, each on amd64 and arm64
go run cmd/gofmt -l .      # must print nothing
go vet ./...               # must print nothing
```

`go run cmd/gofmt` is the gofmt of the toolchain go.mod names. An older gofmt on
your PATH can call a file clean that CI then rejects.

CI runs formatting and vet, a build for every released platform, the published
injection figure, govulncheck against the toolchain, the full suite, and a
container build. All of them must pass, and code scanning (CodeQL) must find
nothing new. There is no separate lint step and no configuration to learn.

## The one rule that will surprise you

**No third-party dependencies.** `go.mod` has no `require` block, and a test fails
if one appears.

This is not preference. A CMS is the highest-value place in an infrastructure to
put something, and every transitive dependency is somebody else's release
process running inside yours. The merkle store, the template language, the CID
encoder, the OIDC client and the HTML tokeniser are all written here, and each
is smaller than the library it replaces because it does only what this needs.

If you genuinely need something the standard library does not have, open an issue
before writing the code. The answer is usually "write the part we need", and
sometimes it is "that feature is not worth a dependency" — both are faster to
hear before you have written a patch.

## How code is reviewed here

Three things get a patch returned, and they are worth knowing in advance.

**Tests that assert structure, not just behaviour.** The recurring failure in
this project has never been broken code — it has been a capability present in
one interface and absent from another. So the suite walks the source and fails
on omissions: every command declares its privilege, every capability is reachable
from the CLI, the browser and the agent interface or has a written reason it is
not, every write surface consults the type gate. If you add a capability, it
needs to be reachable from all three or carry a written reason.

**Comments that say why, not what.** The code says what. A comment earns its
place by recording the reasoning, the alternative that was rejected, or the bug
that made the current shape necessary. Comments restating the line below them
get deleted in review.

**Refusing rather than warning.** When the tool detects a problem it stops and
explains, and the override is explicit and recorded. A warning nobody reads is a
feature nobody has.

## Signing off

Every commit in a pull request needs a `Signed-off-by` line:

```bash
git commit -s -m "your message"
```

That certifies the [Developer Certificate of Origin](https://developercertificate.org/):
you wrote it or have the right to submit it under the project's licence.

Contributions are licensed under the [Apache License 2.0](LICENSE), as its
section 5 provides. There is no contributor licence agreement and no copyright
assignment: your copyright stays yours.

## Where to start

Issues labelled `good first issue` are scoped so that the hard part is
understanding the codebase rather than the problem. `help wanted` is everything
else that is ready to be picked up.

If you want to do something larger, open an issue describing it first. Not for
permission — so that two people do not build the same thing, and so anybody who
has already thought about it can tell you what they found.

## What this project is not looking for

- Dependencies, as above.
- A JavaScript build step. The admin is server-rendered. Its one script is
  first-party, allowed per page by a nonce, and every screen works with it
  switched off; a security dashboard that needs a framework to tell you a token
  is world-readable has the dependency the wrong way round.
- Features that add a query language over content. The absence of one is what
  removes an entire vulnerability class.
- Anything that makes a control easier to skip. Overrides are fine when they are
  explicit and recorded; a flag that turns a gate off quietly is not.
