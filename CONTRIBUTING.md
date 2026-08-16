# Contributing to Lithoform

This project is looking for maintainers, not just patches. If you want commit
access, the path is written down in [GOVERNANCE.md](GOVERNANCE.md) and it is
short.

## The name, so it does not confuse you

The project is **Lithoform**. The command is **`scrivet`**, which was the
working name and stayed as the binary — the same way Chromium ships `chrome`.
Anywhere you see `scrivet` in a command, a path, or a Go import, that is
deliberate and not a leftover.

## Try it first, in about two minutes

You need Go 1.24 or later and nothing else. There are no dependencies to fetch.

```bash
git clone https://github.com/lithoform/lithoform   # or your fork
cd lithoform
go build -o scrivet ./cmd/scrivet

mkdir /tmp/try && cd /tmp/try
../scrivet init      # wherever you put the binary
../scrivet demo      # a complete example application
```

`scrivet demo` installs Gram — a photo-sharing site with a feed over structured
records, an explore page with a working filter, profiles under a content type,
stories that stop being served on a date, and a message box.

### Getting a token, which you need for anything that writes

Lithoform has no default password and creates no default account. Nothing is
"admin" until you say so, and there is no state where an unconfigured install is
reachable with a known credential.

Two commands. The order matters, and the token is shown once:

```bash
../scrivet auth grant you admin          # "you" is any name you like
../scrivet token issue laptop --principal you --role admin
```

That prints a secret starting `scv_`. Put it in the environment:

```bash
export SCRIVET_TOKEN=scv_…
```

Then start both processes:

```bash
../scrivet serve --addr 127.0.0.1:8080                                # admin
../scrivet site  --addr 127.0.0.1:8081 --base-url http://127.0.0.1:8081   # site
```

Open `http://127.0.0.1:8080` for the admin and `http://127.0.0.1:8081` for the
site. The admin's manual is at `/docs` and every screen's Help link points at
its own section.

Things worth trying, because they are the parts that are hard to believe:

| Try | What it shows |
|---|---|
| `/explore?topic=travel` on the site | A declared query with a typed parameter, filtered per request |
| `/stories/sol-rooftop` | 404s until September — the window is checked when the page is asked for, not by a job |
| Remove a page the menu points at | Refused, naming the menu entry |
| `scrivet verify` | Every object re-hashed against the id it is filed under |
| `scrivet rollback` | Instant, because it is a pointer move |

Token notes: `--role` may be narrower than the principal (a token can carry less
than the person holding it, never more), `--read-only` refuses every write
whatever the role, `--ttl` sets expiry, and `scrivet token revoke ID` kills one
immediately — revocation is checked on use, not only at issue.

## Building and testing

```bash
make test        # the whole suite, about 1400 tests
make build       # one binary for this platform
make build-all   # linux/amd64, linux/arm64, darwin/amd64, darwin/arm64
gofmt -l .       # must print nothing
go vet ./...     # must print nothing
```

CI runs formatting, vet, the full suite, and a container build. All four must
pass. There is no separate lint step and no configuration to learn.

## The one rule that will surprise you

**No third-party dependencies.** `go.mod` has no `require` block and CI fails if
one appears.

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

## Signing off: DCO, not a CLA

Every commit needs a `Signed-off-by` line:

```bash
git commit -s -m "your message"
```

That certifies the [Developer Certificate of Origin](https://developercertificate.org/)
— you wrote it or have the right to submit it under the project's licence.

**There is deliberately no contributor licence agreement.** A CLA would assign
your copyright to whoever holds the project, and that party could then relicense
the whole thing — including away from AGPL. Under a DCO, copyright stays with
each contributor, so no single person can ever take Lithoform closed or move it to
a permissive licence. The guarantee the AGPL makes to users is only as strong as
the impossibility of quietly revoking it, and distributed copyright is what makes
it impossible.

This matters more than usual here, because the plan is to hand this project to a
community. A project one person can relicense is a project one person still owns.

### About the licence, honestly

Lithoform is **AGPL-3.0-or-later**. Two consequences worth knowing before you
spend time:

- If you run a modified Lithoform as a service for other people, those people can
  have your source. That is the point of choosing it.
- **Some employers forbid contributing to AGPL projects.** Google's open source
  policy is explicit about this and others follow it. Please check before
  contributing on work time or from a work account. This is a real cost of the
  licence and pretending otherwise wastes your time, not ours.

## Where to start

Issues labelled `good first issue` are scoped so that the hard part is
understanding the codebase rather than the problem. `help wanted` is everything
else that is ready to be picked up.

If you want to do something larger, open an issue describing it first. Not for
permission — so that two people do not build the same thing, and so anybody who
has already thought about it can tell you what they found.

## What this project is not looking for

- Dependencies, as above.
- A JavaScript build step. The admin is server-rendered and its CSP forbids
  script entirely; a security dashboard that needs a framework to tell you a
  token is world-readable has the dependency the wrong way round.
- Features that add a query language over content. The absence of one is what
  removes an entire vulnerability class.
- Anything that makes a control easier to skip. Overrides are fine when they are
  explicit and recorded; a flag that turns a gate off quietly is not.
