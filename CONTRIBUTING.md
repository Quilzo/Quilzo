# Contributing to Quilzo

This project is looking for maintainers, not just patches. If you want commit
access, the path is written down in [GOVERNANCE.md](GOVERNANCE.md) and it is
short.

## The name, if you are reading older material

The project and the command are both **Quilzo**. Earlier releases shipped the
binary as `scrivet`, an old working name, and that is gone: the command, the
store directory, the environment variables, the token prefix and the agent
tool names are all `quilzo` now. There is no compatibility path — a store
created by the old binary is not found by this one, and tokens have to be
reissued. Pre-1.0, one name is worth more than a migration shim nobody would
delete later.

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

`quilzo demo` installs Gram — a photo-sharing site with a feed over structured
records, an explore page with a working filter, profiles under a content type,
stories that stop being served on a date, and a message box.

### Getting a token, which you need for anything that writes

Quilzo has no default password and creates no default account. Nothing is
"admin" until you say so, and there is no state where an unconfigured install is
reachable with a known credential.

Two commands. The order matters, and the token is shown once:

```bash
../quilzo auth grant you admin          # "you" is any name you like
../quilzo token issue laptop --principal you --role admin
```

That prints a secret starting `qz_`. Put it in the environment:

```bash
export QUILZO_TOKEN=qz_…
```

Then start both processes:

```bash
../quilzo serve --addr 127.0.0.1:8080                                # admin
../quilzo site  --addr 127.0.0.1:8081 --base-url http://127.0.0.1:8081   # site
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
| `quilzo verify` | Every object re-hashed against the id it is filed under |
| `quilzo rollback` | Instant, because it is a pointer move |

Token notes: `--role` may be narrower than the principal (a token can carry less
than the person holding it, never more), `--read-only` refuses every write
whatever the role, `--ttl` sets expiry, and `quilzo token revoke ID` kills one
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

## Signing off: DCO, and a CLA

Every commit needs a `Signed-off-by` line:

```bash
git commit -s -m "your message"
```

That certifies the [Developer Certificate of Origin](https://developercertificate.org/)
— you wrote it or have the right to submit it under the project's licence.

**Code contributions also need a contributor licence agreement.** See
[CLA.md](CLA.md), which is the whole story: which Harmony agreement, which
options, what it costs you, and the two things about it that are still
unfinished.

The short version. Quilzo is dual-licensed — AGPL-3.0-or-later or a commercial
licence, at the user's choice ([LICENSING.md](LICENSING.md)). A DCO grants the
right to submit under the project's licence and nothing beyond it, so it cannot
support offering somebody else's contribution under commercial terms. The
agreement supplies that, and two things bound it: **your copyright stays yours**
— it is Harmony's licence variant, not the assignment one — and whatever you
contribute is *also* licensed under the AGPL, permanently, to everyone. There is
no version of this where your code exists only inside a closed product.

If that trade is not one you want to make, say so rather than sign. Bug reports,
reproductions, design review and adversarial testing need no agreement at all,
and several of the more useful contributions to this project have been of exactly
that kind.

### What this section said until September 2026, and why it changed

Until the commercial licence was added, this section was headed *"DCO, not a
CLA"* and said:

> **There is deliberately no contributor licence agreement.** Copyright stays
> with whoever wrote the code. The maintainer holds copyright in the code they
> wrote and is not seeking to hold yours: there is no CLA waiting behind the DCO
> and no copyright assignment.

Three of those four claims survive. Copyright still stays with whoever wrote the
code, the maintainer still is not seeking to hold yours, and there is still no
copyright assignment. The one that does not survive is *"no CLA waiting behind
the DCO"* — there is one now, and there was not when that sentence was written.

It is quoted rather than edited down because somebody may have decided to
contribute on the strength of it. **Nothing already contributed is affected**: a
CLA cannot reach backwards any more than a licence change can, which is the
position [NOTICE](NOTICE) takes about the Apache-2.0 window and has to be the
position here too.

This is the second time this section has been corrected, and the paragraph below
is the first. Both are kept. A file that documents its own retractions once looks
scrupulous; one that does it twice is starting to describe a pattern, and the
pattern is the useful thing to be able to see.

### What this section used to say before that, and why it said less

Until August 2026 this section said something stronger, and it is quoted rather
than deleted because somebody may have decided to contribute on the strength of
it:

> There is deliberately no contributor licence agreement. A CLA would assign
> your copyright to whoever holds the project, and that party could then
> relicense the whole thing — including away from AGPL. Under a DCO, copyright
> stays with each contributor, so no single person can ever take Quilzo closed
> or move it to a permissive licence.

The second sentence was true. The third was true only of code somebody else had
written, and at the time nobody else had written any — so the guarantee was real
for future contributors and empty for the project as it actually stood. That was
demonstrated rather than argued: on 22 August 2026 the maintainer relicensed the
project to Apache-2.0, which they could do precisely because they were still the
only human author, and reverted it about eighty minutes later. [NOTICE](NOTICE)
records the window, including the part of it that does not revert.

So the promise was not broken by a loophole. It was made in a form that did not
yet bind anyone, and saying "no single person can ever" while being the single
person who could was overclaiming. This paragraph exists so the record shows
that rather than the sentence quietly disappearing.

What the DCO guaranteed, and what it does now that a CLA sits alongside it:

- **Still true:** your copyright stays yours. There is no assignment, and you
  keep every right you had — including the right to relicense your own
  contribution to anybody else, or use it in your own proprietary work.
- **No longer true:** *"nobody can relicense code you wrote without asking
  you."* The CLA is that asking, done once and in advance, and it covers the
  commercial licence. This bullet said the opposite until September 2026 and is
  corrected rather than removed, because it is precisely the sentence somebody
  would have relied on.
- **Bounded by:** the guarantee back. Whatever the commercial licence does with
  your contribution, that contribution stays licensed under AGPL-3.0-or-later to
  everybody, permanently. [CLA.md](CLA.md) is where that is stated as a term
  rather than an intention.
- **Still does not:** make a *further* licence change unilateral for code you
  wrote. The CLA permits offering your contribution under other terms; it is not
  an assignment, so it does not make you a bystander to what the project is.

Every release made under a licence stays available under it. A licence change
decides what happens next; it cannot retract what was already granted, in
either direction.

### About the licence, honestly

Quilzo is **AGPL-3.0-or-later, or a commercial licence at the user's choice**.
Three consequences worth knowing before you spend time:

- If you run a modified Quilzo as a service for other people, those people can
  have your source. That is the point of choosing Affero.
- **Some employers forbid contributing to AGPL projects.** Google's open source
  policy is explicit about this and others follow it. Please check before
  contributing on work time or from a work account. This is a real cost of the
  licence and pretending otherwise wastes your time, not ours.
- **Some of the same employers separately forbid signing CLAs**, and a few
  require every one to go through legal. Adding the commercial licence made this
  project harder to contribute to on work time, not easier, and that cost lands
  on contributors rather than on the maintainer. It is listed here next to the
  other one because two barriers is a different proposition from one, and you
  should find that out from this page rather than from your employer's counsel.

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
