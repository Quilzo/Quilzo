<img src="https://raw.githubusercontent.com/Quilzo/quilzo.github.io/main/images/mark.svg" alt="" width="72" height="72">

# Quilzo

A content management system where stored content is immutable, publishing moves
a pointer, and the template language cannot execute anything.

[![ci](https://github.com/quilzo/quilzo/actions/workflows/ci.yml/badge.svg)](https://github.com/quilzo/quilzo/actions/workflows/ci.yml)
[![licence: AGPL-3.0-or-later](https://img.shields.io/badge/licence-AGPL--3.0--or--later-blue)](LICENSE)
[![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen)](go.mod)

```bash
quilzo init          # a store in the current directory
quilzo demo          # install Marginalia, a complete shop
quilzo site          # serve it on 127.0.0.1:8081
quilzo serve --open  # the admin on 127.0.0.1:8080, opened in a browser
```

Linux, macOS and Windows, amd64 and arm64.

Go, no third-party dependencies, one static binary. Everything below is
reachable from the command line, the browser and the agent interface, and a test
fails when one of them falls behind the others.

---

## What this project is for

**A CMS that cannot be exploited in the two ways CMSs are actually exploited.**

Look at how content management systems fall over in practice. Almost every
serious one is some combination of two things: a query an attacker can influence,
and a place where writing data means writing something that later executes.
WordPress's 2026 pre-auth RCE chained exactly those two. Drupal's CVE-2026-9082
was the first half on its own.

You do not harden that chain. You remove its links, and you can only remove them
at the level of the storage model and the template language — which is why this
is a new CMS rather than a hardening guide for an existing one.

So there are three goals, in order:

1. **Whole vulnerability classes absent by construction, not by patching.** No
   query language over content, so nothing to inject into. No executable
   template language, so nothing to escape from. These are properties of the
   design; the tests assert them and the fuzzers attack them.

2. **Every control enforced where it is used, not where it is documented.** This
   project has repeatedly shipped a rule the terminal honoured and the browser
   did not. So the test suite walks its own source and fails on the gap: every
   command declares its privilege, every capability exists in all three
   interfaces or carries a written reason, every write surface consults the
   content-type gate.

3. **Refuse rather than warn.** A warning nobody reads is a feature nobody has.
   When Quilzo detects an inaccessible page, an unmarked AI-generated page, a
   menu pointing at nothing, or content that violates its own type, it stops the
   publish. Overriding is possible, explicit, and recorded in the commit.

### What it is deliberately not

Not a plugin marketplace — the extension point is an out-of-process hook with
a timeout and no inherited environment, not a way to run arbitrary code in the
request path. It is not a capability sandbox; SECURITY.md says exactly what it
does and does not bound. Not a framework. Not a JavaScript
application; the admin is server-rendered and its own CSP forbids script
entirely. And not a general database with a CMS on top, because that is the
thing whose absence makes the first goal possible.

### Where it is honest about its age

One maintainer, and the project is looking for more — [GOVERNANCE.md](GOVERNANCE.md)
says three merged pull requests of substance and you can have commit access.
Nothing in the release path depends on one person's machine or account. There is
no 1.0 yet and no backports to earlier tags.

---

## What it is

Quilzo manages structured content and publishes a website from it. It does the
things a CMS is expected to do — content types, media, taxonomies, menus, views
over structured data, forms, workflow, multiple languages, staged environments,
scheduled publication, an audit trail — and it does them on a storage model
borrowed from version control rather than from a relational database.

That choice is the product. It is what makes rollback instant, caching exact,
and two of the three CMS vulnerability classes structurally absent.

## Why the storage model matters

Every object is addressed by the SHA-256 of its own bytes. A page is a hash. A
set of pages is a tree, which is itself a hash. A commit names a tree and its
parents. Publishing sets one ref to one commit.

Four things follow, and none of them are features anybody had to write:

**Nothing is edited.** There is no UPDATE and no DELETE. An edit writes a new
object and moves a pointer, so every previous version is still addressable.
Rollback is a pointer move, not a restore.

**There is no query for content.** Reading a page is a hash lookup on a file
path. There is no statement for an attacker to influence, which removes the
first half of the kill chain that both WordPress's 2026 pre-auth RCE and
Drupal's CVE-2026-9082 depended on.

**Cache invalidation is free.** A page's ETag *is* its content hash — not
derived from it, not a proxy for it. Different content is a different hash, so a
conditional request answers itself and nothing has to be purged on publish.

**Integrity is checkable.** `quilzo verify` recomputes every hash. A store that
has been tampered with does not verify, and the check does not depend on a log
that the tamperer could also edit.

## Why templates cannot execute

Server-side template injection exists because the popular template languages are
programming languages. Give one an attacker-influenced string and it reaches a
constructor, a class hierarchy, a filesystem, a subprocess.

Quilzo's template language has four constructs and no way to add a fifth:

```
{{ page.title }}                  a value, escaped for the context it lands in
{% if page.subtitle %}…{% end %}  present and truthy
{% for row in listings.feed.rows %}…{% end %}   bounded iteration
{% raw page.body %}               deliberately unescaped, and greppable
```

No author-defined functions, no arithmetic, no assignment, no imports, no field
access on Go values, no method calls, no recursion. There is nothing to escape
*from*, because there is nothing underneath: values come out of decoded JSON and
the only operations are lookup, truthiness and iteration.

Formatting — the thing Velocity and Twig are usually embedded to provide — is a
closed list of filters (`upper`, `truncate:60`, `date`, `slug`, `join`, and a
dozen more), each taking at most one literal argument.

Loops iterate over data, never a condition. Depth, output size and total
iterations are capped. Rendering terminates for every input; that is a property,
not a hope.

## The two processes

```
quilzo serve   the admin      loopback, behind your own auth
quilzo site    the website    the thing you point the internet at
```

Separate binaries-in-one, separate ports, separate exposure. The public process
holds no credentials and has exactly one write capability: appending a form
submission to a store that is not the content store. It cannot read a submission
back, cannot reach a ref, and cannot cause a commit. Reading the postbag happens
in the admin, behind authentication.

## What is in it

**Content.** Pages and structured records. Content types with typed, validated
fields — text, number, boolean, date, URL, email, slug, choice, list — enforced
identically by the CLI, the browser and the agent interface. Media with format
validation by decoding rather than by extension, and alternative text required
before an image may be published.

**Views over records.** Declared queries with typed parameters, a field
allowlist and a cost budget, resolved before rendering. A page names the
listings it embeds; the template receives data, never a callable.

**Structure.** Closed-by-default vocabularies with synonyms and hierarchy, so a
misspelled tag cannot invent a new one. Menus that refuse to save while pointing
at a page that does not exist, and refuse to publish while pointing at one that
is not going live.

**Publishing.** Draft and live refs, diff, instant rollback, staged environments
with promotion, scheduled publication, and content that carries its own publish
window — checked when the page is served, so an embargo cannot lift because a
cron job was wedged.

**Gates before publication.** Accessibility, checked by rendering the page and
not by inspecting the content. Provenance, because the EU AI Act requires
AI-generated content to carry a machine-readable mark. Dual authorisation, where
an approval names the content hash it agreed to, so editing the draft afterwards
does not carry the approval forward. Every gate refuses rather than warns; the
override is explicit and lands in the commit metadata.

**Agents.** A manifest is the whole of what an agent may do: capabilities, a
content scope, a budget and an autonomy level, enforced at one chokepoint every
operation passes through. Reading stored content taints the run, so what an
agent produced from input somebody else may have written needs a person before
it goes live. A model may choose each action from the manifest's capabilities
and cannot invent one. The design follows CaMeL (arXiv:2503.18813), which is
where the research settled: enforce policy outside the model with a
deterministic gate, because no amount of training makes a model refuse every
malicious instruction.

**Commerce, as far as a CMS should go.** Products are records; a listing is the
one declaration behind the shop page, the product page and `/catalogue.json`,
so what is public is decided once. schema.org Product and Offer are emitted from
the same row the page rendered. No cart, no checkout, no payment — the 2026
agentic protocols settled on discovery and hand-off, and the moment this process
holds a card it needs a threat model it does not have.

**Claims and rights.** A publish gate that refuses copy the business cannot
stand behind — not a blocked-word list, which every team switches off, but a
claim and its substantiation: "guaranteed" publishes beside the guarantee terms
and is refused without them. And image licences treated as publish windows,
because rights *end* — a lapsed stock licence leaves a site infringing with an
audit trail proving it was deliberate, and nothing notices.

**Reaching other systems.** MCP in both directions: a server exposing this
store, and a client calling servers an operator declared. The client's tool
allow-list is the point — 17.2% of remote MCP servers surveyed in July 2026 were
dead, and the live risk is a server redefining a tool after the day somebody
trusted it. Credentials are named in the declaration and read from the
environment, never stored, because an object in this store cannot be deleted.

**Replication.** One store pulls objects from another, verified against their
own hashes, into quarantine — never onto the live site. A peer can offer you
objects; it cannot decide that any of them is your site.

**Forms.** Declared fields with kinds, a required privacy notice, a retention
period with a ceiling, honeypot and timing checks, CSV export that neutralises
spreadsheet formula injection, and erasure by search — because an append-only
merkle store cannot erase, which is why submissions deliberately do not live in
it.

**Access.** Roles from reader to admin, path-scoped and own-content-scoped
grants, API tokens with their own narrower scope than the principal holding
them, failed-authentication throttling with soft lockout, and an audit log with
a published commitment to every entry so far.

**Assurance.** A static scanner over your own templates and extensions, a
Content-Security-Policy generated from what your content actually references, a
software inventory, store integrity verification, and a posture report.

**Interfaces.** A browser interface covering every capability, grouped into five
sections and reorderable per person, with a light/dark toggle and a Help link on
every screen into the manual. A command line covering the same ground. An agent interface over
MCP covering everything that reads or authors content — and deliberately not
covering anything that changes who may do what, what code runs, or what the keys
are.

**Decentralised publication.** Content-addressed storage maps onto IPFS
naturally: `quilzo ipfs` computes CIDv1 identifiers and produces a bundle that
pins as-is. Zero dependencies here too — the DAG-PB and CID encoding is about
four hundred lines, verified against published identifiers and an independent
reimplementation.

## The demonstration

`quilzo demo` installs **Marginalia**: a shop selling paper. Twelve products as
typed records, three stockists, a catalogue a machine can read, two policies, a
wholesale enquiry form, and a sale that has not started yet.

It exists because a starter template shows what a page looks like and cannot
show what the tool is for — that only appears with several features working at
once. It replaced a photo-sharing demo, which was honest and exercised the wrong
half: a feed and a filter never raise a question a paying customer arrives with.
A shop raises all of them — a price that has to be a number, an availability
that has to be a closed set, copy that has to be substantiated before it
publishes, and a catalogue something other than a browser has to read.

It was built through the admin interface first and written down afterwards, in
that order deliberately. Building it found five bugs, including a publish gate
that was checking ten pages and none of fifteen products while reporting
success.

`quilzo demo --name "Your Shop"` renames the whole of it, so it can be a
starting point rather than something to find and rename afterwards.

Things worth trying once it is running:

```
/catalogue.json           everything for sale, as a shopping agent reads it
/product/brass-pen        one product, one URL, schema.org Product in the head
/ranges?range=archive     a listing with a parameter, filtered at request time
/available                filtered on the data, not on somebody remembering
/sale                     404s until 24 November; its window has not opened
/wholesale                the one thing the public server may write
```

And the gates, from a terminal:

```bash
quilzo brand check    # every claim, and what substantiates it
quilzo rights         # image licences: expired, lapsing, undeclared
```

## No dependencies

`go.mod` has no `require` block. Not a preference — a supply-chain position. A
CMS is the highest-value place in an infrastructure to put something, and every
transitive dependency is somebody else's release process inside yours. CI fails
the build if a dependency appears.

The cost is real: the merkle store, the template language, the CID encoder, the
OIDC client and the HTML tokeniser are all written here. Each one is smaller
than the library it replaces because it does only what this needs.

## Testing

1,147 test functions, 2,103 cases counting subtests. Roughly one line of
test for every two lines of program.

The ones that matter most are structural — they walk the source and fail on
omissions rather than on wrong answers, because the recurring failure in this
project has not been broken code but capability present in one interface and
absent from another:

- every command declares its required privilege
- every capability is reachable from the browser, the CLI and MCP, or has a
  written reason it is not
- every write surface consults the content-type gate
- every write surface uses compare-and-swap
- every mutating command can reach the audit log
- every screen renders, passes the accessibility checks this tool enforces on
  other people's content, and survives both an empty store and a server with
  nothing wired in
- every link and form action in the interface is served by a registered route
- every CSS class in the markup is styled

Seven fuzz targets cover the template renderer, the media acceptor, the
importer, the redirect map, the API request parser, the anchor verifier and the
OIDC discovery walk.

## Getting started

### With Docker

The image is built `FROM scratch`: the binary and nothing else — no shell, no
package manager, no libc. 27.6 MB, amd64 and arm64.

```bash
docker run -v quilzo:/srv/store ghcr.io/quilzo/quilzo --root /srv/store init
docker run -v quilzo:/srv/store ghcr.io/quilzo/quilzo --root /srv/store demo
docker run -p 8081:8081 -v quilzo:/srv/store ghcr.io/quilzo/quilzo \
  --root /srv/store site --addr 0.0.0.0:8081
```

Published on each tagged release, with a build-provenance attestation binding
the image to the workflow run that produced it:

```bash
gh attestation verify oci://ghcr.io/quilzo/quilzo:latest --repo quilzo/quilzo
```

### From source

You need Go 1.24 or later. There are no dependencies to fetch.

```bash
git clone https://github.com/quilzo/quilzo
cd quilzo
go build -o quilzo ./cmd/quilzo
# or: make build   →  bin/quilzo, stripped and version-stamped (see Makefile)

export PATH="$PWD:$PATH"   # so the `quilzo` commands below just work
mkdir mysite && cd mysite
quilzo init
```

### Getting a token

There is no default password and no default account. Nothing is admin until you
say so, so there is no state in which a fresh install is reachable with a
credential somebody already knows.

```bash
quilzo auth grant you admin                            # "you" is any name
quilzo token issue laptop --principal you --role admin # shown once
export QUILZO_TOKEN=qz_…
```

A token can carry **less** authority than the person holding it and never more:
`--role reader` on an admin's token makes a read-only credential, `--read-only`
refuses every write whatever the role, `--on /blog` scopes it to a path, and
`--ttl 24h` expires it. `quilzo token revoke ID` takes effect on the next use,
not at the next restart.

### Then either

```bash
quilzo demo                              # a whole example application
# or
quilzo template use landing
quilzo add index=index.json -m "first page"
quilzo publish
```

### And run it

```bash
quilzo serve --addr 127.0.0.1:8080                                    # admin
quilzo site  --addr 127.0.0.1:8081 --base-url http://127.0.0.1:8081   # site
```

`quilzo help` lists all 92 commands.

## Documentation

**[quilzo.github.io](https://quilzo.github.io)** — setup, content modelling,
publishing, the three interfaces, access control and security, with screenshots.

Every screen in the admin carries a Help link in the same place, pointing at the
section for the screen you are looking at rather than at the top of the manual.

The manual used to be compiled into the binary and served at `/docs`. It is a
site of its own now, in [its own repository](https://github.com/Quilzo/quilzo.github.io),
so a wording fix or a corrected screenshot ships the day somebody notices rather
than waiting for a release.

## Deployment

The container is `distroless/static-debian12:nonroot` — no shell, no package
manager, no libc. For a CMS that is not incidental: WordPress's kill chain ends
in *upload a plugin*, and an image with no interpreter has no terminal step to
offer.

Run the admin on loopback behind whatever you already trust, and the site
process on the interface facing the internet. They share a store directory and
nothing else.

```bash
docker build -t quilzo .
docker run --rm -p 8081:8081 -v "$PWD/store:/store" quilzo \
  site --addr 0.0.0.0:8081 --base-url https://example.org
```

## Licence

AGPL-3.0-or-later. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Affero specifically, because nobody distributes a CMS — they host it. A licence
whose obligations trigger on distribution would never trigger at all for the
software this is. Running a modified Quilzo as a service for other people means
those people can have the source.

## Contributing

This project wants maintainers, not only patches. Three merged pull requests of
substance and you can have commit access — the bar is written down in
[GOVERNANCE.md](GOVERNANCE.md) so that nobody has to guess when they qualify.

[CONTRIBUTING.md](CONTRIBUTING.md) has the two-minute path from clone to running
site, the one rule that will surprise you (no dependencies), and how review
works here. Security reports go through [SECURITY.md](SECURITY.md), privately.

One thing to know before you spend time: **some employers forbid contributing to
AGPL projects**, Google's policy explicitly. That is a real cost of the licence
and it is better said here than discovered later.
