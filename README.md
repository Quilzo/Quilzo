# Scrivet

A content management system where stored content is immutable, publishing moves
a pointer, and the template language cannot execute anything.

```bash
scrivet init          # a store in the current directory
scrivet demo          # install a complete example application
scrivet site          # serve it on 127.0.0.1:8081
scrivet serve         # the admin interface on 127.0.0.1:8080
```

Go, no third-party dependencies, one static binary. Everything below is
reachable from the command line, the browser and the agent interface, and a test
fails when one of them falls behind the others.

---

## What it is

Scrivet manages structured content and publishes a website from it. It does the
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

**Integrity is checkable.** `scrivet verify` recomputes every hash. A store that
has been tampered with does not verify, and the check does not depend on a log
that the tamperer could also edit.

## Why templates cannot execute

Server-side template injection exists because the popular template languages are
programming languages. Give one an attacker-influenced string and it reaches a
constructor, a class hierarchy, a filesystem, a subprocess.

Scrivet's template language has four constructs and no way to add a fifth:

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
scrivet serve   the admin      loopback, behind your own auth
scrivet site    the website    the thing you point the internet at
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
sections and reorderable per person, with a light/dark toggle and a manual with
screenshots. A command line covering the same ground. An agent interface over
MCP covering everything that reads or authors content — and deliberately not
covering anything that changes who may do what, what code runs, or what the keys
are.

**Decentralised publication.** Content-addressed storage maps onto IPFS
naturally: `scrivet ipfs` computes CIDv1 identifiers and produces a bundle that
pins as-is. Zero dependencies here too — the DAG-PB and CID encoding is about
three hundred lines, verified against published identifiers and an independent
reimplementation.

## The demonstration

`scrivet demo` installs **Gram**: a photo-sharing site with a feed over
structured records, an explore page with a working filter, profiles under a
content type, stories carrying publish windows, and a message box.

It exists because a starter template shows what a page looks like and cannot
show what the tool is for — that only appears with several features working at
once. It was built through the admin interface first and written down
afterwards, in that order deliberately: six bugs were found on the way, and
every value in it is one a screen accepted.

Things worth trying once it is running:

```
/explore?topic=travel     a listing with a parameter, filtered at request time
/stories/sol-rooftop      404s until September; its window has not opened
/messages                 the one thing the public server may write
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

1388 tests. Roughly one line of test for every two lines of program.

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

```bash
go build -o scrivet ./cmd/scrivet

mkdir mysite && cd mysite
scrivet init
scrivet token issue laptop --principal you --role admin   # shown once
export SCRIVET_TOKEN=scv_…
scrivet auth grant you admin

scrivet template use landing        # or `scrivet demo` for a whole application
scrivet add index=index.json -m "first page"
scrivet publish

scrivet serve --addr 127.0.0.1:8080      # admin
scrivet site  --addr 127.0.0.1:8081      # site
```

`scrivet help` lists all 92 commands. The admin interface carries a manual with
screenshots at `/docs`, and every screen's Help link points at its own section.

## Deployment

The container is `distroless/static-debian12:nonroot` — no shell, no package
manager, no libc. For a CMS that is not incidental: WordPress's kill chain ends
in *upload a plugin*, and an image with no interpreter has no terminal step to
offer.

Run the admin on loopback behind whatever you already trust, and the site
process on the interface facing the internet. They share a store directory and
nothing else.

```bash
docker build -t scrivet .
docker run --rm -p 8081:8081 -v "$PWD/store:/store" scrivet \
  site --addr 0.0.0.0:8081 --base-url https://example.org
```

## Licence

AGPL-3.0-or-later. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Affero specifically, because nobody distributes a CMS — they host it. A licence
whose obligations trigger on distribution would never trigger at all for the
software this is. Running a modified Scrivet as a service for other people means
those people can have the source.
