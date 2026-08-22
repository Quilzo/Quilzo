<img src="https://raw.githubusercontent.com/Quilzo/quilzo.github.io/main/images/mark.svg" alt="" width="72" height="72">

# Quilzo

A content management system where stored content is immutable, publishing moves
a pointer, and the template language cannot execute anything.

[![ci](https://github.com/quilzo/quilzo/actions/workflows/ci.yml/badge.svg)](https://github.com/quilzo/quilzo/actions/workflows/ci.yml)
[![licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)
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

## How four constructs are enough

The obvious objection to a language this small is that no real design fits in
it. Three things close the gap, and none of them adds a construct.

**A page names its layout.** `templates/` holds as many layouts as you like and
a page picks one — `"layout": "catalogue"` — resolved in exactly one place, so
the public server, the accessibility gate, the preview and the static export
cannot disagree about which template a page gets. A page naming a layout the
site does not have is refused at publish rather than quietly rendered through
the default, because a page nobody designed with no message anywhere is worse
than a failure.

**A page's shape is content.** The default layout renders an ordered list of
typed sections — hero, features, metrics, bar chart, donut, split, gallery,
carousel, video, steps, timeline, quote, logos, pricing, FAQ, table, people,
prose, notice, call to action. Reordering the homepage is an edit, not a deploy,
and it rolls back like any other edit.

**A page's shape is editable everywhere.** Sections are content, so the terminal
could always edit the JSON — and the browser could not touch them at all. Both
can now, over one implementation of the moves:

```bash
quilzo section kinds                       # nineteen, grouped by what they do
quilzo section add index pricing           # arrives with content that renders
quilzo section move index 4 up             # refused at the ends, not clamped
quilzo section fields index 0              # what is editable inside one
quilzo section set index 0 title='…'       # only where a value already is
```

The browser has the same at `/sections`, with buttons rather than a canvas —
the admin serves `script-src 'none'` and a test asserts it, so a drag-and-drop
editor would mean an exception for the most attacker-interesting surface in the
system. Each move writes a draft commit naming what it did, so an accidental
reorder is undone by rolling the draft back.

**The negations are computed.** The language has no `else`, deliberately: an
`if` with one exit means a template's structure can be read off its source. The
shape that costs is a heading that is a link when there is somewhere to go and
text when there is not — so the renderer derives `unlinked`, `no_image` and
`no_slug` for every object in a page, once, where every renderer sees the same
thing. It is the same argument as the demo's prices: the language has no
arithmetic, so the formatted price is computed before the render.

What is still absent is absent on purpose. No partials, no includes, no
inheritance — each of those resolves a name at render time, and this language
resolves nothing at render time.

## Design, and the check that used to be missing

A site's stylesheet is generated from a closed list of named tokens: every
colour in both schemes, three type stacks, the type scale, the line height, the
measure, the corner radius, the spacing density, the border weight, a two-stop
gradient. The component rules underneath — what a card is, where the focus ring
goes, how a grid wraps, what happens under `prefers-reduced-motion` and
`forced-colors` — are not editable, because that is where the accessibility work
lives.

That split buys something specific. This program used to list colour contrast
under what it does **not** check, on the grounds that contrast lives in a
stylesheet the tool cannot see. It generates the stylesheet now, so the excuse
expired: every text pair is computed against its background in both schemes, and
a theme that puts body text below 4.5:1 is refused at publish with both numbers
named — the same treatment an image with no alternative text gets.

```bash
quilzo theme tokens                    # the whole closed list, and what each does
quilzo theme set primary '#0b4f6c'     # refused if the result is unreadable
quilzo theme check                     # every pair, both schemes
quilzo theme apply article             # take a starter's palette, keep your layout
```

Typefaces are served from the site's own origin or not at all. Put a `.woff2` in
`templates/fonts/` and it is validated, served at `/fonts/`, and available to the
type tokens by name; there is deliberately no way to name a font on somebody
else's host, because a page that fetches one has handed that host a request on
every visit and the ability to stall the render — and the policy cannot help,
because the page asked for it.

## Bringing a template you already have

Nobody's existing template works here, and being told to start again is the
reason people do not move. So a template written for another system is converted
once, in front of the renderer, with a report:

```bash
quilzo template adopt theme.liquid --dry-run
```

Liquid, Twig, Jinja, Django, Handlebars, Mustache, Go templates and Hugo layouts
map onto the four constructs where they can. Script, event handlers, executable
URL schemes and embedded documents are removed unconditionally — they are the
vulnerability class this program is built without, arriving inside a file
somebody downloaded. External stylesheets and fonts are removed too, because the
policy would refuse them and the page would render with its design silently
missing.

Everything that could not be translated is named, with the shape it should
become, and the layout is not written at all while any remain. An `{% else %}`
dropped in silence renders the wrong branch of every conditional, and the person
who ran the conversion has no reason to look.

## Publishing from a Telegram chat

`quilzo telegram serve` is a third process: a Mini App that turns a form in a
chat into a published page, and refuses to publish one a reader could not use.

```bash
export QUILZO_TELEGRAM_TOKEN=…        # never a flag; a flag is shell history
quilzo telegram check                 # confirms the token, names the bot
quilzo telegram serve --app-url https://your.tunnel --site-url https://example.com
```

The bot answers `/start` with a button, by long polling — which needs no inbound
reachability of its own, since the Mini App already has to be behind https for
Telegram to open it at all. A webhook is available instead and requires a secret,
because an endpoint that acts on whatever is posted to it is not a webhook.

[deploy/](deploy/) has what a stable address needs: a Caddyfile that renews its
own certificate, and two hardened systemd units. The admin is deliberately not
in any of it — it is loopback and holds credentials, so it is reached over an SSH
port forward rather than a hostname.

The surface serves `script-src 'none'`, which is not free on a Mini App.
Telegram delivers launch parameters in the URL fragment, and a fragment is never
sent to a server — so reading `initData` server-side normally means JavaScript
on the page lifting it out and posting it back, on the one surface in this
program where a stranger composes content. Instead the bot mints a signed,
single-use, expiring credential in the query string, which the server does see.
`initData` is implemented in full as well, at `POST /launch`, for anyone running
this with Telegram's SDK.

There is no HTML field. A field is text, it lands in a template that cannot
execute, and the page goes out through the same gates as everything else — so
the answer to "what if somebody pastes a script tag" is structural rather than a
filter somebody has to keep ahead of.

## The three processes

```
quilzo serve      the admin       loopback, behind your own auth
quilzo site       the website     the thing you point the internet at
quilzo telegram   the Mini App    authenticated, writable, framed by Telegram
```

Separate binaries-in-one, separate ports, separate exposure. The public process
holds no credentials and has exactly one write capability: appending a form
submission to a store that is not the content store. It cannot read a submission
back, cannot reach a ref, and cannot cause a commit. Reading the postbag happens
in the admin, behind authentication.

The third is the newest and the most exposed: it is authenticated, it can
publish, and it is framed by somebody else's client. That combination is why it
is a separate process with a separate policy rather than a route on one of the
others — mixing it in would mean widening that one's policy to cover this one's
needs, which is how a policy stops describing anything.

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

**Crawl terms.** Machine-readable licensing for automated use: RSL at
`/license.xml`, TDMRep at `/.well-known/tdmrep.json`, and a `robots.txt` that
points at both. Search, training and AI summarisation are **separate grants** —
from 15 September 2026 Cloudflare stops treating indexing and training as one
permission, and a site publishing one undivided answer is answering a question
that has become two. The vocabulary is closed, because a typo in an open one is
a site that believes it refused training and did not. Nothing is published until
an operator sets terms: a licence file asserting terms nobody chose is worse
than none, since a crawler will honour it.

**Replication.** One store pulls objects from another, verified against their
own hashes, into quarantine — never onto the live site. A peer can offer you
objects; it cannot decide that any of them is your site.

**Forms.** Declared fields with kinds, a required privacy notice, a retention
period with a ceiling, honeypot and timing checks, CSV export that neutralises
spreadsheet formula injection, and erasure by search — because an append-only
merkle store cannot erase, which is why submissions deliberately do not live in
it.

**Working together.** Compare-and-swap on every write, so nobody silently
overwrites anybody; a three-way merge for the writes that only collided on the
ref; advisory locks that expire on their own and have no break-lock button; and
approvals that name the content hash they agreed to, so editing the draft
afterwards does not carry the approval forward.

**Leaving, and depositing.** Export as Markdown with front matter, as WordPress
WXR, as lossless JSON — each tested by round trip, which is the only check that
means anything — and as an RO-Crate research object with a sha256 per file, a
licence and the commit the bytes came from, for a deposit somebody has to
verify later.

**Evidence for an assessor.** A posture scan over the real deployment mapped to
35 NIST SP 800-53 controls, OSCAL 1.2.3 assessment results generated from it, a
CycloneDX SBOM from the build, an audit-log export as OCSF or CEF with an
integrity envelope, and a crypto inventory with post-quantum positions.

**Access.** Roles from reader to admin, path-scoped and own-content-scoped
grants, API tokens with their own narrower scope than the principal holding
them, failed-authentication throttling with soft lockout, and an audit log with
a published commitment to every entry so far.

**Assurance.** A static scanner over your own templates and extensions, a
Content-Security-Policy generated from what your content actually references, a
software inventory, store integrity verification, and a posture report.

**Interfaces.** A browser interface covering every capability, grouped into five
sections and reorderable per person, with light/dark and hide-the-navigation
controls and a Help link on every screen into the manual. A command line
covering the same ground. An agent interface over MCP covering everything that
reads or authors content — and deliberately not covering anything that changes
who may do what, what code runs, or what the keys are.

**On a device.** The published site is an installable app with an offline page
and a network-first service worker, and it can register as a share target so the
operating system offers it in the share sheet — a share arriving as an ordinary
form POST with no script in the path.

**Decentralised publication.** Content-addressed storage maps onto IPFS
naturally: `quilzo ipfs` computes CIDv1 identifiers and produces a bundle that
pins as-is. Zero dependencies here too — the DAG-PB and CID encoding is about
four hundred lines, verified against published identifiers and an independent
reimplementation.

## How this uses AI, and why it is not what everyone else means

Almost every CMS shipping "AI" in 2026 means one of two things: a text box that
calls a model and pastes the answer into a field, or an agent given your API
credentials and asked politely to behave. The first is a feature. The second is
a vulnerability with a roadmap.

The problem with the second is not that models are careless. It is that a model
reads your content, and your content is written by people — commenters,
contributors, whoever filled in a form. Anything a model reads is something an
attacker may have written. Prompt injection is not a bug to be trained out; it
is the consequence of putting instructions and data in the same channel.

So the model here never holds the authority. **A manifest is the whole of what
an agent may do**: which capabilities, over which content, on what budget, at
what autonomy. It is enforced at one chokepoint every operation passes through,
so an agent that has been completely hijacked can still only do the things it
declared before anybody talked to it. The model chooses from that list. It
cannot invent an entry.

Two consequences worth stating plainly:

- **Reading stored content taints the run.** Not as a heuristic — as a fact
  that follows the data. Anything an agent produced after reading input somebody
  else could have written needs a person before it goes live, and the system
  knows which runs those are without being told.
- **A model cannot approve its own work.** Not a rule bolted on for AI. Approvals
  must come from principals and self-approval is forbidden, and a model is not a
  principal. The rule that stops an editor rubber-stamping herself is the rule
  that stops a model shipping unreviewed.

This follows CaMeL ([arXiv:2503.18813](https://arxiv.org/abs/2503.18813)), which
is where the research settled: enforce policy outside the model with a
deterministic gate, because no amount of training makes a model refuse every
malicious instruction.

**What is honestly missing:** this has not been run against AgentDojo. That is
the benchmark that would turn "designed to resist injection" into "measured
against it", and until it has, the claim is architectural rather than empirical.
It is open as issue #33.

### The part people mean by "agentic OS"

An agent that can only edit text is not much use. An agent that can touch your
files, your notifications and your devices is useful and terrifying in the same
breath, and the industry's answer so far has been to hand it an OAuth token and
hope.

There is a paper worth reading here — *Governance Gaps in Agent Protocols*
([arXiv:2606.31498](https://arxiv.org/abs/2606.31498)) — which works through what
MCP, A2A and ACP cannot express: permissions, delegation with accountability,
budgets, provenance, revocation, and who answers for what an agent did. Six
gaps. Quilzo's agent card fills all six, published as an A2A governance
extension at `/.well-known/agent-card.json`, so another system can read what
this one will and will not allow before it asks for anything.

The device side is deliberately the boring version. A published site is an
installable app with a share target: the operating system offers it in the share
sheet, and a share arrives as **an ordinary multipart form POST** — no service
worker in the path, no JavaScript, no SDK. It lands as a submission with a
retention period and a privacy notice, because content anybody with a URL can
create is the vulnerability every CMS with open registration has had.

---

## Three interfaces, and the same rules in all of them

The browser, the command line and the agent interface are not three views of a
product with one real implementation and two thin wrappers. Every capability
exists in all three or carries a written reason why it does not — **and a test
walks the source and fails on the gap.** This project has shipped a rule the
terminal honoured and the browser did not, more than once, which is why the test
exists rather than the intention.

**The command line** is the whole system. `quilzo init`, `add`, `publish`,
`rollback`, `diff`, `log`; content types, listings, forms, media, menus,
languages; `auth`, `token`, `oidc`; `posture scan`, `compliance controls`,
`siem`; `export`, `import`, `ipfs`, `peer`. Everything a person can do in a
browser has a command, and every command declares the privilege it needs — which
is checked, not documented.

**MCP, in both directions.** A server exposing this store to a model, and a
client calling servers an operator declared. The client's allow-list is the part
that matters: 17.2% of remote MCP servers surveyed in July 2026 were dead, and
the live risk is not a dead server — it is a live one redefining a tool after
the day somebody trusted it. Credentials are named in the declaration and read
from the environment, never stored, because an object in this store cannot be
deleted afterwards.

The agent interface covers everything that reads or authors content, and
deliberately covers nothing that changes **who may do what, what code runs, or
what the keys are**. That boundary is the design, not an unfinished edge.

---

## Signing in

Three ways, and the differences matter more than the count.

**OpenID Connect** against whatever your organisation already runs —
`quilzo oidc configure --issuer ... --client-id ...`, with PKCE, written from
scratch because there is no dependency to import it from. `quilzo oidc check`
talks to the provider and reports what it actually offers rather than what the
documentation claims.

**API tokens**, shown once, each with a scope **narrower than the principal
holding it**. That is the part most systems get wrong: a token that inherits its
owner's authority is a copy of that person, and it lives in a CI variable
forever. Here a token is issued for a job and can do that job only.
`quilzo token stale` finds the ones nobody has used.

**Roles**, from reader to admin, scoped to a path or to a person's own content.
`quilzo auth explain WHO ACTION` answers *why* somebody can or cannot do a thing,
which is the question that actually gets asked, and it answers it by evaluating
the real policy rather than by describing it.

Failed authentication is throttled with a soft lockout. The audit log has a
published commitment to every entry so far, so removing one is detectable rather
than merely forbidden.

---

## Working on the same site at the same time

Two people saving at once is normally either a lock somebody has to break, or a
refusal that costs the second person their work.

Neither here. A write says which commit it was based on, and a write whose base
has moved is refused — compare-and-swap, exact in a content-addressed store,
with no timestamps and no version columns. And then, because most of those
refusals are not real collisions, `--merge` resolves the ones that are not: two
people on different pages, or on different fields of one page, both keep their
work and are told which change came from where.

What it will never do is resolve a disagreement by picking a side. Both changed
the same field to different values? That is reported, nothing is written, and the
draft still holds their version — so no work is lost either way while somebody
decides. A merge that guessed would be a merge somebody has to audit, and nobody
audits a merge that says it succeeded.

Locks exist too, and they are advisory on purpose. They stop two people each
spending an afternoon on the same page. They are not the safety property, they
expire on their own, and there is no break-lock button because there is nothing
to break.

There is no live cursor in a shared document, and there will not be. That
feature is JavaScript by construction — an editor, a transport, and a CRDT in
the browser — and this admin serves no script at all.

---

## On a phone

A published site is a progressive web app: a manifest, a display mode, an
offline page, and a service worker that is network-first because publishing has
to take effect at once and a cache that serves yesterday's page is a rollback
nobody asked for.

Point `share.form` at one of your forms and it registers as a share target, so
the operating system offers your site in the share sheet. A share arrives as an ordinary form POST and becomes a submission —
declared fields, a privacy notice, a retention ceiling. Startup refuses to
advertise the share sheet when the form it points at could never accept one,
rather than offering an entry that fails weeks later on somebody's phone.

The admin is server-rendered HTML that works on a small screen because it is
HTML, and it now carries a control to hide the navigation and give the content
the width.

---

## For government, and for work that has to be evidenced

Most CMS compliance stories are a PDF. FedRAMP 20x ended that: since CR26 was
finalised in June 2026, packages carry **machine-readable evidence**, at least
70% of it automated, and OSCAL output is required from 30 September 2026.

That is a much better fit for a system that already knows its own configuration
than for one that has to be described.

- **`quilzo posture scan`** reads your actual deployment rather than a
  checklist, and every rule already names the NIST SP 800-53 controls it bears
  on and the OWASP category it belongs to. **35 controls have an automated
  check.** `quilzo compliance controls` prints the map.
- **OSCAL 1.2.3 assessment results**, generated from that scan. Not a claim of
  compliance — the output of an assessment, which is what the format is for and
  what an assessor can ingest.
- **`quilzo compliance sbom`** is CycloneDX 1.6 derived from the build, and it
  is a short document, because there are no dependencies to enumerate.
  `quilzo compliance crypto` lists every algorithm in use and its post-quantum
  position.
- **`quilzo siem`** exports the audit log as OCSF, CEF or JSON Lines with an
  integrity envelope, so the receiving system can tell whether events were
  removed. Identifiers are pseudonymised unless somebody explicitly asks for
  them, and asking is itself recorded.
- **GDPR.** Article 20 asks for a structured, machine-readable format; export is
  tested by round trip, which is a higher bar than the law sets. Article 17 is
  why form submissions deliberately do not live in the merkle store — an
  append-only store cannot erase, so the data that must be erasable is kept
  where erasing it is possible, and erasure works by search rather than by id.
- **EU AI Act Article 50** requires machine-readable marking of AI-generated
  content. Publishing an unmarked AI-generated page is refused, not warned about.

For an air-gapped or classified deployment the shape is unusually simple: one
static binary with no dependency graph to review, a distroless container with no
shell, no package manager and no interpreter, no telemetry, and no outbound request an
operator did not configure. The whole state is one directory — back that up and
you have backed up the content, the history, the access policy and the
credentials.

**What this is not:** an authorisation. No ATO, no third-party assessment, no
audit. These are the artefacts an assessment needs, produced automatically and
continuously. Somebody still has to do the assessment.

---

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

The image is `gcr.io/distroless/static-debian12:nonroot`: the binary, CA
certificates and a passwd entry. No shell, no package manager, no interpreter,
no libc. It runs as nonroot. amd64 and arm64.

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

You need Go 1.27 or later. There are no dependencies to fetch.

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
quilzo template use sections             # a layout, a theme and sample content
quilzo add index=templates/sections.json -m "first page"
quilzo publish
```

### And run it

```bash
quilzo serve --addr 127.0.0.1:8080                                    # admin
quilzo site  --addr 127.0.0.1:8081 --base-url http://127.0.0.1:8081   # site
```

`quilzo help` lists every command.

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

## Why you might choose this, and when you should not

The honest version, because a comparison that only flatters is a comparison
nobody believes.

**Against WordPress.** WordPress wins on ecosystem and it is not close: forty
thousand plugins, every integration already written, and somebody in every town
who can maintain it. That ecosystem is also the attack surface — the 2026
pre-auth RCE chained an injectable query with a write that later executed, and
the kill chain ends in *upload a plugin*. If your requirement is "a marketing
team ships a landing page this afternoon with a form builder and a booking
widget", WordPress is the right answer. If your requirement is "this sits in
front of something that matters and I need to argue about its security to
somebody who will not accept 'we patch quickly'", the plugin runtime is the
thing you cannot argue away.

**Against Strapi, Sanity, Contentful and the headless generation.** They are
good at what they do and this borrows from them freely — the API shape, the
content modelling, the developer ergonomics are all things they got right. The
differences are two. Theirs is a database with a CMS on it, so a query language
sits between an attacker and your content by design; here there is no query
language over content, which is why one whole class of exploit has nowhere to
land. And theirs is a hosted product or a Node application with a dependency
tree in the hundreds; this is one static binary with none.

**Against a static site generator.** If nobody but developers edits the content,
use Hugo. Genuinely. A CMS is a tool for letting non-developers change a site
safely, and if you do not need that, you are buying a workflow you will not use.
This becomes worth it the moment somebody who does not use git needs to publish.

**Against Git-based CMSs** (Netlify CMS, TinaCMS, Decap). Closest in spirit, and
the storage model is not the difference — content addressing is. Publishing here
moves a pointer to bytes that already exist, so "what production serves is what
staging served" is exact rather than a property of your build being
deterministic. And rollback is a pointer move, not a rebuild.

### The three things nothing else does

1. **Publishing refuses.** Not warns. An inaccessible page, an unmarked
   AI-generated one, a menu pointing at nothing, a claim the business cannot
   substantiate, an image whose licence has lapsed — each stops the publish.
   Every CMS has a linter somebody turned off; this is a gate, the override is
   explicit, and the override lands in the commit metadata with a name on it.

2. **The agent boundary is enforced, not requested.** A manifest, a chokepoint,
   and taint that follows the data. Everyone else is writing better system
   prompts.

3. **The compliance artefacts are generated from the running system.** OSCAL
   from a real scan, an SBOM from the real build, an audit export with an
   integrity envelope. Not a questionnaire somebody filled in last year.

### When you should not use this

- You need a plugin that already exists. There is no plugin runtime and there
  will not be one; extensions are out-of-process, sandboxed, and pinned by
  digest.
- You need per-visitor personalisation or a shopping cart. Products, catalogue
  and structured data yes; a cart holding a card, no — that needs a threat model
  this process does not have.
- You need commercial support today. One maintainer, no 1.0, no backports.
  That is the real state of it, and [GOVERNANCE.md](GOVERNANCE.md) says exactly
  what it takes to change it.

---

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

**This changed, and the previous answer is worth stating rather than quietly
replacing.** Quilzo was AGPL-3.0-or-later until August 2026. Affero was chosen
for a specific reason: nobody distributes a CMS, they host it, so a licence
whose obligations trigger on distribution would never trigger at all. Running a
modified Quilzo as a service meant those users could have the source.

Two things changed that reasoning.

The first is that the reciprocity was aimed at the wrong risk. The thing worth
protecting here is not the code — it is the properties: that a template cannot
execute, that an unmarked AI-generated page does not publish, that an
inaccessible one is refused. Those are worth more the more places they are, and
a licence that a corporate legal review declines at the first paragraph is a
licence that keeps them in one place.

The second is that this became infrastructure other people need to embed. A
publishing pipeline that marks machine-generated content and refuses what it
cannot vouch for is only useful where machine-generated content is being
published, and that is increasingly inside somebody else's product.

Apache-2.0 rather than MIT for the explicit patent grant, which is the clause a
legal review actually looks for.

Everything released under AGPL stays under AGPL. That grant is irrevocable and
this is not an attempt to retract it: anyone holding a copy of a previous
release keeps every right it gave them, permanently, including the right to
fork and continue under those terms.

## Contributing

This project wants maintainers, not only patches. Three merged pull requests of
substance and you can have commit access — the bar is written down in
[GOVERNANCE.md](GOVERNANCE.md) so that nobody has to guess when they qualify.

[CONTRIBUTING.md](CONTRIBUTING.md) has the two-minute path from clone to running
site, the one rule that will surprise you (no dependencies), and how review
works here. Security reports go through [SECURITY.md](SECURITY.md), privately.

Contributions are taken under a [DCO](https://developercertificate.org/) —
`git commit -s` — and copyright stays with whoever wrote the code.
[CONTRIBUTING.md](CONTRIBUTING.md) says what that does and does not commit you
to, including what changed when the licence did.
