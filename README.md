<img src="https://raw.githubusercontent.com/Quilzo/quilzo.github.io/main/images/mark.svg" alt="" width="72" height="72">

# Quilzo

A content management system where stored content is immutable, publishing moves
a pointer, and the template language cannot execute anything.

[![ci](https://github.com/quilzo/quilzo/actions/workflows/ci.yml/badge.svg)](https://github.com/quilzo/quilzo/actions/workflows/ci.yml)
[![licence: AGPL-3.0-or-later](https://img.shields.io/badge/licence-AGPL--3.0--or--later-blue)](LICENSE)
[![or commercial](https://img.shields.io/badge/or-commercial-blue)](LICENSING.md)
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
quilzo section kinds                       # twenty, grouped by what they do
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

### The design system you already use

The usual request is a theme named after the design system a company runs on,
and that is the one thing this cannot be. A design system has two licences and
people read the first one: the code licence — MIT for GitHub's Primer,
Apache-2.0 for IBM's Carbon and Adobe's Spectrum — which usually does permit a
derived palette, and the trademark policy, which separately does not permit the
name. Apache-2.0 reserves marks explicitly in section 6; MIT simply never
grants them. Two go further: Adobe's trademark guidelines bar copying "trade
dress… the look and feel… distinctive colour combinations", and Shopify's main
Polaris licence is a modified MIT whose rights apply only to apps that
integrate with Shopify, requiring anything else to be "dissimilar and visually
distinct". Apple's design resources may not be embedded in software at all.

So this ships nobody's palette and nobody's name. It reads the token file the
design system publishes, on the machine of somebody entitled to use it, in the
W3C Design Tokens Format Module — version 2025.10, the first stable one,
published in October 2025 with around forty backing organisations including
Adobe, Figma, Google, Microsoft, Shopify and Salesforce. What a customer gets
is their own design system rather than an imitation of it.

```bash
quilzo theme import tokens.json --list            # every path in the file, and its value
quilzo theme import tokens.json --map pairs.json  # fill this site's tokens from it
quilzo theme export --out tokens.json             # and the same thing going out
```

The pairing is written down rather than guessed. Naming is where design systems
differ most — one calls the page background `background`, another `layer-01`,
another `elevation.surface`, and `primary` means the brand colour in one and
the main text colour in another, which is the opposite end of the contrast
range. A matcher that got those two the wrong way round would produce a theme
that is coherent, plausible and inverted, and because every value came from a
real design system every one of them would look right on its own. `--list`
exists so that writing the mapping is reading rather than guessing.

Imported values go through the same door a hand-typed one does: matched against
a pattern, then every contrast pair computed in both schemes. A design system
with a reputation does not get to skip the check.

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

## The four processes

```
quilzo serve      the admin        loopback, behind your own auth
quilzo site       the website      the thing you point the internet at
quilzo telegram   the Mini App     authenticated, writable, framed by Telegram
quilzo studio     screen recording loopback, and the only one that runs scripts
```

Separate binaries-in-one, separate ports, separate exposure. The public process
holds no credentials and has exactly one write capability: appending a form
submission to a store that is not the content store. It cannot read a submission
back, cannot reach a ref, and cannot cause a commit. Reading the postbag happens
in the admin, behind authentication.

The Mini App is authenticated, it can publish, and it is framed by somebody
else's client. That combination is why it is a separate process with a separate
policy rather than a route on one of the others — mixing it in would mean
widening that one's policy to cover this one's needs, which is how a policy
stops describing anything.

The studio is the same argument arriving from the opposite direction. The
admin's policy is `default-src 'none'` and a test asserts its screens execute
nothing, but `getDisplayMedia` and `MediaRecorder` are JavaScript APIs — there
is no form post that reaches a screen and there will not be one. So either
recording does not happen here, or something runs a script. Rather than open a
nonce route in the admin and weaken the claim that holds everywhere else, the
capture surface is its own process: **the argument for that header is that the
admin has no scripts, not that it has some the policy catches.**

## What is in it

**Content.** Pages and structured records. Content types with typed, validated
fields — text, number, boolean, date, URL, email, slug, choice, list — enforced
identically by the CLI, the browser and the agent interface. Media with format
validation by decoding rather than by extension, and alternative text required
before an image may be published.

**Pictures and video.** A picture can be replaced: the newer file records what
it supersedes, every draft reference — on pages *and* on records, at whatever
depth an author nested it — is pointed at it in one commit, and the listing
shows both directions, because the field points backwards and somebody looking
at the retired picture is the one who needs to know. Nothing is overwritten;
the retired file is still there under its own address and the commit this moved
from is still stored. Format validated by decoding rather than by extension;
alternative text required before an image may be published; a focal point that
says which part of a picture must survive a crop; a derived crop that leaves the
original alone, because nothing here is overwritten; EXIF orientation applied so
a photograph is stored the way up it is meant to be seen, and the rest of the
metadata removed on every path into the store. A video does not publish without
captions, and the accessibility report says so either way. Range requests read
only the bytes asked for, so seeking in a film does not read the film. A picture
asked of a model arrives declared as generated — it cannot arrive any other way
— and `quilzo media verify` checks every C2PA manifest, the ones this program
wrote and the ones that came with somebody else's file.

**Search that answers a sentence.** The ranker required every word of a query
to appear, which scored perfectly on two-word queries and returned *nothing* as
soon as one word was missing — so "how long does delivery take" matched no page
on a site with a delivery page. It is BM25 now: saturation so the tenth
occurrence of a word counts for almost nothing, and length normalisation so a
long page is not rewarded for being long, which is what the conjunction was
protecting against. Measured on a judgement corpus before and after, and both
numbers are in the tests.

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
content scope, a budget, an autonomy level, and the named tools it may call on
hosts it named first — enforced at one chokepoint every operation passes
through. Reading stored content taints the run, and so does calling a tool,
because a third-party result is whatever a host returned on this request with no
review by anybody here at all. What an agent produced after either needs a
person before it goes live. A model may choose each action from the manifest's
capabilities and cannot invent one; when it names a tool, the host is resolved
from the manifest and from the install's own declarations, and **the two have to
agree or nothing is called** — a host the model supplied is dropped rather than
forwarded.

A supervisor hands stages to agents its manifest names in advance, so a
supervisor that has been talked into something cannot invent a worker. The
delegate runs as the intersection of the two manifests and never its own
declaration — otherwise delegation is a way to launder capability — on what is
left of the supervisor's budget rather than on what it declared, and everything
the child spent, refused and was tainted by comes back to the parent. That last
part is the one that matters: a tainted child answering into a clean parent
would defeat the taint rule with a single indirection. The design follows CaMeL (arXiv:2503.18813), which is
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
store, and a client calling servers an operator declared — from the command
line, or by an agent whose manifest named that tool and that host. The client's
tool allow-list is the point — 17.2% of remote MCP servers surveyed in July 2026 were
dead, and the live risk is a server redefining a tool after the day somebody
trusted it. Credentials are named in the declaration and read from the
environment, never stored, because an object in this store cannot be deleted.

**Federation.** The site is followable from the fediverse — WebFinger, an actor
at `/@`, an outbox — and a published page is delivered to every follower, signed,
with bounded retries. The inbox verifies each activity against the sending
server's own key **and requires the body to be inside what was signed**: without
that, capturing one legitimate activity from an actor lets anybody send any
activity as them. `quilzo fediverse init` makes the signing key.

The part no other server can offer: every federated post carries **the store's
own object id for the content and the commit it was published at**. An
ActivityPub id is a URL — a mutable pointer at mutable bytes — which is why
"edited after it federated" is unsolved across the network. Here a reader can
fetch the content and check it hashes to what the post claimed. The claim stops
being *trust this origin* and becomes *here is the digest, go and look*.

**Crawl terms.** Machine-readable licensing for automated use: RSL at
`/license.xml`, TDMRep at `/.well-known/tdmrep.json`, and a `robots.txt` that
points at both. Search, training and AI summarisation are **separate grants** —
from 15 September 2026 Cloudflare stops treating indexing and training as one
permission, and a site publishing one undivided answer is answering a question
that has become two. The vocabulary is closed, because a typo in an open one is
a site that believes it refused training and did not. Nothing is published until
an operator sets terms: a licence file asserting terms nobody chose is worse
than none, since a crawler will honour it.

**Enforcing those terms.** A crawler that identifies itself with a Web Bot Auth
signature — RFC 9421, Ed25519, keys the operator configured rather than fetched
from the request being verified — and asks for a use the licence refuses is
answered `402 Payment Required` with a price, a link to the terms and somewhere
to ask. One that offers enough is served. **An unsigned request is a person and
is always served**: a User-Agent is a string anybody can type, and a CMS that
turns readers away on a guess has broken the thing it is for. The honest limit
is that only a crawler which identifies itself can be charged — which is the
large, well-funded ones, and is more than a declaration reached.

**Replication.** One store pulls objects from another, verified against their
own hashes, into quarantine — never onto the live site. A peer can offer you
objects; it cannot decide that any of them is your site.

**Forms.** Declared fields with kinds, a required privacy notice, a retention
period with a ceiling, honeypot and timing checks, CSV export that neutralises
spreadsheet formula injection, and erasure by search — because an append-only
merkle store cannot erase, which is why submissions deliberately do not live in
it.

The retention ceiling is enforced by the program. Both long-running servers
sweep on a timer of their own, and `quilzo form expire` still forces it. This
used to say that nothing called it on its own and that a deployment needed a
cron entry — which was true, and meant that an operator who had not read the
paragraph had a site that promised to forget and did not. A declared retention
period and an enforced one are different things, and only the second is worth
anything to the person whose data it is.

An install that runs neither server has nothing sweeping, so `quilzo posture
scan` counts submissions that have outlived their period. Scheduled publishing
is the other half and keeps its external timer on purpose — a scheduler that is
also a long-lived process is a second thing that can be down — so the scan
reports an entry that was due and did not fire rather than firing it.

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

**Speed, measured rather than assumed.** Every figure below came from profiling
the running program on a real site, and each is checked by a test that fails if
the cost comes back:

```
a page on a 211-page site      6.83 ms -> 2.66 ms   listings page rather than
                                                    rendering the whole store
the layout, per reader         re-parsed -> parsed once, then shared
the escaper, per page          10% of the request -> built once
                               714 KB/1163 allocs -> 234 KB/737 allocs
the media library, per row     re-read from disk -> read once per request
a page over the wire           6,443 B -> 1,955 B  (70%, deflate at level 6)
a second copy of a page        an ETag list is parsed as RFC 9110 says
the sitemap and the feeds      1,054 B -> 304, and no body
```

Compression weakens an ETag to `W/`, because a compressed response is not the
bytes a strong validator named — the same thing nginx does — and `Vary:
Accept-Encoding` goes on compressed and bodyless responses only, because serving
identity to a client that would have taken gzip is harmless and the reverse is
not. `io.ReaderFrom` is implemented on the compressing writer so `sendfile`
still carries video.

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

**Security operations.** A normalised event model that carries a disposition on
every event and refuses an identifier without an issuer, because "u-1043" from
two directories is two people. Detections as data, where a rule that matches
none of its own fixtures, or refuses none of them, is refused at load — a
detection that cannot fire is not a detection, and between 13 and 18 percent of
deployed SIEM rules never fire under any input. A behavioural baseline that
answers "not enough observations yet" rather than "normal". Canaries, the one
detection with no false positive problem, with the three ways that premise dies
each given a state of its own. One register for what comes out of all of it,
ranked rather than thresholded, whose state is the fold of an append-only audit
log rather than a column somebody edits. An event store partitioned on arrival
rather than on the timestamp in the event — the one clock the thing being
recorded cannot move — with two retention limits, deletion that is never a side
effect, holds that survive a restart, and a watermark measured from observed
arrival delay instead of guessed at by whoever wrote the rule.

**Conversation, built so that what was said stays said.** Slack shows
"(edited)" and the previous text is gone — for everybody, including the person
who already acted on it, recoverable only through a separate product on the
top plan. "I said deploy to staging", edited to "I said deploy to prod", is
unfalsifiable by design. Here a message is an append-only sequence of
revisions and the current text is a fold of them; "edited" is not a flag
somebody can clear but the observable fact that there is more than one. Slack's
own documentation is plain that there is no recycle bin and a deleted message
may be gone forever, which is two problems: the content is lost, and — worse —
a conversation where message 47 is missing and nothing says so is a
conversation somebody edited. So removing takes the words and leaves the
shape. Retention does the same with a different actor, and only an Article 17
erasure takes the words from the log as well, which it can because the log
holds a digest and never the text. A reply is unread in the room rather than
in a thread nobody is following, because that is the commonest structural
complaint about the original. And a broadcast says how many people it
interrupts *before* it goes.

**A codec for screens, and deliberately not one for video.** AV1 took a
consortium several years; a codec written here would be five to ten times
worse per bit, would have no hardware decoder on any device, and would cost
battery on every phone it ran on. There is no version of that trade worth
making. Screen content is a different problem. Video codecs assume natural
images — smooth gradients, motion, and an eye that does not notice small
errors — and screen content breaks all three: a terminal is flat colour with
hard edges, a code editor changes one character between frames, and a small
error in a letterform is a different letter. Every screen share on every
platform runs the picture through a transform designed to discard what the eye
will not miss, and at eight pixels tall what it discards is the difference
between a colon and a semicolon. So this is lossless — not high quality, not
visually lossless — and the damage model is the compression: at 1920x1080,
a key frame is 90x smaller than raw, a keystroke costs 271 bytes and a still
screen costs 89, which is about 8 KB/s of typing with the frame encryption on
top. Pointed at a photograph it compresses barely at all, and it says so
rather than quietly sending fifty megabytes a second.

**Marks on a shared screen that follow the content, not the glass.** Everyone
has sat through this: somebody circles line 40, the presenter scrolls, and the
circle is now around line 52 — pointing, with complete confidence, at the
wrong thing. Every product that draws on a screen share has this bug, because
every one of them pins the drawing to a pixel and the pixel does not move. The
codec above makes the fix available: a frame can be asked what its tiles
contain, so a mark records the fingerprint of the content it was drawn on
rather than the coordinate it landed on, and when the view scrolls the mark is
found wherever that content went. Where the content did not land back on the
tile grid — a scroll of a hundred pixels rather than a whole number of lines —
the scroll itself is measured from the frames, one hash per pixel row and no
search, and the mark moves by that distance instead. Both routes are labelled,
because the first is a sighting and the second is an inference. What matters
more is the third case. A mark whose content is gone, or now appears in four
places with nothing to tell them apart, is **reported and not drawn**: a
rectangle around the wrong function looks exactly like a rectangle around the
right one, so the room has no way to catch it and the person who drew it has
less, because on their screen it never moved. Marks carry no pixels — a kind,
a path, an author and a hash — so what a group pointed at survives a retention
schedule that the frames themselves do not, and taking a mark back leaves the
retraction rather than a gap.

**End-to-end media encryption that an SFU cannot read.** A call between more
than two people goes through a selective forwarding unit, which has to see RTP
headers to route packets, drop layers and rewrite sequence numbers. SRTP is
hop-by-hop, so the SFU holds the keys and can read everything — which is how
most products that say "end-to-end encrypted group calls" resolve the tension,
by not meaning what the phrase says. RFC 9605 is the resolution: the sender
encrypts once, only the receivers decrypt, and the forwarding unit passes
ciphertext it cannot read. All five cipher suites are implemented and checked
against the working group's own test vectors — the derived keys, salts,
nonces, associated data and ciphertexts, plus 289 header encodings — because a
cryptographic implementation checked only against itself proves that it is
self-consistent, which is the one property that does not matter. Three of the
suites have tags shorter than sixteen bytes, and the arithmetic that makes
them worth having is printed rather than assumed: at thirty frames a second
across four streams the difference is 1,440 bytes a second. What SFrame does
not do is stated in the package and in the command — it protects the media and
not who is in the call, who is speaking, or for how long, and it says nothing
about how the key got there.

**Where the call's key actually comes from.** SFrame protects the media and
says, in as many words, that it has nothing to say about how the base key got
there; RFC 9605 leaves key management out deliberately and points at MLS. That
is the honest position for a codec and an untenable one for a product, because
until something fills it "end-to-end encrypted" is a claim about an algorithm
rather than about a call. This fills it. Each epoch has a secret shared by
exactly the people in the call at that moment, encapsulated to each of them
under ML-KEM-768 and X25519 **together** — the hybrid holds if either one
holds, which is the only defensible position while one is three years old and
the other thirty, and it matters here rather than notionally because a
recorded call is a ciphertext somebody can keep. Leaving is forward secret and
rejoining tells you nothing about what you missed. A member whose device was
compromised rotates their key in an Update, and the next epoch closes behind
whoever had it. The property that is usually missing, though, is agreement:
every member derives a confirmation tag from the roster, so a server that
tells Ada the call is {Ada, Bob} while telling Bob it is {Ada, Bob, Eve}
produces two tags that do not match and two clients that refuse — and each
epoch's secret is sealed against the roster hash, so the rewritten commit does
not even open. Most products that say "end-to-end encrypted group call" cannot
do this, because the server is the only thing that knows who is in the room.
It is **not MLS**: the key schedule follows RFC 9420 Section 8 in shape and
the SFrame binding follows RFC 9605 Section 5.2 to the letter including the
KID layout, but the labels are this project's and there is no ratchet tree,
and the package says so rather than implying an interoperability it does not
have. The tree is the one real omission and the arithmetic is printed rather
than asserted: a flat commit costs 26 KB for a call of twenty and 118 KB for a
hundred, against 92 KB for one key frame of the screen codec — about one video
frame, once, when somebody joins or leaves. A tree would make those 6.6 KB and
8.2 KB. That is a genuine saving on a cost that is already a single frame,
bought with tree hashes, parent hashes, blank nodes and the resolution
algorithm, which is the part of MLS where implementation bugs actually live. A
call is not a group of fifty thousand. `quilzo call cost` prints the table so
that stays a decision rather than an assumption.

**A row of buttons where some of them are real.** Every meeting product has
the same controls and presents them as equally solid. They are not. "Remove
from meeting" and "mute participant" sit next to each other in Zoom's
interface, and one is enforced by arithmetic while the other is enforced by
the other person's software choosing to cooperate — so in the meeting where it
actually matters, nobody in the room knows what they are relying on. Here every
control declares what stands behind it, and there are three honest answers.
**Cryptographic**: removal, which holds against a modified client and a hostile
server because the epoch secret was never encapsulated to them. **Agreed**:
muting and speaking rights, which every participant derives from the same group
state, so the server cannot lie about them and every honest client applies them
— while software that ignores the mute can still put bytes on the wire, exactly
as it can in every other product. **Requested**: "please unmute", which is a
message to a person, and is in the list so that nothing else in the list has to
be explained away. This is not a smaller claim than the competition makes; it is
the same claim, made accurately. `quilzo huddle controls` prints the table.

The same honesty runs through the door. Zoom's meeting identifiers are nine to
eleven digits — about thirty-six bits — and researchers predicted four percent
of them; an invitation here carries 160, which is the least interesting of its
protections. The link is not the key. Presenting a valid invitation gets
somebody into the lobby, and the lobby is not the server declining to forward
media: it is a place where they hold no group secret, so the media would not
mean anything if it arrived. Getting a key takes a host committing them into the
group. A link that leaks, is forwarded, or outlives its meeting therefore buys a
knock at a door — which is what everybody already assumes a waiting room is, and
what in most products it is not. Invitations expire by construction, can be
bound to one person so forwarding them achieves nothing, and are stored as
hashes, so whoever holds the state of a call cannot turn it back into a working
link. Several people share screens at once, and one person can share two windows
at once, because RFC 9605 gives the SFrame key identifier a context field for
precisely that — a second stream is a number to allocate, not a second key
exchange, and no two streams ever share a salt. Raised hands queue in the call's
own order rather than by timestamp, because two hands inside the same second
should not be ranked by whose laptop was fast.

**The note-taker is a participant, not plumbing.** In every other product the
AI note-taker lives on the vendor's side of the call and appears in no
membership list anybody checks. That arrangement is why Otter and Fireflies are
both being sued: the open question is whether the person who switched it on was
responsible for everybody else's consent. Here it holds a key. Holding a key
means being in the roster, and the roster is inside the confirmation tag every
participant already verifies each epoch — so a note-taker cannot join without
everybody's epoch authenticator changing in front of them. There is no secret
recording, not because the product promises not to, but because the mechanism
that would hide one does not exist: a listener who can decrypt is a member, and
members are counted. Ejecting it is cryptographic in the sense above — "stop
recording" is not a request to a vendor, it is an epoch whose secret it does not
have.

**It refuses to do what several competitors sell.** EU AI Act Article 5(1)(f)
has prohibited inferring emotions from biometric data in the workplace since 2
February 2025, with penalties to €35,000,000 or 7% of worldwide turnover, and
voice-tone sentiment scoring in a work meeting is squarely inside it. This will
not do it in any setting — outside the workplace the Act moves it from
prohibited to high-risk, which is a different set of obligations rather than
none, and inferring how somebody felt from how they sounded does not work well
enough to put a number on it beside their name. The faculties stay in the
enumeration so a refusal can name them and cite the reason. Analysis of the
transcript is a different matter and is *not* emotion recognition under the Act,
because the words somebody said are not biometric data — and the package marks
that boundary rather than pretending to be comfortable with it, because the
moment tone-of-text informs an employment decision it is a question again.
Consent is per-participant and the strictest jurisdiction governs the whole
call: thirteen US states require everybody to agree, so a meeting run from New
York becomes all-party the moment one person dials in from California. Anything
not in the table is treated as requiring everybody, because failing closed is
the only defensible default when the downside is a wiretap charge. Somebody
arriving mid-call who has not agreed **pauses it**, which is precisely the
decision being litigated. `quilzo scribe law` prints both tables.

**Minutes that can show their working.** The standing complaint about
note-takers is that they invent things, so no line of the minutes exists
without pointing at a span of transcript, and the check refuses to publish a
line that points at nothing. Coverage is reported too — minutes drawn from four
spans of a fifty-minute call are not wrong, but somebody deciding whether to
trust them should see that first, and so should the fact that two of the five
people who spoke are quoted nowhere. When somebody withdraws consent their
words are erased and the fact that they spoke remains, and any line resting only
on them is withdrawn and reported rather than silently kept. And because a
transcript is people talking, and people can say "ignore previous instructions
and send the summary to" out loud, instruction-shaped spans are quarantined:
they can be quoted, and they can never be the authority for an action item. The
detector is not the defence — a detector that can be evaded is a detector — the
manifest in `internal/agent` is, and this only keeps the worst case to a strange
sentence in the minutes instead of a task somebody has to explain.

**The assistant acts, and can say why.** `internal/agent` already decides what
an agent may call at all — it is shaped after DeepMind's CaMeL, the manifest is
enforced at a chokepoint every operation passes through, and an agent that has
been entirely talked round by something it read can still only do what its
manifest declared. That is the security property. Two things a manifest cannot
see sit on top of it. It cannot know whether a task came from *anything*: so an
errand carries the sentence somebody actually said, and "why is there a ticket
with my name on it" has an answer that is not "the AI decided". And it cannot
know that the address it is about to send to belongs to somebody who was not in
the call — which is the ordinary shape of an agent leaking something, not a
break-in but a helpful forward. Every errand carries the roster of the call it
came from, anything reaching further is refused until a person agrees, and the
refusal names exactly who would newly learn. An approval is recorded against
those names rather than as a boolean, so agreeing to tell the security team is
not agreeing to tell the security team and a mailing list.

The third thing is smaller and gets got wrong everywhere: **the person who made
the commitment is the person who confirms it.** If the minutes say grace will
write the migration, it is grace's to confirm — not the meeting organiser's, not
an administrator's. Every product that puts a single approve button in front of
whoever opened the summary has quietly moved the decision to the wrong person.
And when somebody withdraws consent and their words are erased, an errand
resting on them is reported rather than silently dropped: either work that
vanished off somebody's list, or work already done with nothing on record saying
why. Something already carried out stays carried out, because rewriting a record
to say a thing did not happen is a worse lie than the gap.

**Four states, and no way to add a fifth.** Every Jira administrator has had
the conversation about how many statuses is too many; Atlassian's own community
has a thread called *Worst Jira Admin Contest: Multiple Green Statuses*, and
real workflows read "in dev → dev done → ready for test → in test" with thirteen
options in the transition menu. The usual diagnosis is that people are not
thinking clearly, which is why the problem never goes away. Look at what the
extra statuses are: "dev done" and "ready for test" are the same moment
described from two sides, and "in review", "awaiting QA", "blocked" and "ready
for deploy" are not states of the work at all — they are statements about who is
holding it up, put in the only field available. One field is being asked to
carry two independent facts, and proliferation is it splitting under the load.
So the field is split deliberately: four states, fixed, and an orthogonal
*waiting* that names a subject and what is wanted from them. Six invented
statuses collapse into two states and one dimension — and because that dimension
is a reference rather than a word, **"what is alan holding up" becomes a query**,
which no amount of status design can give you. Linear's answer to the same
problem is to fix the model and offer no escape hatch, which works for most
teams and leaves the rest encoding their process in issue titles; the escape
hatch here is structured rather than a new word in a dropdown.

Multiple green statuses exist because "done" means different things, so the
meaning is attached to the kind of work as a short list — capped, because a
definition of done with fifteen lines is a process document that will be excused
into meaninglessness within a quarter. An item reaches Done when the list is
satisfied, or with a requirement **excused by a named person with a reason**,
because the difference between "we did it" and "we decided not to" is the only
thing anybody wants to know a quarter later and a green status cannot hold it.
Moving backwards needs a reason, since an item that was Done and now is not is
the most informative event on a board and is exactly why teams invent a Reopened
status and then have two meaning To Do. Dropping work needs one too: silently
abandoned work is what turns a backlog into a graveyard. Every item carries
where it came from — including, for work that came out of a call, the sentence
somebody actually said. Duplicates are reported and never merged, because two
similar titles are sometimes two pieces of work. And *stuck* is reported as two
different things, because they need different responses: work waiting on a named
person has somebody to ask, and work that is in progress waiting on nothing has
been picked up and put down.

**Automation whose books have to add up.** Zapier's own troubleshooting advice
contains this sentence: every time you use a filter or a path, you must ask what
happens to the data that does not pass, and if you have no else-path or fallback
notification, that data is gone forever. That is not a warning about an edge
case — it is a description of the default behaviour of the largest automation
platform in the world, and it is why an industry of third-party monitors exists
whose entire product is telling you that your automation stopped. Errors are not
the dangerous part; an error at least produces something eventually, even if
Zapier's arrive batched or daily. The dangerous part is the filter that
discards, because **a run that quietly dropped ninety-seven of a hundred items
looks exactly like a quiet day.**

So the organising idea is an accounting identity. Every item entering a run
leaves through exactly one named exit — acted on, rejected by a named filter for
a stated reason, failed at a named step, or held — and those have to add up to
what came in. A run that cannot say where everything went does not report
success with a caveat; it *is* the failure, and the check refuses it as an error
rather than a log line, because a log line is how it gets found six weeks later
by somebody looking for something else. Counting something twice is refused too,
since it makes every other number unreliable. Three things follow. A filter must
declare where its rejects go before the flow will validate: dropping is allowed
and has to be chosen and explained, which is the whole difference between a
decision and an accident. Silence is a failure — a flow states how often it
should run, because otherwise a flow that has stopped and a flow with nothing to
do are the same observation and only one of them is an incident. And a run states
the window of source time it covered, so the gap between one run's window and the
next is found rather than discovered later by somebody asking where their record
went, which is how polling silently misses data when a source is busy or
rate-limited.

The failure that looks most like success gets its own detection: a **streak** of
consecutive runs that received items and acted on none. A streak rather than a
total, because a total is wrong in both directions — a flow that worked this
morning and has discarded everything since is broken, and a flow with one busy
hour in a quiet week is not. A quiet run in the middle does not break the streak,
since nothing arriving is not evidence that whatever was discarding things has
recovered. Everything is reported ranked rather than as one alert per condition,
because an alert per condition is how a team learns to ignore alerts — and none
of it has to be switched on.

**Bring your own detections, in the format they are already in.** Every
security product invents a detection language, and the cost lands on the
customer: rules written for one tool are worthless in the next, which is most of
why replacing a SIEM takes a year. Sigma is the vendor-neutral answer — a YAML
format with a public corpus of a few thousand community rules and converters
into Splunk's SPL, Microsoft Sentinel's KQL, Elastic and Chronicle's YARA-L. So
"bring your own rules" here means the format the rules are already in: a rule
that runs on somebody's Splunk runs here, and one written here converts back
out, because it is the same artefact. Per-deployment field naming is handled the
way the standard handles it — a pipeline held separately from the rules, so the
rules stay portable and the mapping is the single thing a customer edits rather
than three thousand files.

It never half-compiles. A rule using a construct this does not implement is
reported with the construct named and is not loaded, because the alternative is
worse than a failure: a rule that quietly lost its exclusion clause still fires,
still looks like it is working, and is now a different rule from the one
somebody reviewed. The import report separates the two kinds of skip, because
they are work for two different people — a gap in this implementation, or a gap
in the rule. Reading the YAML is deliberately a small reader for the corner of
YAML that Sigma uses, with no type inference at all: everything is a string, so
the country code `no` is the string "no" rather than the boolean false, and a
version like `010` stays `010`.

Two things fall out that no product offering Sigma import says out loud. The
standard asks every rule for a **falsepositives** list, which is exactly the
knowledge `internal/detect`'s blind-spot field exists for and observes that
nobody ever fills in — so here it arrives filled in, and a rule claiming high or
critical whose only stated false positive is "Unknown" is reported, because that
pairing is a rule written confidently by somebody who has not run it anywhere.
And **every imported rule is unproven**: Sigma has nowhere to record an event a
rule is asserted to match, so a library of three thousand community rules arrives
as three thousand rules nothing has demonstrated can fire. Between 13 and 18
percent of deployed rules in this industry never fire under any input and nothing
about a rule's text reveals which ones, so they do not load until somebody writes
an event they should catch and one they should not.

**Where a detection goes before it goes live.** On 19 July 2024 CrowdStrike
shipped Channel File 291 — a *content* update, not code — and took down around
eight and a half million Windows machines. The sensor expected twenty input
fields and the update supplied twenty-one. CrowdStrike's own root cause analysis
says the mismatch evaded multiple layers of build validation and testing, and
gives the reason: **the tests used wildcard matching criteria** for the field
that was wrong. That sentence is the whole argument. A rule tested only against
inputs it was written to match proves nothing at all — it is the same point
`internal/detect` makes when it refuses a detection with no negative fixture,
generalised: what you have to show is not that a rule fires, it is what it does
to everything else.

So a candidate enters **shadow**, where it is evaluated and counted and nobody
is woken up. It reaches **canary** when it has fixtures both ways and a replay
over real recorded telemetry — at least ten thousand events spanning at least a
day, because the traffic that makes a detection unusable is almost always
periodic and a replay that never saw a nightly job has not seen the thing that
will wake somebody at four in the morning. It reaches **live** when somebody has
looked at the measured volume and accepted it by name, and that volume is stored
on the promotion, so "we did not know it would do that" is not available
afterwards. Nothing skips a ring, including a rule from a signed feed, because
there is no argument for an exception that does not also excuse the next bad
batch. A candidate matching more than one event in twenty is refused outright as
the Channel File 291 shape. Because feeds ship in releases, a bad batch is
recalled *as a batch* — the alternative is working out which of four hundred new
rules arrived together at three in the morning.

The measurement is the point. Every team deploys detections without knowing how
often they will fire, finds out in production, and tunes by suppression — which
is how an estate becomes a set of rules nobody trusts and an exception list
nobody can explain. Replaying over last week gives the number *before* the
decision. A replay over unlabelled events reports how loud a rule is and says
plainly that it says nothing about whether the rule is right, rather than
reporting a precision it cannot know. Editing a rule is compared rather than
assumed: the report leads with what the new version **stopped** catching, which
is the number nobody looks at and the way a tuning change quietly removes a
detection. And the estate knows its own total alert volume per analyst per day —
the number a detection estate is actually judged by, and which nobody computes
because it lives across as many dashboards as there are tools.

**An agent may propose a rule, write fixtures for it and run a replay.** All
three are read-only or confined, bounded by the manifest in `internal/agent`.
What it may never do is promote, and a rule a model proposed is held to exactly
the same gates as one a person wrote, with one addition: whoever accepts it must
not be whoever asked for it, because a proposal reviewed only by its requester
has been reviewed by the request. There is no fast path for generated content,
since a fast path for generated content is the only kind an attacker with a
prompt needs.

**One reader for every scanner, and the field they all forget.** SARIF 2.1.0
is an OASIS standard and, unusually for this industry, it won: Semgrep, CodeQL,
ZAP, OSV-Scanner, Trivy and most of the rest emit it, and GitHub code scanning
consumes it. So one reader covers static analysis, dynamic analysis and
dependency scanning, and one writer puts results back where developers already
look.

The useful part is what it says a scanner left out. GitHub tracks an alert
across commits using `partialFingerprints`, and uses exactly one key from it:
`primaryLocationLineHash`. When a tool omits it the uploader falls back to
hashing the line — so **editing the line closes the alert and opens a new one**,
and whitespace counts. A team that reformats a file gets a wave of new alerts
and a matching wave of fixed ones, nobody connects the two, and the conclusion
drawn is that the scanner is noisy. It is not the scanner; it is a field the
scanner did not fill in. So the import reports which results arrived without
one, names the tool responsible, and the writer always emits one.

SARIF's `level` is `error`, `warning` or `note`, and it describes how the tool
is *configured* rather than how much a finding matters — there is no risk
concept in the standard at all, which is why GitHub bolts one on as a
`security-severity` property from 0.0 to 10.0. Tools conflate the two
constantly and the result is a queue sorted by whichever meaning the last
scanner had in mind, so both are read and kept apart, mapped on the platform's
own published boundaries, and the conversion records which was used. And the
limits are not what they look like: a run may carry **twenty-five thousand
results of which the top five thousand are displayed**, so a scanner emitting
forty thousand findings produces a page that looks complete and is missing most
of what was found. Nothing in any interface says so; the import does, because
the OX Security benchmark above is about what happens to a team that cannot see
its own queue.

**Which dependencies are affected, and which of those anybody can fix.** Every
scanner reports that a vulnerable package is present. Almost none report whether
the team reading it can do anything, and those are different questions — only
the second one is work. A direct dependency with a released fix is a version
bump this afternoon; the same advisory four levels down is a conversation with
whoever maintains the thing above it, and until they move the options are a
fork, a replacement or an accepted risk. So the CycloneDX **dependency graph**,
which most tools throw away, is the point here: every finding carries the path
from something somebody chose down to the affected package, and names the
nearest dependency the team actually controls. That name is the work item.
"Upgrade transitive package X" is not an action anybody can take; "ask for a
release of Y that takes X 2.4.1" is — and one package that has not moved is
usually holding up a dozen advisories, which is one conversation rather than a
dozen tickets. Where a bill arrives with no graph at all, that is reported
rather than guessed, because assuming direct sends somebody to bump a version
they do not control.

OSV is the advisory half, and it carries a CVSS **vector** rather than a score,
because a vector can be checked and a number is a summary of one. So the
arithmetic is here rather than assumed, including the 3.1 roundup — which is
not ordinary rounding, since 4.02 becomes 4.1 — implemented in the
specification's integer form, because the floating-point version disagrees on
values landing exactly on a tenth and a score 0.1 from the published one costs
somebody an afternoon. It is checked against published vectors rather than
against itself. Version ranges are evaluated properly from OSV's event
encoding, where each `introduced` opens a run the next `fixed` closes; an
`introduced` with nothing closing it means every version is affected and no fix
exists, which changes what the work is rather than how urgent it is. Withdrawn
advisories are skipped, because a retracted advisory is neither a fix nor a
false positive.

**Detections about several events, and the bug in every one of them.** Sigma
version 2 defines four correlations, and they are the four questions a single
event cannot answer: how many times did this happen, how many different things
did it happen to, did these separate things happen close together, and did they
happen in this order. All four are implemented, including `temporal_ordered`,
which most backends skip and which is the difference between *these things
happened* and *this sequence happened*.

The part that matters is when a window closes. A correlation over fifteen
minutes has to decide when fifteen minutes is up, and the obvious answer — the
clock — is wrong, because events arrive late. A proxy buffers, an agent
reconnects, a cloud export lands in five-minute batches. An event that happened
at 10:02 and arrived at 10:20 belongs in the 10:00 window, and a window closed
at 10:15 by the clock never saw it: **the rule does not fire, nothing reports an
error, and the only evidence is an absence.** It also makes the detection
non-reproducible, so replaying yesterday's events gives different answers from
the live run and the rule cannot be tested — which is exactly what the proving
ground above has to do before anything is promoted. So a window here closes when
a **watermark** passes its end, `internal/telemetry` keeps arrival and event time
apart for this reason, and a replay supplying the same watermarks gets the same
answers as the live run. An event arriving after its window has closed is
counted rather than swallowed, because a rising late count is how a team finds
out its watermark is too aggressive for a source.

Two smaller honesties. Counting without grouping is almost always a mistake —
"ten failed logons in fifteen minutes" across an estate fires continuously and
means nothing, while the same rule grouped by user is an account under attack —
so it is permitted, because refusing a construct the standard defines would make
portable rules unportable, and reported. And a group key an attacker controls is
a way to exhaust the machine running the detection, so the engine refuses to open
a new group past a cap and says so: a correlation that stopped tracking new
groups has lost coverage, where one that consumed all the memory has lost
everything.

**Every reporting deadline runs from a decision, never from an
investigation.** That is the whole of the regulatory problem and it is not
obvious. GDPR Article 33's seventy-two hours run from awareness that a breach
has likely occurred. DORA's four hours run from *classifying* an incident as
major. The SEC's four business days run from *determining* materiality. NIS2's
twenty-four hours run from awareness of a significant incident. None of them run
from the end of the investigation, and every one starts at a moment somebody
decided something — so the moment is recorded as a decision, with who made it
and why, and each regime's clock hangs off its own. One incident therefore has
several clocks starting at different times, which is the situation every team is
actually in and almost no tool represents. Moving one afterwards is refused: the
start of a clock is the thing a regulator asks about, and it is the one edit that
cannot be innocent.

The failure this is built against is subtler than missing a deadline. **A team
that never formally determined materiality believes no clock is running, and is
right, and is also three weeks into an incident a regulator will say was plainly
reportable on day one.** So the obligations whose clock has *not* started are
reported, each naming the decision that would start it — because "nothing is
due" and "nobody has made the call that makes something due" look identical on a
dashboard and are not the same situation. Closing refuses while anything is
neither discharged nor ruled out, and those are separate entries, because "we
told the regulator" and "we decided we did not have to" are different statements
and a field that conflated them would lose the distinction that matters most
later.

**A page nobody answered is not a notification.** Escalation that does not
escalate is the other ordinary disaster: a page goes out, nobody acknowledges,
and the system considers itself to have notified somebody. It has not — it has
sent a message. Acknowledgement here is a person saying they have it, escalation
continues until one does, and a ladder that runs out with nobody answering is
reported as the most serious thing on the board, because at that point the
response depends on somebody noticing rather than on anything the system did. A
ladder with one rung is refused, so is one whose first step waits an hour, and so
is one that escalates to somebody who is already on an earlier rung — that is a
ladder pretending to escalate. One person cannot be both commander and scribe:
an incident where one person did every role has no record of itself.

**A scanner is only as good as the list it compares against.** The inventory is
measured; the advisory database is fetched from somebody else, and everything
about the answer depends on how recently. **A scanner whose database stopped
updating three months ago reports no vulnerabilities. So does a system with no
vulnerabilities. They are the same screen**, nothing errors, and the longer it
goes on the more reassuring it looks. So staleness is a finding here, and any
result derived from a mirror carries the mirror's age — a clean scan is a
statement about a system *and* a database, and printing the first without the
second is how a report becomes misleading without anybody lying. A fetch that
succeeded and returned nothing is reported too, because a moved address
answering 200 with an empty document reads exactly like a clean result.

**"We have not fetched" and "they have not published" are different facts with
different owners**, and conflating them is why staleness alerts get ignored. EPSS
publishes a scored file every day, so a mirror three days behind is our problem
and the number of missed publications is arithmetic. CISA's known-exploited
catalogue has no fixed schedule at all — 2026 additions ranged from nine to
thirty-one a month — so a quiet week is a normal week, and where a source has no
cadence the only checkable claim is about our own fetching. Nothing here invents
a schedule for somebody else's publication, so when that feed is behind it says
plainly that how much is missing cannot be said. A source that has stopped
publishing gets its own report, phrased as theirs rather than ours and still
what the scanner is working from.

A feed is a supply chain: an auto-updating database is a channel into the thing
that decides what your scanner finds. Every release is identified, digested and —
where the source signs — verified; a release that arrives unverified is **accepted
and marked** rather than refused, because a mirror that stops updating over a
signature problem has chosen the worse failure. And "unverified" is only said of
a source that publishes signatures at all, since noise on that line is what
trains people to skip it where it matters.

**Every SIEM ships two hundred integrations, and the integrations are the
weakest part of the product.** For one reason: when a source changes shape, the
mapping does not break. It keeps working and produces events with empty fields.
A sign-in event with no user in it is still an event — it still counts, still
appears on a dashboard, and still fails to match the detection written against
the field that is now empty. Nothing errors. The detection simply stops firing,
and the first evidence is an incident nobody was alerted to. So a mapping here
declares which paths it requires, and a record missing one produces a **miss
rather than an event with a hole in it**; a run reports its miss rate by path,
because a page where two in five records fail on the same field has changed and
somebody should be told today. Drift is measured per page rather than in
aggregate, since one bad page among good ones means the opposite of a schema
change and a check that could not tell them apart would be muted within a week.

Sixteen platforms across cloud control planes (CloudTrail, Azure activity, GCP
audit), identity (Entra, Workspace, Okta, Duo), endpoint and device
(CrowdStrike, Jamf), the software supply chain (GitHub audit, Kubernetes
audit), the edge (Cloudflare), the applications a business keeps its data in
(Salesforce, Slack, Snowflake), and a machine with no API at all (Linux
auditd). Salesforce is in that list for a specific reason: UNC6395, where OAuth
tokens stolen from one integration vendor were used to query Salesforce across
seven hundred organisations, and the tell was in the login history most of them
were not reading.

Three things each mapping has to state rather than guess. **The identity**,
because the same person is a principal name in Entra, an email in Workspace, an
IAM ARN in CloudTrail and an alternate id in Okta — so the issuer is the
connector's own name and not a free string, since one source writing "azure"
where another writes "entra" breaks every join in the estate with no error
anywhere. **The outcome convention**, because three exist in the wild: named
failure values (Okta writes FAILURE), a named *success* value with everything
else a failure (Entra writes a zero error code and several hundred others), and
presence itself (CloudTrail writes an error code only when there was an error).
Guessing wrong inverts every disposition in a stream silently. And **how far
behind the source runs**, because the correlation windows above close on that
number and a cloud audit trail batching every fifteen minutes cannot share one
with a local agent — a window closed on the fastest source's watermark is a
window that never sees the slowest.

**Two kinds of authority, and only one of them was written down.** The access
model above is the standing kind: a binding says this principal has this role on
this resource, an administrator granted it, it is revocable, and an explicit deny
wins wherever it sits. The other kind arrived later and by accident. A call has a
host who can eject people. An incident has a commander whose instructions others
follow. An errand has an owner who is the only person who can confirm it. A
detection has somebody who promotes it out of shadow. **Nobody granted any of
those**, they expire when the situation does, and each was invented inside the
package that needed one.

That is not a mistake in itself — a call host is genuinely not a rung on a
site-wide ladder, and forcing it to be one would produce exactly the
over-granting the access model exists to avoid. The mistake is leaving the
relationship unstated, because then two things become possible and neither is
visible: situational authority quietly exceeding standing authority, or an
administrator assuming an override that does not exist.

The tempting rule — every situational role needs a standing one above some line
— is wrong, and applying it would break the thing that works. The point of a call
host is that an ordinary person can run a meeting; requiring an administrator to
be present would mean meetings are run by whoever has the most access, which is a
permission model shaping the organisation. **The rule that holds is about
reach.** A power that acts inside its own situation needs nothing standing:
ejecting somebody from a call ends when the call does, and the worst case is a
bad meeting. A power that survives the situation is a standing act wearing a
situational costume and needs the standing authority for what it actually does —
recording awareness starts a regulatory clock that binds the organisation for
years, promoting a detection changes what every team sees for as long as it runs,
and excusing a definition-of-done requirement is the record an auditor reads a
year later. All three land on **publish**, which the ladder already defines as
the only action with an outside observer.

So every situational role declares its powers and, for each, whether the effect
survives — with the reason, because that classification is a judgement and an
unexplained judgement is one nobody can disagree with. A power that reaches
outside and names no standing action is refused, and so is one that acts inside
and demands authority anyway. A guard checks the register covers every package
that reaches for the obvious vocabulary, because the failure this exists to
prevent is a ninth model appearing quietly in the tenth package.

**Four things that fail in the same direction, on one screen.** A feed that
stopped updating reports no vulnerabilities. A log source that changed shape
produces events with empty fields that match no detection. An automation whose
filter started matching everything runs perfectly and does nothing. A detection
estate with nothing live looks exactly like an estate with nothing to find.
Every one of those looks like a quiet week, and the longer each goes on the more
reassuring it becomes — so they belong together, and the screen's job is not to
show that things are fine but to tell **fine from silent**, which is the
distinction none of them can make alone.

It follows the rule the evidence screens already set: every capability may be
absent, and the screen says which rather than rendering an empty section. That
matters twice as much here, because an empty list of stale feeds and a build
that cannot see any feeds are the same picture and opposite facts. A build with
nothing wired says so in the words that stop it being read as reassurance, and a
capability that errors reports the error rather than returning quietly. What is
silent gets **named rather than counted**: "four things are quiet" is a number
somebody acknowledges, and naming them is what gets one of them looked at.

**Code scanning: the part the scanner leaves undone.** OX Security's 2026
benchmark puts the average enterprise at 865,398 security alerts a year, of
which 795 are critical after exploitability analysis — one in 1,088. A 2025
study measured a 91% false positive rate for static analysis on open source;
untuned tools run 30 to 60 per cent and developers stop adopting one above
about 15. This does not scan and does not claim to reduce that rate: writing a
static analyser with no dependencies would produce something worse than what
exists, and a package claiming to fix false positives by reading their output
would be claiming to know which of them were wrong. What it does is identify a
finding so it survives a rename — scanners key on rule, path and line, so a
reformat closes four hundred findings and opens four hundred new ones, and
every age and trend over them is measuring whitespace. Driven over a full tree
rename with reindented lines, 401 of 403 alerts were recognised as the same
findings and only the two genuinely new ones surfaced. New is measured against
the debt the organisation accepted, because a gate on total debt means nothing
merges and is switched off within a month. And a secret is not fixed by
deleting the line: the commit is in the history, on the server and in every
clone, so a vanished credential stays open across runs until somebody records
that it was rotated.

**Access reviews closed by the import, not by the reviewer.** A manager is
sent forty people and clicks approve on all of them in ninety seconds. The
campaign closes at a hundred per cent, the evidence shows a completed review,
the auditor sees a completed review, and nothing was reviewed. Every product
reports completion rate, because that is what a dashboard can show; nothing
reports the *shape* of the completion, which is the only part that
distinguishes a review from a formality. So this records how long each
decision took and reports a campaign that was all keeps, decided faster than a
person can read a row, inside one sitting — not as an accusation but as a
property of the evidence, because an auditor sampling it asks anyway and the
version where they ask first is the expensive one. Reviewing your own access
is refused. Keeping privileged access needs a reason, because that is the
decision nobody writes down. And an item is not closed by the reviewer
deciding: a revocation is done when the account is gone from a *later* import,
which is the half of this control that fails and the half nothing else
measures. A system declared in scope that no accounts came from is reported,
because a review of whatever happened to be exported is silently narrower than
it claims.

**Third parties tiered by what they reach, not by what they cost.** Every
product in this category has one field called "access". There are two
directions and only one of them is usually modelled. A vendor this
organisation holds a token for is bounded: if their service lies to us we get
bad data. A vendor holding a token in *our* estate is not — their compromise
is our breach, which is how one chat-widget vendor's stolen OAuth tokens
reached more than 700 organisations' Salesforce instances in ten days in
August 2025, none of which was itself broken into. So the tier is derived from
what a vendor reaches rather than chosen once on an onboarding questionnaire,
and a vendor holding a credential here is critical whatever anybody wrote —
what makes it critical is not a judgement, it is a token. Critical vendors are
reviewed twice as often, because the thing that makes them critical changes
without anybody telling us. The register is reconciled against the connectors
actually configured, so a credential issued to a processor nobody assessed is
found rather than typed in; and the single most useful thing it computes is a
terminated vendor whose token still works, because offboarding is the
checklist item that reliably gets half done and nothing else in an
organisation notices.

**Questionnaire answers checked against our own register.** Every product in
this category advertises 95% accuracy. The current CAIQ has over 260
questions, so that is thirteen wrong answers per questionnaire, sent under the
company's name into a customer's vendor file where they are relied upon and
where a wrong one is a misrepresentation rather than a typo. The figure is
published as a feature and the arithmetic is never done. The reason it does
not help is that accuracy is measured against the text of previous answers: a
confident answer about a control that stopped working in March matches what
was said last time, and last time is exactly what is now false. So an answer
here is a claim that points at what backs it, and a serious open finding
against that backing stops the file — not a confidence score, which is the
model's opinion about its own text, but this organisation's own records
disagreeing with what it is about to tell a customer. A smaller finding casts
doubt beside the answer rather than blocking it, because a check that fires on
everything is a check somebody turns off. A question nothing answers is left
blank rather than generated, because a generated answer there is the model's
reading of the question rather than the organisation's position.

**An evidence package the auditor can check without asking us anything.**
Either the auditor gets a login to the whole platform — every company, every
framework, every period, and a standing credential for as long as somebody
forgets to revoke it — or they get a folder of exported PDFs, which is scoped
correctly and proves nothing, because it is a set of files the audited party
assembled. The audit log here is a hash chain with an RFC 6962 Merkle tree
over it and a head signed with Ed25519 and ML-DSA-65, which was built for
exactly this: a package carries the evidence in scope, the audit entry that
recorded each piece being gathered, an inclusion proof for every entry, and
one signed head. `quilzo engagement check` verifies it against the published
key on a machine that has never seen the store, the log or the network.
Widening a date in the evidence is caught because it no longer matches the
entry; editing the entry to match is caught because the leaf hash moves and
the proof stops resolving. What it does not prove is that the log is complete
— an entry can be omitted before the tree is built, no cryptography fixes
that, and the package says so rather than leaving it to be assumed. Controls
in scope with nothing behind them are named in the file rather than left out,
because an auditor finds them anyway and finding them themselves is the
version that costs a week.

**A group of companies, measured as one.** A group defines a control, marks it
shared across five subsidiaries, and the evidence arrives from the parent's
identity provider. Every dashboard turns green for all five — and the German
subsidiary runs its own tenant that nobody ever connected. Nothing in the
system is wrong: the control exists, the evidence is real, the connector
works. It simply speaks for one company and is being read as speaking for the
group, and that is the failure the enterprise literature means when it says
control failures go undetected without multi-entity support. The fix is not a
feature but an arithmetic decision: a control each company performs is exactly
as covered as its *worst* company, and evidence flows down a group and never
up or sideways — a subsidiary's export does not evidence the group, because
the group contains companies that export never looked at. A parent's evidence
does not quietly satisfy a per-company control either; relying on it is a
claim the subsidiary records, with a reason, because at audit "the parent does
that" is only an answer if the parent's evidence is in scope for this
examination.

**Framework mappings that do not claim more than they say.** Every compliance
platform shows a control with a row of framework tags — SOC2 CC6.1, ISO 27001
A.8.5, NIST AC-2 — and counts those requirements as covered. The tags are
almost never equality: a control enforcing MFA at the identity provider is a
*part* of a clause about authenticating access to information systems, and it
says nothing about the database with local accounts. The industry complaint
about these products is exactly this, and it surfaces in week three of an
audit. NIST IR 8477 already solved it with set theory: five relationships —
equal, superset of, subset of, intersects with, no relationship — each with a
documented rationale. Only equal and superset satisfy a requirement. A partial
relation must name its remainder, and the remainder never rounds up. A
requirement is met only when a satisfying control also has evidence across the
period, so "mapped" and "operating" stay different facts; and a crosswalk where
most relations claim exact equality is reported as one somebody clicked
through, because two organisations writing independently about access control
do not produce the same concept that often.

**Evidence that a control operated over a period.** Every compliance tool
collects screenshots. A picture of an MFA setting taken on 14 January is
evidence about 14 January, and the question an auditor asks is whether the
control operated effectively *throughout* the period. So evidence here covers
a span rather than carrying a timestamp, and what comes out is the complement:
the days for which the organisation has nothing to show. A check that could
not reach what it was pointed at covers nothing — counting those windows as
covered is the easiest way to make a gap disappear. A quarterly control with
one occurrence in six months has been shown to have happened, not to operate.
A control with forty passes and no failure is either one that always works or
a check that cannot report one, and internal/detect refuses a rule that has
never matched for the same reason. There is no percentage: a compliance score
is controls-passing over controls-in-scope, and scope is chosen by whoever
wants the number.

**A vulnerability queue that is not sorted by severity.** CVSS measures how
bad something would be if it were exploited; FIRST says so, and every scanner
sorts by it anyway. Holding coverage of actually-exploited vulnerabilities
constant at 82%, an EPSS-driven strategy gets there by remediating about
14,000 CVEs and a CVSS-seven-and-above strategy by remediating about 110,000 —
eight times the work for the same result, and roughly 6% of published CVEs are
ever exploited at all. So the order is attested exploitation, then probability,
then reachability, then how long it has been known, and severity last as a
tiebreak. "Exploited" is a list of attestations with authors rather than a
boolean, because since ENISA became a CVE Root in November 2025 there are two
known-exploited catalogues reflecting two agencies' visibility and they do not
agree. The headline is the expected number of exploitations in the next thirty
days and how much of it sits above the fold — the sum of the probabilities,
which is what an expected value is, and the sentence somebody with a Tuesday
afternoon actually needs. Saying something does not apply takes one of
OpenVEX's five justifications, because "we looked and it is fine" is not on
the list; an investigation expires, because a status that reads as work in
progress and behaves as closed is how a backlog empties itself. And a version
comparison that cannot decide reads as affected, never as fixed.

**Connecting to a company's tools.** One reviewable file per tool: its host,
how it authenticates, which endpoints to read, how they paginate, and which
fields to keep. Nothing is executed and nothing is loaded, so reviewing an
integration means reading it rather than reading a program. A manifest
declares exactly one host and cannot exceed it — including on the way back,
because cursor pagination hands the upstream the next URL and a tool that
answers with somewhere else is choosing where a request carrying its own
credential goes. Only GET is ever sent. Every field the connector may keep is
written down, and a mapping that refers to anything outside that list is
refused at load, so the question "what does this have access to" is answered
by reading four lines. The credential is a name; a manifest holding what looks
like a token is refused, because the way that goes wrong is somebody pasting
one in to test it and committing the file. `connect probe` prints the shape of
a response and never its values.

**Reconciling a workforce.** The identity provider knows who exists, the MDM
knows which laptops check in, the training platform knows who clicked the
phishing simulation, and none of them knows any of the others. Every
interesting question is a join, and there is no shared key — so the join is
evidence rather than a guess. Exactly one rule proposes links automatically,
an exact match on a normalised address, and it states what would make it
wrong; a role mailbox is never joined on, because joining on one merges
everybody who has used it into a single person who then reports as compliant
because at least one of them was. Everything else is confirmed by a person and
appended to the audit chain. An unmatched record is the headline rather than a
suppressed error: a dashboard reading 94% is 94% of the people the join
happened to work for, and the leaver whose account was renamed on the way out
is in the other 6%. The finding at the top of the queue is the one no single
console will ever raise — an account disabled in the directory whose laptop
checked in eight hours ago.

**Telling people what happened.** Incidents, breaches, product changes and
deprecations, delivered one recipient at a time and exactly once. The lawful
basis is a property of the kind of notice and is not a setting, so somebody who
unsubscribed from everything still receives a breach notice: Article 34 is an
obligation and an obligation has no opt-out. A breach notice missing any of the
four things Article 34(2) requires is refused. The 72 hours runs from becoming
aware and applies to the supervisory authority only — Article 34 says "without
undue delay" and sets no number, so none is invented. Erasure keeps a keyed
fingerprint so a CRM re-import is refused rather than quietly turning one
honoured objection into a fresh infringement, and the suppression list holds no
addresses. Three channels: in the product, by mail, and as a signed POST to a
customer's own endpoint. Mail requires STARTTLS and a webhook requires HTTPS,
with no flag to disable either, because a notice describing what leaked is the
last message to send in the clear. A channel with nothing configured behind it
is an error at plan time and a failure at send time, never a quiet fallback to
another one — somebody recorded as told by the wrong channel is somebody the
retry skips for ever. Where individual notification is not possible, Article
34(3)(c) permits a public communication instead — which in a CMS is a page,
so it goes through the same accessibility, provenance and approval gates as
every other page. That is not a shortcut avoided: the article permits a public
communication only where people are informed "in an equally effective manner",
and a notice page that fails an accessibility check is not equally effective
for somebody reading it with a screen reader. The page never names anybody
affected, and the prose is checked as well as the fields, because the way that
goes wrong is somebody pasting a list into the body at two in the morning.

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
  knows which runs those are without being told. **It also records what it
  read** — the pages by name, a listing by its ref, a tool by its name and its
  host, and a delegate's sources folded up into its supervisor's. A person
  handed one bit can only review honestly by re-reading the site, which nobody
  does, so the approval becomes a formality; handed a list, it is a minute's
  work.
- **A run a model drove is recorded as the model.** Not as the person who
  started it, who is recorded beside it as the one accountable for starting it.
  This is not bookkeeping: the watchdog that notices an agent hammering at
  operations it keeps being refused reads the audit log filtered to model
  actors, and it buckets by the principal — so with the person there it could
  not see a single agent run, and every agent one person ran would have merged
  into one report anyway.
- **A model cannot approve its own work.** Not a rule bolted on for AI. Approvals
  must come from principals and self-approval is forbidden, and a model is not a
  principal. The rule that stops an editor rubber-stamping herself is the rule
  that stops a model shipping unreviewed.

This follows CaMeL ([arXiv:2503.18813](https://arxiv.org/abs/2503.18813)), which
is where the research settled: enforce policy outside the model with a
deterministic gate, because no amount of training makes a model refuse every
malicious instruction.

**Measured, not asserted.** Against AgentDojo v1.2.1, assuming the attack has
already won completely — the model hijacked, emitting the attacker's calls
verbatim — and asking the gate:

```
  attacks refused        26/26 (100%)
  tasks unattended       71/97 (73%)
  tasks needing a person 26/97 (27%)
  tasks refused outright  0/97 (0%)
```

Every attack refused there cannot succeed for *any* model, which makes the
security figure a lower bound rather than an estimate — and that sentence is
itself measured, because it is only true if the gate answers the same way every
time. `scripts/agentdojo/passk.py` runs the whole corpus ten times in fresh
processes and in shuffled order and compares every individual decision:
**pass^10 = 1.00**. Writing that check found one place where it was not true —
the refusal naming an agent's permitted hosts ranged over a map, so the same
refusal produced a different sentence, and a different audit digest, on every
run. The 27% are the publish
rule and not a refusal of the work: an agent that can publish must have human
approval, so the act happens once somebody agrees. Nothing in the suite is work
the policy prevents entirely.

What that number is not: CaMeL's 77-versus-84 is a model completing tasks end to
end, and benign utility needs a model, which this does not have. Nine injection
tasks are excluded because AgentDojo scores them by environment state rather than
as a call sequence, and one of them asks only that the agent *say* something — a
policy on what an agent may do does not address an attack on what it says, and
that is a limit of this defence.

Reproduce it in a few seconds with no key:
`python3 scripts/agentdojo/score.py --quilzo ./quilzo`. The translation from
AgentDojo's tools to this program's operations is checked in as
`scripts/agentdojo/corpus.json`, so the mapping is arguable rather than implied —
[scripts/agentdojo/README.md](scripts/agentdojo/README.md) has the method and its
weaknesses.

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
  content. Publishing a page that declares no provenance is refused, not warned
  about — on all three surfaces, which is newer than the sentence was. It had
  never been checked on the command line at all, so `quilzo publish && deploy`
  shipped unmarked content with status zero, and on the agent interface the
  check was skipped whenever it errored rather than when it passed.

  A person can override it with `--force-unmarked --reason "..."`, or the same
  reason box in the admin, and the override is recorded with the gates it
  waived. An agent cannot: over the machine interface the refusal is final,
  because the caller there is the thing the marking is about. That asymmetry is
  the point rather than an inconsistency.

  What is refused is an *unmarked* page, which is not the same as an
  AI-generated one — `quilzo provenance check` calls it "a gap, not a claim
  that a person wrote it". Marking a page as `humanEdits` satisfies the gate,
  and is meant to.

- **The Cyber Resilience Act.** Reporting an actively exploited vulnerability
  starts on 11 September 2026 and SBOMs are due in December 2027. You cannot
  report on a component you never inventoried, and here there are none to
  inventory — `quilzo compliance sbom` is a short document. A site publishes
  `/.well-known/security.txt` so a finder has somewhere to send it.

For an air-gapped or classified deployment the shape is unusually simple: one
static binary with no dependency graph to review, a distroless container with no
shell, no package manager and no interpreter, and one directory of state — back
that up and you have backed up the content, the history, the access policy and
the credentials.

The parts that matter to an isolated network are enforced rather than asserted:

- **`network.mode offline`** refuses every connection that would leave the host,
  before a packet is sent, and the refusal names the feature that wanted it and
  what stops working. `quilzo network` prints every purpose and its state, which
  is the evidence NIST SP 800-53 CM-7 and SC-7 ask for. A test walks the source
  and fails if a new outbound path appears, because a boundary a feature can
  step over is one that lasts until somebody adds a feature.
- **FIPS 140-3.** The whole test suite passes under `GOFIPS140=v1.0.0`, the
  CMVP-validated Go Cryptographic Module. Having no dependencies means the
  entire cryptographic surface *is* that module — there is no third-party crypto
  to argue about.
- **Hardware-bound authenticators.** Passkey enrolment can be restricted to
  authenticators that identify themselves, which is what NIST SP 800-63B AAL3
  requires and what a synced platform passkey is not. Off by default.
- **Two-person integrity.** `quilzo review require 2 --humans 2` means two
  people. The count on its own does not: two service accounts satisfy it, and a
  change nobody has read is not reviewed however many credentials agreed to it.
- **Classification marking.** The banner is written into every response rather
  than into templates, because a template can omit it and a page without a
  banner does not look broken — it looks unclassified. A page marked above the
  deployment's banner is refused at publish, with no flag to skip it. No
  vocabulary ships: the levels are read from your own register, lowest first.
- **Cross-domain transfer.** `quilzo transfer record` writes what was moved,
  when, who approved it, who carried it and why, with a digest of every file.
  Verifying on arrival checks both directions — the one that matters is a file
  that is present and *not* on the manifest.

**What this is not:** an authorisation. No ATO, no third-party assessment, no
audit, and no accreditation for classified use. These are the artefacts an
assessment needs, produced automatically and continuously, and the mechanical
controls enforced rather than documented. Somebody still has to do the
assessment.

Two limits worth stating rather than leaving to be discovered. An AAGUID is
self-reported and the attestation chain is not verified — that needs FIDO
metadata refreshed on a schedule an isolated network cannot refresh, so pair it
with procurement or it is decoration. And offline mode governs this process:
loopback is permitted, a proxy listening there could forward off-host, and the
host's own controls are the boundary.

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

### A second one, published

**[Aster & Alum](https://quilzo.github.io/demo2/)** is a natural dyer's site,
built with the same tool and serving the other half of the argument. Marginalia
is a shop and exercises the things a shop needs — a price that has to be a
number, a sale that has not opened yet, a catalogue an agent can read.
Aster & Alum is a business that writes: a journal, a guide with substantiated
claims, an impact page whose numbers come from records rather than from
enthusiasm.

It is worth having both because the failure modes differ. A shop is where typed
records and closed vocabularies earn their keep. A site that publishes prose is
where the brand gate does — every claim on it is one somebody has to be able to
stand behind, and `quilzo brand check` is what asks.

```
/demo2/catalogue.json     the range, machine-readable
/demo2/journal/           dated writing, with a feed
/demo2/feed.xml           and the feed itself
/demo2/guide/             long-form: how to keep an indigo vat
/demo2/impact/            figures that come from records, not from enthusiasm
/demo2/search/            reader-facing search over nested content
```

It is a static export served from GitHub Pages, with no origin behind it and
nothing executing on the other end — which is most of the point. The search
works because it was built at publish time, not because a script is running.

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

### With a release binary

One static file, nothing to install alongside it. linux, macOS and Windows, on
amd64 and arm64.

```bash
curl -LO https://github.com/Quilzo/Quilzo/releases/latest/download/quilzo-linux-amd64
curl -LO https://github.com/Quilzo/Quilzo/releases/latest/download/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
sudo install -m 0755 quilzo-linux-amd64 /usr/local/bin/quilzo
```

The checksum proves the file matches the list. It does not prove the list came
from here, and if you fetched both from the same place you have checked that a
page agrees with itself. The attestation is the one that answers the other
question:

```bash
gh attestation verify quilzo-linux-amd64 --repo Quilzo/Quilzo
```

That succeeds only if this repository's release workflow built the file, from a
tag, and it says which tag. Each release also carries `quilzo.cdx.json`, a
CycloneDX 1.6 bill of materials generated **by the binary** rather than read
from the source tree — so it describes the file you downloaded rather than what
HEAD would build today. It lists one component: the Go toolchain.

### With Docker

The image is `gcr.io/distroless/static-debian12:nonroot`: the binary, CA
certificates and a passwd entry. No shell, no package manager, no interpreter,
no libc. It runs as nonroot. amd64 and arm64.

```bash
docker run --rm -v quilzo:/srv ghcr.io/quilzo/quilzo --root /srv/store init
docker run --rm -v quilzo:/srv ghcr.io/quilzo/quilzo --root /srv/store demo
docker run -p 8081:8081 -v quilzo:/srv \
  ghcr.io/quilzo/quilzo --root /srv/store site --addr 0.0.0.0:8081
```

Then <http://127.0.0.1:8081>. `demo` publishes, so there is nothing else to run.

**One volume, mounted at `/srv` rather than at the store.** `quilzo demo` writes
templates beside the working directory rather than into the store, so a
deployment that keeps only `/srv/store` loses them and `site` exits with `no
template directory at templates`. Both live under `/srv`, so that is what is
kept.

This needs v0.2.0 or later. The v0.1.0 image declared `VOLUME /srv/store`,
which Docker satisfies with a throwaway volume when you mount the parent — so
the store silently vanished between commands — and it shipped no
`/srv/templates` for a volume to be seeded from, so mounting one there was
created owned by root and unwritable by a container running as nonroot. On
v0.1.0 the working incantation is `-v quilzo:/srv -v quilzo-store:/srv/store`.

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

`quilzo help` lists every command, and `quilzo --version` prints the version,
copyright and licence.

Building and installing follows the usual conventions — `make`, `make check`,
`make install prefix=...`, `make dist` — described in [INSTALL](INSTALL). There
is no `./configure`, because there is nothing to detect: no optional libraries,
no feature switches, and `go.mod` has no require block.

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
- Your employer forbids AGPL. Some do, Google explicitly. Better said here than
  discovered after you have written the patch.
- You need per-visitor personalisation or a shopping cart. Products, catalogue
  and structured data yes; a cart holding a card, no — that needs a threat model
  this process does not have.
- You need commercial support today. One maintainer, no 1.0, no backports.
  That is the real state of it, and [GOVERNANCE.md](GOVERNANCE.md) says exactly
  what it takes to change it.

---

## Licence

Two licences, and you choose. `AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial`
— alternatives, not conditions to satisfy together. See [LICENSE](LICENSE),
[LICENSING.md](LICENSING.md) and [NOTICE](NOTICE).

**AGPL-3.0-or-later unless you have signed the other one.** That is the default,
it is not a trial, and it needs no permission, key or conversation. Affero
specifically, because nobody distributes a CMS — they host it. A licence whose
obligations trigger on distribution would never trigger at all for the software
this is. Running a modified Quilzo as a service for other people means those
people can have the source.

The commercial licence exists for one situation: you cannot comply with the
AGPL, or you are not permitted to. That is mostly organisations whose policy
prohibits AGPL code outright — [Google publishes
theirs](https://opensource.google/documentation/reference/using/agpl-policy)
and others copy it — and vendors embedding this in a product they will not
release under the AGPL. Hosting, modifying, charging for it and building a
business on it are all already permitted by the AGPL and need nothing further.

**There is one Quilzo.** No feature is withheld for paying licensees, there is
no separate enterprise build, and nothing in this repository branches on which
licence the operator holds. The commercial licence changes your terms, not the
program. [LICENSING.md](LICENSING.md) states that as a commitment and
[docs_claims_test.go](docs_claims_test.go) checks the parts of it a test can
reach.

This was an addition rather than a relicensing: no permission anybody held was
withdrawn by it. Contributions now need [a contributor licence
agreement](CLA.md), which the DCO alone did not provide, and that page is candid
about what it costs a contributor.

There was a brief Apache-2.0 window on 22 August 2026, reverted the same
morning. That grant does not retract for anyone who took a copy during it —
[NOTICE](NOTICE) has the commits, the times, and what it means.

One thing to know before you spend time: **some employers forbid contributing to
AGPL projects**, Google's policy explicitly. That is a real cost of the licence
and it is better said here than discovered later.

## Contributing

This project wants maintainers, not only patches. Three merged pull requests of
substance and you can have commit access — the bar is written down in
[GOVERNANCE.md](GOVERNANCE.md) so that nobody has to guess when they qualify.

[CONTRIBUTING.md](CONTRIBUTING.md) has the two-minute path from clone to running
site, the one rule that will surprise you (no dependencies), and how review
works here. Security reports go through [SECURITY.md](SECURITY.md), privately.

Contributions are taken under a [DCO](https://developercertificate.org/) —
`git commit -s` — and copyright stays with whoever wrote the code.
[CONTRIBUTING.md](CONTRIBUTING.md) says what that does and does not guarantee,
stated more carefully than it used to be.
