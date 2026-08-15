# scrivet

A CMS where content can't be edited, only added to — and publishing is a pointer
moving.

```bash
scrivet init
scrivet add index=home.json about=about.json -m "first pages"
scrivet diff        # what would change
scrivet publish     # move the live pointer
scrivet rollback    # move it back
```

Go, single static binary, **2.6 MB**. The container image is **4.01 MB** on
`scratch` — no shell, no package manager, no libc. For a CMS that last part is
not incidental: WordPress's kill chain ends in *upload a plugin*, and an image
with no interpreter has no terminal step to offer.

Early, and CLI-first on purpose. There's no admin panel yet because a CMS whose
primitives only exist behind a web UI can't be scripted, reviewed in a pull
request, or driven by an assistant without pretending to be a browser.

## Why build another one

Two CMS disclosures from 2026 explain the design better than an argument would.

WordPress's **wp2shell** chained a REST batch-route confusion with SQL injection
to create an admin account and upload a plugin — pre-auth remote code execution
on a **stock install with zero plugins**, no account, no user interaction.
Drupal's **CVE-2026-9082** was SQL injection in the database abstraction layer
itself.

Both kill chains need the same two links: a query an attacker can influence, and
a place where writing data means writing something that later executes. You
don't harden that chain. You remove its links.

**No query for content.** Every object is immutable and addressed by the SHA-256
of its own bytes. Reading is a hash lookup on a file path, not a statement. There
is no UPDATE and no DELETE, so there's nothing for an injection to alter.

**Nothing you can write that later runs.** Templates aren't a programming
language — see below. WordPress's chain ends in "upload a plugin"; if there is
nothing uploadable that executes, the chain has no final step.

## Content is immutable

It's git's object model applied to content: blobs, trees, commits, all addressed
by hash, nothing ever modified. Editing a page writes a *new* blob and a new
tree; the old one is still there, still exactly what it was.

That makes publishing a pointer move — atomic, and instantly reversible:

```
$ scrivet publish
live is now 247648a6af0c  (1 change(s))
  previous 11ff531f2ffe is still stored; `scrivet rollback` moves the pointer back
  rolling back restores the content, not the fact that it was published
```

The reason rolling back a conventional CMS is frightening is that the previous
state was overwritten and has to be rebuilt from a backup taken at some other
time. Here it was never touched. Rollback can't half-complete.

Unchanged pages are literally the same object, so `diff` compares ids rather than
content — an unchanged page is *provably* unchanged without being read.

Git-backed CMSes get this integrity but are usually limited to static sites,
because serving means a build. scrivet keeps the object model and drops the
working tree: a ref move shows up on the next request.

## Templates that can't execute anything

Server-side template injection exists because popular template languages *are*
programming languages. Give one an attacker-influenced string and it reaches a
constructor, a class hierarchy, a subprocess.

This one has no functions, no arithmetic, no assignment, no imports, no attribute
access, no method calls and no recursion. Four constructs, and no way to add a
fifth:

```html
{{ page.title }}                      a value, escaped for its context
{% if page.subtitle %}…{% end %}      present and truthy
{% for item in nav %}…{% end %}       bounded iteration
{% raw page.body_html %}              deliberately unescaped
```

There's nothing to escape *from*, because there's nothing underneath — values
come out of decoded JSON and the only operations are lookup, truthiness and
iteration. Every classic sandbox escape is refused at parse time:

```
{{ page.title.upper() }}
  → not a value path. Names and dots only — there are no calls,
    operators or attributes in this language.
```

Go's `text/template` would have been the obvious choice and is the wrong one:
it calls methods on the data it renders, which is exactly the capability this
needs not to have.

**Escaping picks the context.** The common failure is escaping for HTML and then
landing inside `href`, where `javascript:alert(1)` contains nothing that needs
escaping and runs anyway. The renderer tracks whether a value lands in text, an
attribute, or a URL, and an unsafe scheme is *replaced*, not passed through:

```
<a href="{{ c.url }}">  with  javascript:alert(1)   →   <a href="#unsafe-url">
```

**Rendering always terminates.** Loops iterate over data, never a condition, and
depth, total output and iteration count are capped. That's a property, not a
hope.

**`{% raw %}` is greppable.** Real sites have rich text, and pretending otherwise
just pushes people to disable escaping globally. It's a distinct keyword rather
than a filter, so `scrivet audit` lists every place trust was extended — a review
someone can actually finish.

## Content types

A content type here is a flat list of fields. That's it — no nesting, no
references, no regular expressions, no `oneOf`. The omissions are the design.

```json
{"name": "article",
 "fields": [
   {"name": "title", "kind": "text", "required": true, "max_len": 120},
   {"name": "body",  "kind": "longtext", "required": true},
   {"name": "slug",  "kind": "slug", "required": true},
   {"name": "status","kind": "choice", "choices": ["draft", "review", "final"]},
   {"name": "hero",     "kind": "url"},
   {"name": "hero_alt", "kind": "text", "alt_for": "hero"}]}
```

```
$ scrivet type add article.json
added article with 6 field(s)  477f9cc57750
$ scrivet type bind news article
news must now satisfy article
```

Most CMSes reach for JSON Schema for this, and a CMS whose users define their own
content types is, by construction, a program accepting schemas from people it
doesn't fully trust. The standard advice is that untrusted schemas need
sandboxing. Rather than sandbox the features, I left them out:

| Left out | Why |
|---|---|
| `pattern` | Backtracking regex. CVE-2025-69873: a 31-character pattern costs about 44 seconds of CPU. |
| `$ref` | Fetched as a URL. CVE-2026-54690 is SSRF via a schema reference — `169.254.169.254` included. |
| recursion | A self-referential schema spins a worker until something kills it. |
| combinators | `allOf`/`oneOf` make validation cost combinatorial in schema size. |

What's left validates in time linear in the input, with no I/O and no recursion.
The test that matters measures it: ten times the input takes 0.8× the time,
because the length bound rejects before any format check runs.

Refusals name the field and say what's wrong:

```
$ scrivet add news=news.json
1 page(s) do not satisfy their content type:
  news does not satisfy article
    is_admin: not a field on type article
    slug: must be lowercase words joined by hyphens
    canonical: scheme "javascript" is not allowed; use http or https
    status: must be one of: draft, review, final
```

Undeclared fields are reported rather than ignored — silently accepting them is
mass assignment coming in through the front door. URL fields refuse
`javascript:`, `data:` and `file:`, so a validated page can't carry an injection
vector. Choices are compared literally, so `FINAL` is not `final`.

### Types are content-addressed too

A type has a hash, the same way content does, and a passing write records both:
this content hash satisfied that type hash.

That's what makes editing a type safe. Tighten `article` tomorrow and yesterday's
published pages don't retroactively become invalid — they point at the type they
actually passed, which still exists at its own address. "This page was valid
under this exact type" stays a checkable claim about two hashes, rather than a
claim about what a mutable file used to say.

### Enforced everywhere, and a test that says so

Validation runs on every write path: `scrivet add`, `scrivet assist`, the admin
save handler, and the MCP `write_page` operation. That's not a convention — it's
a test that parses the source, finds every function calling `SaveDraft`, and
fails if one of them doesn't consult the gate.

It found a fourth write surface the first time it ran. `scrivet assist` — the AI
path, the one most likely to produce content nobody typed by hand — wasn't gated.
Three times before this, a rule this project enforced in the CLI turned out to be
missing from the web UI. A control present in one interface and absent from
another is a control with a hole in whichever one people actually use.

### The editor is built from the type

If a page has a type, the admin renders the declared fields rather than whatever
keys the JSON happens to have: a date picker for a date, a select for a choice,
a number input with the declared range, the author's own labels and help text.
Declared-but-empty fields still appear, so a required field can't be invisible
and block every save.

Fields marked `alt_for` are labelled as descriptions of what they point at —
ATAG 2.0 Part B, the tool helping produce accessible content rather than checking
afterwards whether you did.

## Serving the site

```bash
scrivet site --addr :8081 --name "Example Co"
```

Separate from `serve`, which is the admin. Different audiences, different auth,
different exposure — running both on one port means one misconfiguration exposes
the editing interface.

**Caching falls out of the architecture.** A page's ETag *is* its content hash —
not derived from it, it simply is it. So cache invalidation stops being a
problem: a change is a different hash, and a conditional request answers itself.
Nothing needs purging on publish, because publishing moves a pointer and the next
request computes a different ETag:

```
$ curl -I /            → ETag: "0764cacd7b08…"
$ curl -H 'If-None-Match: "0764cacd7b08…"' /   → 304
$ scrivet publish
$ curl -H 'If-None-Match: "0764cacd7b08…"' /   → 200
```

**The Article 50 mark is injected into the page**, not just kept in a file. A
machine-readable marking has to be in the thing a machine reads:

```html
<meta name="c2pa:digitalSourceType" content="trainedAlgorithmicMedia">
<meta name="ai-generated" content="true">
<meta name="ai-human-reviewed" content="false">
```

Injected before `</head>` rather than asked of the template author — a legal
marking that depends on every template remembering a partial is one that will be
missing from the template nobody checked. Stale records aren't emitted: if the
page changed after the record was written, no claim is made about it.

## MCP, for agents

```bash
scrivet mcp                 # stdio
scrivet mcp --list          # what an agent can reach
```

Added now rather than earlier because the earlier research on this project
concluded MCP earns its cost for **remote, authenticated** access and not for
local deterministic work. Hosting changes which case this is.

**Four tools, not one per command.** The measured problem with MCP is servers
preloading every tool definition — naive ones cost roughly 35× an equivalent CLI
call, with reliability falling as the tool count grows. The 2026 fixes all say
the same thing: stop preloading. So `scrivet_find` describes the rest on demand:

```
7 operations behind 4 tools; an agent loads only what it searches for
```

Registering an operation doesn't add a tool. There's a test asserting that,
because otherwise the property is accidental.

**The read tool can't reach a write operation.** Without that the split is a
labelling convention and a read-only client could write by naming the operation.

**A refusal is not a failure.** Refusals carry code `-32001` with
`retryable: false`, distinct from the internal-error code. An agent reading
"denied by policy" as "the server broke" will retry, and retrying a refusal turns
one blocked action into a hundred.

**The gates apply here too.** This is the third interface onto the same content,
and the two before it each shipped with a control present in one and missing from
the other. Publishing over MCP runs the same accessibility and provenance checks
and refuses for the same reasons — with no override, because that's a human
decision:

```
error -32001: 1 page(s) have no provenance: index.
              Article 50 requires AI-generated content to be marked
```

**Anything an agent writes is marked AI-generated**, without being asked. An
agent calling a write tool is a model writing content, whatever the tool is
called — and the interface built for agents is the last place that should need
reminding.

### On authentication

The 2026-07-28 spec makes an MCP server an OAuth resource server and names the
pitfall: a server checking a token's signature and expiry but **not its
audience** will accept a token minted for something else entirely.

scrivet's tokens are opaque and issued by this server, so they're audience-bound
by construction — there's no other issuer whose token could validate here. That's
a smaller claim than OAuth 2.1 conformance and it's the true one. Multi-tenant
hosting behind a shared identity provider needs RFC 9728 discovery and RFC 8707
resource binding; that's a seam, not something pretended at.

## Proving when you published

```
$ scrivet timestamp stamp
root 731c36e8680f5365 stamped by https://freetsa.org/tsr
  requested at 2026-08-14T15:39:33Z (our clock, not evidence)
  token 4635 bytes; the authoritative time is inside it
```

Useful to anyone publishing regulated claims, prices, press statements or terms —
"the site said this on that date" becomes something you can hand to a third party.

**Why two mechanisms rather than one.** They fail in opposite directions:

- **RFC 3161** carries recognised evidential weight under eIDAS (via ETSI EN 319
  421/422/401). But the proof rests on the TSA's certificate chain — when it
  expires the token must be re-stamped, and if the TSA folds, every token it
  issued lands in a legal grey area.
- **Blockchain anchoring** has no authority to expire or go out of business, so
  it doesn't decay. What it lacks is formal legal recognition.

Legal weight that decays, or durability with no standing. The layered answer is
both: a token for the lawyer, an anchor for the decade. RFC 3161 is implemented;
the anchor is a defined seam, deliberately not a half-built version that would
report success before a block confirms.

**One stamp covers the whole site.** Content is content-addressed, so the
publication root commits to every page at once, and a page's membership is
provable from the tree afterwards. Per-page stamps would be more requests proving
less.

**A stamp of an older root is said to be one:**

```
what is live now has not been stamped; the stamps above cover earlier versions
```

### What this verifies, and what it doesn't

Requesting and storing a token is implemented. **Cryptographically verifying one
isn't**, and that's deliberate: an RFC 3161 token is a CMS signed structure, Go's
standard library has no CMS parser, and a hand-rolled partial verifier is exactly
the sort of code that looks right and accepts a forgery.

So `scrivet timestamp export` writes the token and its data, and prints the
command to check them:

```
openssl ts -verify -in stamp.tsr -token_in -data stamp.data   -CAfile <root> -untrusted <signing cert>
Verification: OK
```

That output is from this implementation against the real freetsa.org chain —
which also proves the ASN.1 encoding is right in a way round-tripping through my
own decoder could not.

The default TSA is free and **not eIDAS-qualified**. Fine for internal evidence;
anyone needing legal standing configures a qualified authority.

## PWA

`/manifest.webmanifest`, `/sw.js` and `/offline` are generated. As of 2026 every
major browser supports service workers and the manifest, and iOS 26 defaults
home-screen sites to web-app mode.

The service worker is **network-first**, which is the opposite of the usual
advice for speed and the right trade for a CMS: publishing must take effect
immediately, and a stale page is a worse failure than a slow one. A caching bug
in a service worker persists across reloads and serves stale content to someone
who can't work out why.

### llms.txt, with a caveat

`/llms.txt` is emitted because it costs a few lines. It's labelled honestly
rather than sold: adoption sits around one site in ten, roughly **40% of existing
files are plugin stubs**, and as of early 2026 no major crawler — OpenAI, Google,
Anthropic, Meta, Mistral — commits to reading it. They fetch the HTML. It's a
community convention with no standards body behind it. A cheap bet, not a
feature.

## Accessibility is enforced, not reported

There are two standards and most CMS vendors implement the easier one. **WCAG**
governs the content a site serves. **ATAG** governs the authoring tool, and its
Part B says the tool must actively *help* authors produce accessible content.

Part B is where almost everything falls down. A CMS that lets you publish an
image with no alt text and mentions it in a report nobody opens has helped
nobody. So the check runs at publish time and stops the publish:

```
$ scrivet publish

  pricing
    blocking  heading-level-skipped (WCAG 1.3.1)
      h3 follows h1; levels must not skip
    blocking  image-missing-alt (WCAG 1.1.1)
      an image has no alt attribute. Use alt="" if decorative, or describe it
    advisory  link-text-is-not-descriptive (WCAG 2.4.4)
      link text "click here" says nothing out of context

2 blocking accessibility failure(s); this content is unusable for someone.
```

Overriding is possible, because real sites have genuine exceptions — but it
needs `--force-inaccessible --reason "..."`. An override without a stated
justification is indistinguishable from not checking.

It renders before checking, because what a reader receives is the *rendered*
page: good content plus a template that drops `alt` is still an inaccessible
site, and only the output shows that.

**Advisory findings don't block.** A checker that fires on correct markup trains
people to reach for the override, and after that it isn't a control.
`alt=""` is a decision, not an omission, so it passes.

**A clean result is not a claim of accessibility.** `scrivet a11y` prints what it
checked *and* what it didn't — contrast lives in stylesheets this tool never
sees, and whether alt text is actually useful needs a person. A tool that implies
full coverage ends the conversation, which is the opposite of helping.

```
$ scrivet verify
  7 object(s) intact
  every object re-hashed to the id it is filed under
```

A conventional CMS can't answer "has anything in here been altered outside the
application". Tampering with an object on disk is detected on the next read and
by `verify`, because the id *is* the hash of the content.

## Continuous security posture

OWASP moved Security Misconfiguration from fifth place to **second** in the 2025
Top 10, and reported that essentially every application they tested carried at
least one instance. Their explanation is the part worth acting on: continuous
deployment without continuous checking creates an exposure window that widens
with deployment cadence.

So there's a scanner, and it runs on every admin request rather than when
somebody remembers.

```
$ scrivet posture scan
posture 58/100   2 high  2 low
  23 rules, 0 suppressed

  high     A sensitive file is readable by other users
           .scrivet/tokens.json is mode 0644 (token hashes and their roles)
           fix: chmod 600 .scrivet/tokens.json
           expose.file-mode  AC-3 AC-6 CM-5  A02:2025 Security Misconfiguration

  high     An API token lasts too long
           ci (svc-ci, author) is valid for 365 days, until 2027-08-15
           fix: scrivet token revoke 8ea763bb5952
           token.long-lived  IA-5 AC-2(3) SC-12  A07:2025 Authentication Failures

  not checked:
    audit log: the chain was not verified
```

Every rule maps to the NIST SP 800-53 controls it provides evidence for and to
an OWASP Top 10:2025 category. That mapping is not decoration — it's what makes
a finding something you hand an assessor rather than an opinion. `scrivet
posture explain <rule>` gives the reasoning, and the same reasoning is a page in
the admin, because a finding somebody doesn't understand is one they argue with.

### The design decisions that make it usable

**The rules are pure functions and the package does no I/O.** Every check
receives a `State` and returns findings. It cannot open a file, a socket, or a
subprocess. That makes each rule testable by construction, and it means a rule
can't be tricked into reading something it shouldn't — a scanner with filesystem
access is a file-disclosure primitive wearing a badge. One function, `Observe`,
turns the world into facts; the answer to "what could this possibly touch?" is
that function and nothing else.

**Not knowing costs points.** A scan that looked at nothing scores 0, not 100.
Converting absence of information into a claim of health is the single most
misleading thing a scanner can do, and it's the default behaviour of most of
them. NIST SP 800-137 is a document about *awareness*; under it, not knowing is
a deficiency rather than a neutral state, so it's priced like one. Every report
ends with what it couldn't check.

**Suppressions expire, and expiry is itself a finding.** Ninety days maximum,
with a required reason and a required name. A permanent exception isn't an
exception — it's a quiet decision to stop looking, made by somebody who won't be
the person who inherits it.

**Rules that a correct deployment can't satisfy get people to ignore the
scanner.** Terminating TLS at a proxy is normal, so `--behind-proxy` makes the
cleartext rule pass while leaving the *exposure* finding in place at a lower
severity. Interception and reachability are different problems and the scanner
says so.

**Severity is what an attacker gains.** A world-writable secret outranks a
world-readable one. An exchanged fifteen-minute admin session isn't flagged
while a long-lived admin token is Critical — flagging the fix would teach people
to skip it.

### What it checks

23 rules across access control, credentials, audit integrity, content
integrity, network exposure, and the agent surface. A few that are specific to
this tool rather than generic:

- an MCP operation that writes without declaring a required role
- a model authenticating with a person's token, which destroys attribution
  silently in a log that still verifies
- an audit chain that no longer verifies — Critical, because it invalidates
  every record including the ones about whoever broke it
- published content whose provenance record describes an older version

The dashboard at `/security` is server-rendered with no script at all. The CSP
on every admin response forbids it, and a security dashboard that needs a
client-side framework to tell you a token is world-readable has the dependency
the wrong way round.

## Material 3 Expressive, as CSS

The interface follows Material 3 Expressive — the design language, not the
framework. Every admin response carries `default-src 'none'; style-src 'self'`,
so there is no Compose, no web-component bundle and no JavaScript anywhere. The
shapes, the spring motion and the state layers are one stylesheet and add no
execution surface.

What that gets you: the ten-step shape scale including the Expressive
`large-increased` and `extra-large-increased` steps, the five-role type scale
with emphasized weights, the full set of colour roles with six surface-container
levels, and spring-physics motion expressed with CSS `linear()` — a sampled
spring curve rather than a bezier that only matches at the endpoints. Spatial
tokens overshoot, effect tokens don't, which is the M3 rule: a colour that
overshoots lands on a hue nobody chose.

### One deliberate departure, and a test that enforces it

M3's *standard* light scheme puts primary at tone 40, which lands near 4.5:1 on
white — WCAG AA. Adopting the baseline unchanged would have quietly downgraded
this interface from AAA. So the roles are drawn from the tones M3's own
high-contrast scheme uses, primary at tone 30, and every text pairing clears
7:1.

That isn't a claim, it's computed. `contrast_test.go` parses the stylesheet,
resolves the `var()` chains, and calculates every ratio in both schemes:

```
$ # swap primary back to M3's standard tone 40
$ go test ./internal/admin/ -run AAA
--- FAIL: TestEveryTextPairingMeetsAAAInBothSchemes
    light/filled button label: --on-primary is 5.94:1 (#f1ffff on #006c7e) — AAA needs 7:1
    light/link: --primary is 5.78:1 (#006c7e on #f8f9fa) — AAA needs 7:1
```

A palette checked once by hand is a palette that was correct on the day somebody
checked it. Nothing in a stylesheet fails when the contrast drops, so this does.
The same file also fails the build if anything sets `outline: none`, if a role
exists in one scheme and not the other, or if reduced-motion stops neutralising
the springs.

Targets are 48px rather than 44 — Material asks for 48dp and WCAG 2.5.8 asks for
24, and taking the stricter of the two costs nothing.

## Ready-made templates

Four starting points, covering the shapes people actually ask for:

```
$ scrivet template list
article     A single piece of writing: headline, standfirst, byline, date,
            body, tags. For news, a blog, or a long-form page.
docs        A documentation page: sticky contents on the side, a code
            example, a reference table.
landing     A marketing or product page: hero, feature cards, a quote. The
            shape most requested for SaaS and launches.
portfolio   Personal or studio work: a hero, a grid of projects with images
            and roles, an about section and a contact card.

$ scrivet template use landing
wrote templates/page.html from the landing starter
wrote templates/site.css
wrote templates/landing.json
```

They're **embedded in the binary**, not fetched. The usual shape for a theme
library is a registry you download from, and a CMS theme is markup that runs on
every page of a site — the highest-value place in the system to put something.
`template use` cannot be pointed at a URL. A template that ships with the tool
has the same provenance as the tool.

Each one is also a test fixture. The suite parses it, renders it with its own
sample content, and runs it through the accessibility gate — because a starter
is the first HTML most people publish with this tool, and shipping one the tool
would refuse to publish is the most embarrassing bug available. The same tests
check no starter reaches an external origin, none uses `raw`, and all of them
escape hostile content in every field.

They also have to degrade. Pages arrive with fields missing, so a structural
element whose label comes from absent content must not render at all — an empty
`<a>` is announced as just "link". That one was found by running the real gate
over a real store: a page left over from an unrelated demo had no `brand` field
and the header rendered an empty link on it.

## Importing from other systems

```
$ scrivet import old-blog.xml --dry-run
detected wordpress

1 page(s) from wordpress
  hello-world
    - <script> and its contents
    - 8 HTML tags flattened to text

  not imported:
    "Main Menu" (nav_menu_item) — a WordPress internal, not content
    "Deleted" — in the trash

  1 media URLs were found and NOT downloaded. Fetching them during an
    import would make this file a way to make requests from inside your
    network.
```

WordPress WXR, Markdown with front matter (Jekyll, Hugo, Eleventy, Astro), and
JSON. The report always says what it *didn't* import — an importer that quietly
drops half an export is worse than one that refuses, because the loss is found
months later by a reader.

**XML entities are not mitigated here, they're absent.** XXE is where CMS
platforms get hurt: CVE-2021-29447 was XXE through WordPress parsing an ID3 tag,
and WordPress 5.7 had another. The usual fix is a parser setting that disables
external entities, which works until someone forgets it on the next parser they
add. Go's `encoding/xml` doesn't process DTD entity declarations at all — a
document declaring `<!ENTITY xxe SYSTEM "file:///etc/passwd">` fails with
"invalid character entity", because the declaration was never read. Verified in
the tests rather than assumed, since "the standard library is safe" is a belief
that survives the library changing.

**Nothing is fetched during an import.** A WordPress export names attachment
URLs; following them turns a file somebody emailed you into a request from
inside your network to a host they chose. URLs are collected and reported, and
pulling them down is a separate step.

**HTML arrives as text.** The template engine escapes everything, so imported
markup would render as visible angle brackets — the choice is to strip it or to
route it through `raw`, and `raw` on content from a database someone else
administered is not a choice. Tags are stripped, links and images extracted, and
the contents of `<script>`, `<style>` and `<iframe>` are discarded rather than
flattened. That last one was a bug: the first version removed the tags and kept
the code between them, so `alert(1)` appeared as page text.

## Uploads and URL imports

```
$ scrivet media add bomb.png --alt "A photo"
bomb.png does not look like a valid png: it is 30000x30000, which is 900
megapixels — a small file that decodes to gigabytes is a decompression bomb,
not a photograph

$ scrivet media get https://169.254.169.254/latest/meta-data/
refusing to fetch: 169.254.169.254 is link-local, which is where cloud
metadata lives
```

OWASP names four controls for uploads. Three fall out of the architecture rather
than being added to it: content is addressed by the SHA-256 of its bytes, so the
stored name is server-generated by definition and no caller-supplied string ever
becomes a path — which retires traversal, null bytes, `.php.jpg`, and reserved
names in one go. Storage is the same object store the content uses: opaque
blobs, no extensions, nothing a web server would dispatch on. The fourth, a
separate origin, is documented honestly as a mitigation rather than claimed as
solved.

**Magic bytes are not validation.** A polyglot satisfies a signature check and
is also something else — the GIFAR was a valid GIF and a valid JAR at once. So
every accepted format is decoded: an image has to parse and report plausible
dimensions, an MP4's `ftyp` box is checked at offset 4 where it actually lives,
a RIFF container is distinguished by the four bytes at offset 8 so a WAV can't
be served as a WebP.

**Refused, with the reason:** SVG (XML that browsers execute, plus
ImageTragick), HTML, JavaScript, archives, Office documents, executables. Every
refusal explains itself — "unsupported file type" sends people looking for a
converter that produces the same risk under a different extension.

### The SSRF bug this is built not to have

`--from-url` is server-side request forgery with a friendly label. The usual
defence — resolve the hostname, check the address, then request it — is what
[Craft CMS shipped and had bypassed](https://github.com/craftcms/cms/security/advisories/GHSA-gp2f-7wcm-5fhx),
because the check and the request are two separate DNS lookups and DNS rebinding
makes them differ.

The fix isn't a better list. It's `net.Dialer.Control`, which runs after
resolution and before the socket connects, with the exact address being dialled.
There's no second lookup to poison because there's no second lookup, and every
connection goes through it including redirects.

One bug this found in itself: a `::ffff:0:0/96` entry meant to block IPv4-mapped
addresses. `net.ParseCIDR` normalises that to a 4-byte network, truncating the
mask to `0.0.0.0/0` — it was blocking the entire IPv4 internet while looking
correct. A test asserting that public addresses stay *reachable* is what caught
it. Every defence needs one of those.

## Migration continuity: sitemap and redirects

A migration loses rankings in two ways — old URLs stop resolving, and crawlers
stop trusting what the sitemap says. Both are handled at import time, because
the export already contains everything needed and typing it by hand afterwards
is where it doesn't get done.

```
$ scrivet import old-blog.xml
  1 page(s) kept the same path, so they need no redirect.
  1 redirects were generated from the old URLs, so links published before the
  migration keep working. Google asks for at least a year, and there is
  rarely a reason to remove them.

  wrote redirects.json with 1 redirect(s)

$ curl -sI /2019/03/04/hello-world/
308 → /hello-world
```

### lastmod that is actually true

Google and Bing both say lastmod is the field that matters and both ignore
`priority` and `changefreq`, so those aren't emitted. Google also says something
less often quoted: it may stop trusting lastmod entirely on sites where the
value moves without the content moving.

That caveat exists because almost every CMS lies. `lastmod` comes from the row's
`updated_at`, which moves when an editor opens a page and saves it unchanged,
when a bulk operation touches every row, when a plugin rewrites metadata. The
date is real; the claim it makes is not.

Here it can't be wrong. Content is addressed by hash, so "when did this page
last change" has an exact answer: the commit where its object id stopped
matching the previous one. Re-saving identical bytes produces the same id, so
the date doesn't move. Republishing the whole site doesn't move it either.
There's a test for precisely that.

This is the one place where a decision made for a completely different reason —
content addressing, chosen for rollback and integrity — turns out to satisfy an
external requirement that nobody using a row-based store can meet.

### Redirects that can't chain

Google's crawler follows a limited number of hops, so a URL three or four deep
in a chain may never be crawled to its destination and the PageRank at the
origin never arrives. Rather than documenting that chains are bad, chains are
flattened at write time: `a → b → c` is stored as `a → c` and `b → c`, so a
chain is impossible to create rather than something to remember to avoid. Loops
are refused, and so is a source with two different destinations — resolving that
by ordering would make behaviour depend on which line someone added first.

308 rather than 301. They're equivalent to search engines, and 308 preserves the
request method where 301 lets a browser silently turn a POST into a GET.

## Leaving

Every CMS has an export button. Most produce something only that CMS can read,
and nobody finds out until the day they try to leave — which is the day the
vendor's incentive to have fixed it was lowest.

So export here is checked the only way that means anything: a round trip. Export
a site, re-import what came out, compare. A single changed field fails the test.

```
$ scrivet export markdown --to out
2 page(s) as markdown into out
  content/about.md
  content/hello-world.md
  README.md
  redirects.json
```

Three formats, chosen by where people actually go:

| Format | Why |
|---|---|
| **Markdown + front matter** | Hugo, Astro, Eleventy and Jekyll read it directly; every other CMS has an importer |
| **WXR** | WordPress's own format, so "move to WordPress" is a file copy |
| **JSON** | Lossless, and what this tool's own importer reads |

The output is a directory of ordinary files — no archive, no manifest. `ls` and
`cat` are enough to recover a single page by hand. Redirects and per-page change
dates travel with it, because an export without them hands somebody a site that
loses its rankings on arrival.

There is something faintly absurd about writing an exporter for a competitor.
That is the point: a tool that makes leaving hard is a tool that has stopped
needing to be good.

### Round-tripping is harder than it looks

The round-trip test found three real bugs on its first run, two of them in code
I'd already shipped:

- Front-matter values were quoted on the way out and the quotes stripped without
  unescaping on the way back in, so `"a \"quoted\" title"` came back with
  literal backslashes.
- A legitimately quoted `"&notreal"` was refused as a YAML anchor, because the
  anchor check ran *after* the quotes were stripped. A quoted scalar cannot be
  an anchor — and quoting everything is exactly what stops YAML reading `no` as
  false and `12:30` as a sexagesimal integer.

## Exporting the audit log

```
$ scrivet siem ocsf --envelope env.json -o audit.ocsf
4 event(s) as ocsf, sequences 1-4
  identifiers are as the log stored them
  envelope in env.json — verify with `scrivet siem verify`

$ scrivet siem verify audit.ocsf --envelope env.json
verified  4 event(s), sequences 1-4
  nothing was added, removed, reordered or altered since export
```

**OCSF**, **CEF** and **JSON Lines**. OCSF is where the industry is converging;
CEF is the widest-supported thing that exists. LEEF is deliberately absent —
QRadar-specific, and QRadar reads CEF.

### Tamper evidence usually dies at the export boundary

A SIEM re-serialises what it ingests: fields renamed, types coerced, order
changed. Whatever integrity the source had is gone, and from then on the log is
trusted because it is *in the SIEM* rather than because anything checks out.

Every export carries an envelope: every event's hash in order, the sequence
range, and the anchor the first event links back to. A verifier on a machine
that never held the original can confirm nothing was added, removed, reordered
or altered. `siem verify` is that check, and it states what it does **not**
prove — a partial export is a partial export, and it says which event the range
links back to.

A broken chain is refused rather than exported. Shipping one to a SIEM launders
it.

### Privacy survives the export

Pseudonymisation is worth nothing if the export undoes it, and an export is
exactly where it gets undone — the receiving system asks for usernames and
somebody adds a flag. So exports carry whatever the log carries, `--reveal` is
not the default, and asking for it is itself written to the log.

Building this found the hole that makes the rest pointless: the principal was
pseudonymised while `Source` carried `scrivet-cli@hostname` in clear. On a
single-user machine a hostname is a person's name, so the two fields together
re-identified them in the same record. The source is now pseudonymised too —
AU-3(d) wants to know *where* an event came from, and a stable pseudonym answers
that.

## More than one person

Concurrent editing, four-eyes approval and keeping a human in the loop on AI
changes look like three features. They are one mechanism: every write says what
it was based on, and every release says who agreed to exactly what.

### Approval is a signature over content, not a flag on a ticket

Everywhere else, approval is a state — a row moves to "approved", somebody with
edit rights changes the content afterwards, and the approval survives because it
was attached to the *request* rather than to what was in it. Most review systems
have this hole and most people never notice.

Here an approval names a content hash:

```go
prop.Approve("sam", "looks right", now)   // approves hash aaa
prop.Approve("kit", "agreed", now)        // approves hash aaa  → 2 of 2, allowed

prop.Rebase("bbb", "dana", now)           // dana edits one character
// → 0 of 2. Nothing detected the edit; the approvals are simply about
//   different bytes now.
```

The superseded approvals are kept, not deleted — "who signed off the version
before this one" is a real question and silently dropping the record answers it
with nothing.

### Human in the loop falls out of the same rule

A model's change cannot be approved by the model, for the same reason Dana
cannot approve Dana's: approvers must be principals and authors cannot
self-approve. On top of that, an AI-authored change needs at least one approval
from a *human* — two machines agreeing with each other is not review. Setting
the numeric threshold to zero does not disable that, and there's a test for it,
because "Required: 0" would otherwise be a way to let a model publish
unreviewed.

### Wired to every write, and a test that says so

`SaveDraftFrom` is called by `add`, `assist`, `import`, the MCP write operation
and the admin save handler. That isn't a convention — a second source-walking
test finds every function calling either form and fails if one still uses the
unchecked `SaveDraft`. An empty base is allowed, because a single writer has
nothing to collide with; the point is that the call site had to decide.

```
$ scrivet review require 2
publishing now needs 2 approval(s)
  and a human on anything a model wrote
  an author can never approve their own change

$ scrivet review approve            # as dana, who wrote it
dana wrote this change and cannot approve it
```

### Locks are the smaller half, and they say so

The received design is a checkout lock. It scales badly and leaves stale locks
because people close laptops, so every CMS that does it grows a break-lock
button, the button gets used constantly, and the lock guarantees nothing.

The guarantee here is compare-and-swap, which content addressing makes exact
rather than a heuristic about timestamps:

```
$ scrivet add index=index.json --based-on 4f2a1c
the draft moved while you were working; dana changed it
  you were working from 4f2a1c9b8e01, the draft is now 7d3e5a2f01bb
  changed since: index
```

Locks still exist — they stop two people spending an afternoon on the same page
— but they are **advisory**, they expire in 30 minutes on their own, and taking
one somebody else holds is permitted and tells you whose it is. Refusing would
make it a real lock, a real lock needs a break-glass button, and the button is
the problem.

A conflict also knows whether it *actually* collides. Two people editing
different pages get told the retry is safe, because reporting every concurrent
edit as equally dangerous is what teaches people to retry blindly — and then
the real ones get retried blindly too.

## Encryption at rest

```
$ scrivet vault enable
IOZrHckhr36l73q7wpvxK2p9NqYcXW8fVJ0mQ1sLbTg=

  this is the only time it is shown. It is not stored here — a key kept
  beside the data it protects protects nothing against somebody who takes
  the directory.
```

**What this defends against:** somebody who obtains the files. A stolen laptop,
a backup on an open bucket, a disposed disk, a container image with the data
directory baked in.

**What it does not:** somebody who can run the program. The program has to read
content to render templates, validate types, check accessibility and build
sitemaps. End-to-end encryption is the wrong control here — it would mean the
server cannot read content whose entire purpose is to be read out loud, and
every feature this tool has would stop working. Saying that plainly beats
shipping something that sounds stronger and protects less.

### Nonce reuse cannot happen, rather than being avoided

AES-GCM has one catastrophic failure mode: reusing a nonce with the same key
destroys authentication and leaks the XOR of two plaintexts. Every serious
implementation is organised around not doing it, usually with a counter somebody
has to remember not to reset.

There is nothing to remember here. Each object gets its own data key used for
exactly one encryption, because the store is content-addressed and write-once —
identical bytes are the same object and are never written twice, different bytes
are a different object. A key that encrypts one thing once cannot repeat a
nonce. It is not a rule being followed; it is a shape with no room for the
mistake.

### The object id is still the hash of the plaintext

The name is load-bearing everywhere: deduplication key, ETag, what a content
type binds to, what an approval signs. So the id stays the hash of the content
and the *file* holds the sealed form. The pleasant consequence is two
independent integrity checks — GCM's tag says the ciphertext was not altered,
re-hashing says it is the object it claims to be.

The ciphertext is also bound to its address, so swapping two sealed files on
disk fails to open rather than silently swapping two pages.

### Rotation rewraps, it does not re-encrypt

```
$ scrivet vault rotate --id k2
  new objects are sealed with k2. k1 is retained and still needed to read
  everything written before now
  nothing was re-encrypted. Rotation rewraps data keys, which is why it is
  cheap enough to actually do.
```

The key comes from `SCRIVET_KEY`, `SCRIVET_KEY_FILE`, or `SCRIVET_KEY_COMMAND` —
and the command form is the interesting one, because it makes a KMS, an HSM, a
password manager or a hardware token work without this program knowing any of
them exist.

Enabling encryption does not rewrite what is already there, so a store can be
half converted and both forms stay readable. Turning it on cannot lose content.

## Signing in with an identity provider

```
$ scrivet oidc check --issuer https://accounts.google.com
discovery
  issuer       https://accounts.google.com
  token        https://oauth2.googleapis.com/token

algorithms
  provider     RS256
  agreed       RS256
  a token naming anything outside this list is refused before its
  signature is examined

keys
  4 usable signing key(s)
```

OIDC, not SAML, and the reason is specific rather than a preference. Go's
`encoding/xml` does not preserve semantics across a parse and re-serialise,
which lets a crafted document show one thing to signature verification and
another to data extraction — XML Signature Wrapping. Both major Go SAML
libraries shipped variants of it. The irony is exact: the loose tokenizer that
makes `encoding/xml` immune to XXE, which this project relies on for the
WordPress importer, is what makes the wrapping possible.

An ID token is three base64url segments and the signature covers the first two
*as received*. There is no canonicalisation step, so there is no gap between
what was verified and what is read. SAML is still reachable — through a provider
that speaks both, which moves the XML parsing to software whose full-time job it
is.

### The algorithm list never comes from the token

The classic JWT failure is trusting the `alg` in the token's own header:

| Header says | What a naive verifier does |
|---|---|
| `alg: none` | agrees the token is unsigned |
| `alg: HS256` | hands the RSA **public** key to HMAC — and the public key is public |

So the algorithm is never read as an instruction. The provider's discovery
document says what it signs with, that list is intersected with what is
implemented here, and anything else is refused before the signature is examined.
The test for this constructs a genuinely valid HMAC over the public modulus —
the only thing stopping it is that HS256 is not on the agreed list.

Also refused: `crit` headers this does not understand (a `crit` that gets ignored
is the extension mechanism working backwards), encrypted tokens, EC points that
are not on the curve, RSA keys under 2048 bits, and an absent `kid` when the
provider publishes more than one key — trying each until one verifies accepts a
token signed by *any* of them.

PKCE with S256 always. `state`, `nonce` and the code verifier are three distinct
random values, because reusing one for two purposes means breaking one breaks
both, and a sign-in attempt expires in ten minutes.

Discovery and JWKS go through the SSRF-hardened fetcher, which matters here more
than almost anywhere: an issuer URL is configuration, and "fetch this URL from
inside the network" is the whole of server-side request forgery. Every endpoint
in the metadata is revalidated, and the token exchange does not follow redirects
at all — a redirected form submission replays the client secret to wherever the
redirect points.

`scrivet oidc check` runs the whole path deliberately, because the alternative is
finding out from somebody who cannot log in.

### The provider authenticates; this program authorises

A verified ID token is exchanged for an ordinary scrivet session token. Every
existing mechanism — the role ladder, path bindings, revocation, the audit trail
— applies unchanged, and none of it had to learn about OIDC. Revocation stays
local: cutting somebody off does not depend on the provider noticing, or on a
token expiring, or on a back-channel logout arriving.

**There is no auto-provisioning, and that is the decision that matters most
here.** A verified token proves the provider knows this person. It does not say
they may edit anything. Creating a principal on first sign-in would mean
everybody with an account at the identity provider — which for a public provider
is everybody — becomes a user of this system.

```
dana@example.com signed in successfully, but is not in the access policy
for this site.
An administrator can add them:  scrivet auth grant dana@example.com author
```

Discovery happens at startup, so a misconfigured provider is a failure to start
rather than a person who cannot log in and no information about why. Starting
with a provider configured and no client secret is refused outright, rather than
offering a sign-in button that cannot work.

## Anchoring a publication to Bitcoin

```
$ scrivet anchor submit
submitting 869d2ad9de3a
  accepted  https://alice.btc.calendar.opentimestamps.org
  accepted  https://bob.btc.calendar.opentimestamps.org
  accepted  https://finney.calendar.eternitywall.com

  these are pending, which is not anchored. A calendar batches many
  hashes into one Bitcoin commitment, which takes hours.
```

A timestamp from an authority proves when something existed, and the proof rests
on that authority's certificate — when it expires the token needs re-stamping,
and if the authority folds every token it issued lands in a legal grey area. An
anchor has the opposite shape: no authority to expire, so the proof does not
decay.

Until recently it also had no standing anywhere, which is why this project
shipped RFC 3161 first and left anchoring as a documented seam. That changed.
**eIDAS 2 (Regulation (EU) 2024/1183)** introduces qualified electronic ledgers
carrying a presumption of uniqueness, authenticity, accurate date and time and
sequential ordering, with implementing acts through 2026. Italy's Law 12/2019,
Vermont and Arizona already give blockchain records legal effect. The layered
answer — a signed token for the lawyer, an anchor for the decade — is now better
on both sides.

### One hash, and why nothing else can go on a ledger

What is anchored is the live commit id: a single SHA-256 over the entire
publication. Not a page, not a field, not anything about a person.

That is not a preference. The **EDPB's guidelines on blockchain and personal
data** (02/2025 v2.0, adopted July 2026) recommend against registering clear
text, encrypted **or hashed** personal data on a ledger, because it is immutable
and Article 17 erasure has to remain possible. The pattern they endorse instead
is exactly this one: keep the data off-chain, put only a commitment on it, so
deleting the data renders the on-chain record unlinkable.

A root over a whole site satisfies that. Delete the content and the anchor still
proves a site existed on a date, and proves nothing about who was in it.
Publishing content itself to a permanent store — Arweave's pay-once model most
obviously — is the case the guidelines rule out, and this does not offer it.

### Pending is not anchored, and the code refuses to blur them

A calendar returns a proof immediately, and that proof commits to nothing yet.
State is derived from the attestations inside the proof, never from how long ago
it was submitted — a proof submitted a year ago that nobody upgraded is still
pending, and calling it anchored because time has passed would be a claim about
Bitcoin made by looking at a clock.

The operation chain is walked and the commitment recomputed, so a proof that
does not derive from the digest it claims is rejected. Whether a Bitcoin
attestation names a real block containing that root needs block headers, which
this does not have — that is delegated to the `ots` client, the same call made
for RFC 3161 verification. A verifier that is subtly wrong is worse than none,
because its output is believed.

Operations outside append, prepend and SHA-256 stop the walk rather than being
skipped. Skipping one carries a value forward that is not what the proof
describes, and every attestation after it would then be checked against the
wrong number while appearing to succeed.

## More than one language

Serving `/fr/about` instead of `/about` is bookkeeping. The bug every
multilingual CMS has is worse: somebody edits the English page, the French
translation is now wrong, and nothing says so. The site keeps serving a fluent
translation of a paragraph that no longer exists, often for months.

Other systems handle this with a flag set by hand, or by comparing modification
timestamps — which move when a page is saved unchanged, so they cannot tell
"edited" from "opened and saved". Both degrade into a warning nobody believes.

```
$ scrivet lang check
  stale     about                fr
            translated from 4e2d62d7f0fc, the source is now 1f2e26786654
            dana made the translation
```

A translation records the hash of the source it was made from. Change one
character and the hash stops matching, so "out of date" is a fact about two
values rather than a guess about two clocks. **Re-saving the source unchanged
does not mark anything stale** — the case a timestamp comparison cannot handle,
and the one that turns the warning into noise.

This is the third time content addressing has given an exact answer where
everyone else has a heuristic: a content type records the hash of what it
validated, an approval records the hash of what was agreed, a translation
records the hash of what it was translated from.

### Deliberately absent

No machine translation, no `Accept-Language` sniffing, and **no automatic
fallback to the default language**. That last refusal is the interesting one:
serving the English page to somebody who asked for French, without saying so, is
how a reader comes to believe a page exists in their language when it does not.

`hreflang` is emitted only for translations that actually exist, computed from
what is published rather than what is configured — declaring a language a page
is not available in means a search engine offers it to a reader who then finds
it missing. A single-language site's sitemap is byte-identical to what it was
before this feature existed.

The default language keeps its unprefixed paths. Prefixing everything would
break every existing link on the day a site adds a second language, which is the
moment people decide multilingual support is not worth it.

## Scheduled publishing



Publishing is a pointer move, so scheduling it is a note saying which commit and
when. No staging area, no copy to keep in sync, no half-published state.

**The gates run at publication, not at scheduling.** The usual failure is that
checks run when somebody clicks the button: a page approved on Monday, edited on
Tuesday and published by a timer on Wednesday goes out unapproved, and the audit
trail says it was approved. Here scheduled publishing goes through the ordinary
publish command, so accessibility, provenance, content types and dual
authorization all run against the content as it stands then — and approvals are
bound to a content hash, so an edit invalidates them by construction.

**An entry names a commit, not "the draft".** If the draft moves, the entry is
stale and is skipped rather than fired:



"Publish whatever is current at nine on Friday" is a different and much worse
instruction than the one somebody thought they were giving.

Fired entries stay in the record with who scheduled them and why, because "what
went out on Friday and who decided that" is the first question an audit asks.
 is meant for cron or a systemd timer — it does not daemonise,
since a scheduler that is also a long-lived process is a second thing that can
be down.

## Scheduled publishing

```
$ scrivet schedule add 48h --note "embargo lifts"
8cfacf43ca06 will publish at 09:00 on 17 Aug 2026
  this names that exact commit. Editing the draft afterwards does not
  change what is scheduled — it makes the entry stale, and a stale entry
  is reported rather than fired
  every gate runs at publication, not now
```

Publishing is a pointer move, so scheduling it is a note saying which commit and
when. No staging area, no copy to keep in sync, no half-published state.

**The gates run at publication, not at scheduling.** The usual failure is that
checks run when somebody clicks the button: a page approved on Monday, edited on
Tuesday and published by a timer on Wednesday goes out unapproved, and the audit
trail says it was approved. Here scheduled publishing goes through the ordinary
publish command, so accessibility, provenance, content types and dual
authorization all run against the content as it stands then — and approvals are
bound to a content hash, so an edit invalidates them by construction.

**An entry names a commit, not "the draft".** If the draft moves, the entry is
stale and is skipped rather than fired:

```
skipped 5cf6f2ab63c5 — the draft has moved since this was scheduled
```

"Publish whatever is current at nine on Friday" is a different and much worse
instruction than the one somebody thought they were giving.

Fired entries stay in the record with who scheduled them and why, because "what
went out on Friday and who decided that" is the first question an audit asks.
`schedule run` is meant for cron or a systemd timer — it does not daemonise,
since a scheduler that is also a long-lived process is a second thing that can
be down.

## Log transparency: what "immutable" can honestly mean

You cannot make logs unmodifiable by an administrator on a machine they control.
Anyone selling that is selling something. What you can do is make modification
**provable to somebody who does not trust that machine**, and the difference is
the whole design.

A hash chain says whether the log was altered — but verifying it means walking
the whole log, and being convinced nothing was removed between Tuesday and
Friday means having held Tuesday's copy. Neither is how an auditor works.

An RFC 6962 Merkle tree over the same entries gives both, logarithmically:

```
$ scrivet auditlog prove 3
entry 3 is in a log of 6
  proof 3 hashes

  that is the whole proof. Somebody holding this entry, these 3 hashes
  and a root they trust can confirm it is in the log without ever seeing
  the log — which also means without seeing every other entry in it
```

| Proof | What it establishes |
|---|---|
| **Inclusion** | this exact entry is in the log with head H, in ~20 hashes for a million entries |
| **Consistency** | the log with head H2 is an append-only extension of H1 — nothing before H1 changed, moved or vanished |

### The log writer runs as somebody else

```
$ scrivet logd status
no log writer
  this process writes the audit log itself, so anything that can execute
  code as this account can rewrite the record of what it did
```

Without separation, the process that publishes content is the process that
writes the record of it — so a template bug, a dependency, or a mistake in this
program is enough to rewrite history. `scrivet logd` runs as its own account,
owns the log file, and accepts submissions over a unix socket. The CMS never
holds a descriptor that could seek, truncate or reorder.

**The writer computes the chain.** A client sends what happened; it does not
send a sequence number, a previous hash, or an entry hash. That is not
validation — the submission type has nowhere to put them. A forged submission
claiming `seq: 9999` and a chosen hash lands as the next sequence with a
writer-computed hash, and the demo does exactly that.

**There is no fallback.** If the writer is configured and unreachable, the
record is not written and the tool says so in red:

```
audit record NOT written: connect: connection refused
  the log writer is configured and unreachable. This action is not in
  the record.
```

Falling back to writing the file directly would mean anybody who can stop the
writer regains the ability to edit the log — and where separation is properly
configured the fallback would fail anyway, because the CMS account cannot open
the file.

The peer's uid comes from `SO_PEERCRED`, asked of the kernel rather than of the
client: a uid a client tells you is a claim, one the kernel returns is a fact.
`logd` refuses to run as root — it needs to append to one file and bind one
socket, and root buys it nothing.

This does not stop root, and nothing running on the machine can. It moves the
requirement from *code execution as the web application* to *root*, which is a
large gap in practice. What makes root's rewrite undeniable is the layer below.

### Publishing the head is the mechanism

A head kept beside the log protects nothing: whoever can rewrite one can rewrite
the other. A head that has *left the building* fixes history before it.

```
$ scrivet auditlog anchor
submitted the log head at 9 entries
  accepted  https://alice.btc.calendar.opentimestamps.org

  once this is in a block, entries before it cannot be rewritten without
  producing a log that fails consistency against a value nobody involved
  can alter — including whoever runs this machine
```

Demonstrated: rewriting entry 3 and recomputing every hash after it produces a
file whose chain can be made to look intact, and which still fails consistency
against a head published beforehand.

```
this log is NOT an append-only extension of the head published at 6 entries.
  the old root does not follow from the proof; the log may have rewritten history
```

The posture scanner reports a log with no published head as a **high** finding,
and a head far behind the log as medium — the gap since the last one is exactly
the window in which entries can still be quietly rewritten. If nobody supplied
the answer, that is reported as *not checked* rather than as a finding, because
a scanner that reports on data it never gathered is a scanner people learn to
ignore.

## Watching the agents

```
$ scrivet agents
  flagged  pushy-agent        claude
           6 repeated-refusal, 1 escalation across 7 actions
           · seq 10  publish /legal — reached for something above the role it holds
           · seq 11  publish /legal — the same request has now been refused 2 times
  ok       polite-agent       claude
           9 actions, nothing refused
```

Both agents above were refused eight times. One is flagged and one is not, and
the difference is the whole point.

**Being refused is not misbehaving.** An agent that attempts something, is told
it needs approval, and stops has behaved correctly — it asked. Counting that
against it quarantines the well-behaved agents fastest, because they are the
ones that try things and accept the answer. What counts is *not accepting the
answer*: retrying a refusal, reaching above the role it holds, producing content
a gate rejects.

The only input is the audit log. That means an agent cannot avoid detection by
taking a path nobody instrumented, because the log is what the system already
believes happened — and every strike names an audit entry, so each one is
checkable rather than being the detector's opinion.

**Nothing is revoked automatically.** Automatic revocation on a heuristic means
a busy afternoon of legitimate work looks like an incident, the agent doing that
work is cut off, and then somebody turns the detector off — after which it
detects nothing at all.

## Webhooks

A webhook is an SSRF primitive with a friendly name: the endpoint is a URL
somebody configured and this program requests it from inside the network. So it
goes through the same connect-time address check as importing — one defence, not
two that can disagree.

**The signature covers a timestamp as well as the body**, because a request
captured today verifies next year otherwise: the signature is over bytes that
have not changed. And it covers them *length-prefixed*, not concatenated —
with `HMAC(secret, timestamp + body)` an attacker can move the boundary, so
`("1", "23x")` and `("12", "3x")` produce the same digest and a signature valid
for one is valid for the other.

The scheme is specified rather than implied. A golden test asserts the signature
against a value computed by an independent implementation:

```python
def field(b): return struct.pack('>Q', len(b)) + b
m = hmac.new(secret, digestmod=hashlib.sha256)
m.update(field(timestamp_ascii)); m.update(field(body))
```

If that test fails after a change, every receiver written against the documented
scheme has silently stopped verifying.

Delivery is at-least-once and says so: the id is stable across retries, so a
receiver can deduplicate. A 4xx is not retried — the receiver is saying the
request is wrong and repeating it will not make it right. Payloads name what
changed rather than carrying it, so a misconfigured endpoint cannot be sent
unpublished content. A delivery failure never blocks publishing, because making
it one hands anybody who can take an endpoint offline the ability to stop the
site being updated.

## Compliance evidence

```
$ scrivet compliance summary
github.com/rsh1k/scrivet  3f3ecf09a3db…

  third-party components             0
  NIST controls with a check         32
  quantum-broken, generated here     none
  quantum-broken, verified only      2
```

The EU **Cyber Resilience Act** brings vulnerability reporting obligations from
**11 September 2026** — 24 hours for an early warning, 72 for a full
notification — with penalties up to €15M or 2.5% of turnover. It requires a
machine-readable SBOM covering at least top-level dependencies, kept current,
retained ten years.

The reason that is cheap here is the first line of the summary. **Zero
third-party dependencies** means no transitive tree to track, nothing that can
reach end of life unnoticed, and no advisory feed to reconcile against — which
the research identifies as the main CRA problem for everyone else. A test fails
the build if a dependency is ever added, so that stops being true deliberately
rather than by discovery during an incident.

Everything here is **derived, not written**. The SBOM comes from the build
information in the running binary rather than from `go.mod`, because during an
incident the question is what is deployed. The control mapping is generated from
the posture rules, so a control listed is one something actually checks. And the
cryptographic inventory is checked against the source by a test — a compliance
document maintained by hand is one that was true when somebody wrote it.

### Post-quantum: the inventory is the answer

NIST's guidance is that a migration begins with a cryptographic inventory, so
that is what this produces:

```
This program generates no material with an algorithm a quantum computer
defeats.

It verifies RSA and ECDSA, which quantum computers defeat. Those signatures
are made by an identity provider, so the algorithm is their choice and the
migration is theirs to lead.

There is no harvest-now, decrypt-later exposure here, because nothing
long-lived is protected by an algorithm Shor's algorithm breaks.
```

That position is not a plan, it is a consequence: content addressing, the audit
chain, the Merkle log, pseudonymisation, encryption at rest and webhook
signatures all rest on hashes and symmetric ciphers, whose post-quantum
weakening is a halving the key and digest sizes already account for. The
inherited exposure is named rather than omitted, and it will follow whatever a
provider advertises when they publish a post-quantum algorithm.

### Licensing for AI crawlers

`/license.xml` declares terms under **Really Simple Licensing** (1.0, December
2025), advertised from `robots.txt`. robots.txt says *whether* to crawl; this
says *on what terms* — attribution, a named licence, a contact.

Not emitted unless configured. A licence file asserting terms nobody chose is
worse than none, because a crawler will honour it and the operator never agreed
to it. Enforcement depends on crawlers choosing to honour it, exactly as
robots.txt always has — what changes is that "we never said they could" becomes
a document with a date.

**None of this is a certification.** An SBOM is not a SOC 2 report and a control
mapping is not an assessment. It is the evidence somebody needs before any of
that is worth starting, produced accurately rather than approximately.

## Search, without a search engine

```
$ curl "/search.json?q=pricing"
  pricing   Pricing                     score 22.7  body,slug,title
  faq       Frequently asked questions  score  1.7  body
```

An inverted index with positional postings, built at publish time from content
this program already holds. **No dependency**, because the zero-dependency
position is load-bearing — it is what makes the CRA obligations cheap and the
bill of materials one line, and trading that for a search cluster in an 8 MB
static binary would be a bad exchange for most sites this size.

The ranking is deliberately coarse and each part earns its place:

| | Why |
|---|---|
| Field weighting | somebody searching "pricing" wants the pricing page, not the FAQ sentence mentioning it |
| Inverse document frequency | a word on every page says nothing about which page is wanted |
| Diminishing returns on repetition | otherwise a page repeating a term wins every time — tested against 200 repetitions |
| All terms must match | "any term" on a two-word query returns most of the site |

**What it does not do, said plainly:** stemming, synonyms, fuzzy matching,
relevance tuning, or millions of pages. No stemmer specifically because a site
here can be in more than one language, and an English stemmer applied to German
produces confident nonsense. Beyond a few thousand pages the honest answer is a
search engine, and the index exports cleanly enough to feed one.

The index records the commit it was built from and is built from **live**, never
the draft. A search box returning unpublished pages is a content leak however it
is labelled.

`/search.json` is JSON rather than a rendered page, because the template
language deliberately cannot loop over something computed at request time —
adding that to serve a results page would reintroduce exactly the execution this
project removed.

## Releases carry their own evidence

```
$ make release VERSION=v0.1.0
release v0.1.0
  5774d924…  scrivet
  8363ca6b…  scrivet.cdx.json
  b83ad1f9…  scrivet.crypto.json
```

The bill of materials is produced **by the binary being released**, not from the
source tree. `debug.ReadBuildInfo` reads what actually went into the artefact;
asking the source describes what *would* be built now, and during an incident
the question is what is deployed. The binary's own SHA-256 goes into the
document, so the SBOM is tied to a file rather than to a version string —
verified in the demo above.

The release workflow refuses to ship two things:

- **A modified build.** An SBOM for a binary built from uncommitted changes
  names a revision nobody can fetch.
- **Undeclared dependencies.** The zero-dependency property is what the CRA
  position rests on, so it stops being true deliberately rather than by
  discovery during an incident.

Artefacts are attested to the workflow run that produced them.

## Status

Working: the content store, draft/publish/rollback, diff, history, the template
engine, `verify`, content types, RBAC with API tokens, the tamper-evident audit
log, provenance marking, the accessibility gate, the admin UI, the public server
with PWA output, RFC 3161 timestamping, the MCP server, the assistant, the
continuous posture scanner with its dashboard, the Material 3 Expressive
interface, four ready-made templates, import from WordPress/Markdown/JSON,
validated uploads with an SSRF-hardened URL fetcher, sitemap/redirect
generation, export to Markdown/WXR/JSON, audit-log export to OCSF/CEF/JSONL
with an integrity envelope, concurrent editing with dual authorization enforced
on every write surface, envelope encryption at rest, OIDC sign-in wired through
the admin, Bitcoin anchoring via OpenTimestamps, and multilingual sites with
exact translation staleness, scheduled publishing, and an RFC 6962
transparency log with inclusion and consistency proofs written by a
privilege-separated writer, rogue-agent detection, signed webhooks, generated compliance evidence,
and search.

583 tests. The ones worth reading are the negative ones: every SSTI payload I
could find, XSS in all three escaping contexts, termination limits, tamper
detection, path traversal through ids that become filenames, over-denial in the
role ladder, and the source-walking test that checks each gate is wired to every
interface rather than just the one I was looking at.

A green suite proves nothing on its own, so the gates are mutation-tested:
removing the check has to break something. Twice now that turned up a control
with no behavioural test behind it.

Runs in the container as a non-root user (65532) and works against a read-only
mount, so a rendering deployment never needs write access to the store.

Not built yet: workflow states and approval chains, the chatbot runtime, media
handling, scheduled publishing, multi-site, and OIDC — the API tokens are the
bootstrap for that last one, not the destination.

Publishing is the one action with an outside observer, which is the thing worth
gating; that's what [recoup](https://github.com/rsh1k/recoup) is for.

## Licence

Proprietary. All rights reserved — see [LICENSE](LICENSE). No licence is granted
by access to this repository.
