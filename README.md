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

## Status

Working: the content store, draft/publish/rollback, diff, history, the template
engine, `verify`, content types, RBAC with API tokens, the tamper-evident audit
log, provenance marking, the accessibility gate, the admin UI, the public server
with PWA output, RFC 3161 timestamping, the MCP server, the assistant, and the
continuous posture scanner with its dashboard.

253 tests. The ones worth reading are the negative ones: every SSTI payload I
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
