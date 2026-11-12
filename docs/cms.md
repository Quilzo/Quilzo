# The content platform

This page is the long reference for the part of Quilzo that stores, checks and
publishes content. It was the project's README while Quilzo was a content
management system and nothing else, and it is kept whole because the agents
described in the [README](../README.md) work on exactly this: an immutable
store, a publish that moves a pointer, and gates that refuse.

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

One maintainer, and the project is looking for more — [GOVERNANCE.md](../GOVERNANCE.md)
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

**A backup is the whole store, encrypted, and checked before it is called one.**

```
quilzo backup key                         # once: a key shown once, kept nowhere here
export QUILZO_BACKUP_KEY=...              # or QUILZO_BACKUP_KEY_FILE
quilzo backup create site.qzb             # the store and the layouts, read back whole to check
quilzo backup verify site.qzb             # any time, without restoring
quilzo backup restore site.qzb --into /srv/restored
quilzo config set backup.dir /mnt/backups # and the admin server makes one a day
```

What it holds and how:
- **Everything:** the history, settings, sealed credentials (still sealed),
  media, records and logs, and the layouts beside the store; not locks or
  temporary files.
- **Encrypted in parts:** AES-256-GCM, 64 KiB at a time, each part numbered and
  the last one marked, under a key derived for that backup from the backup key.
  A part changed, moved, dropped or cut off at the end is refused. The backup
  key is not the vault's: whoever holds the backups need not hold the keyring.
- **Checked whole:** a manifest lists every file's SHA-256, and a check decrypts
  every part and compares every file. A backup that checks is one that
  restores; one that does not is not kept.
- **Taken while running:** the history's objects are taken last, after the
  pointers to them, so every pointer in a backup points at an object in it.
- **Restored apart:** only into an empty directory, where the history is
  checked object by object; it becomes the store when somebody moves it into
  place.
- **Kept a week:** with `backup.dir` set, a backup a day, the newest
  `backup.keep` (seven) kept.

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
the admin's one script is its own, allowed by a nonce, and every screen works
without it, so a drag-and-drop editor would mean far more script on the most
attacker-interesting surface in the system. Each move writes a draft commit naming what it did, so an accidental
reorder is undone by rolling the draft back.

**Sections written once, shown on many pages.** A page marked a block — a call
to action, opening hours, a newsletter sign-up — is reused on others, and
changing it changes every page that reuses it, at the next publish:

```bash
quilzo section block hours                 # hours is a block now, no page of its own
quilzo section reuse index hours --at 2    # its sections, third on the home page
quilzo section blocks                      # every block, and the pages that reuse it
```

A block is content, so it is saved, reviewed, published and rolled back with the
rest of the draft, and it is never served on its own: no address, no sitemap
entry, no search result, no chatbot passage. A page that reuses one is, to every
layout, gate, search index and chatbot, a page with those sections in it, and
its ETag covers the block, so a cache is never told an old block is current.
One level only: a block inside a block shows nothing, so there is nothing to
loop. A block for members only is never put on a public page, a block a page
still reuses cannot be deleted or made a page again, and the Sections screen
says where each one is used.

**The negations are computed.** The language has no `else`, deliberately: an
`if` with one exit means a template's structure can be read off its source. The
shape that costs is a heading that is a link when there is somewhere to go and
text when there is not — so the renderer derives `unlinked`, `no_image` and
`no_slug` for every object in a page, once, where every renderer sees the same
thing. It is the same argument as the demo's prices: the language has no
arithmetic, so the formatted price is computed before the render.

What is still absent is absent on purpose. No partials, no includes, no
inheritance — each of those resolves a name at render time, and this language
resolves nothing at render time. A reused block is not one: it is put in place
in the content before any template sees it, from the same commit, one level
deep.

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

### Typefaces from the file you have

Most foundries send a TrueType or OpenType file, and WOFF2 — the format above —
compresses its tables with Brotli, which Go's standard library does not have and
this program will not take a dependency for. So it also serves WOFF 1.0, which
is the same tables compressed with zlib, and which every browser that reads
WOFF2 reads too. One command makes one:

```bash
quilzo theme font add Satoshi-Variable.ttf --name Satoshi-300-900
quilzo theme set font-body Satoshi
```

It writes `templates/fonts/Satoshi-300-900.woff` and checks it the way every
WOFF in that directory is checked: the header agrees with the file, every table
lies inside it and inflates to exactly the size it declares, the tables a
browser's font sanitiser refuses a face without are there, and the face's own
licence flag (OS/2 `fsType`) does not say "restricted licence embedding" — a
face that may not be embedded may not be served with a page either. A `.woff` is
checked as it is, in the same way. A `.woff2` is checked only for its signature,
the length it declares and its size, because its tables are Brotli and nothing
here can read them. Nothing is fetched or sent anywhere. The Design screen has
the same form, through the same code.

Without `--name` (on the screen, an empty "Served as"), the face is served under
the file's own name, with the weight and style the face's own tables declare
wherever that name does not say them. Foundries name static faces
`Satoshi-Regular.ttf` and `Satoshi-BoldItalic.ttf`; the first, taken at its
word, would claim every weight from 100 to 900, so a browser asked for bold
would draw the regular glyphs, and the second is not a name the contract reads.
So a static regular of weight 400 is served as `Satoshi-400.woff`, the bold
italic as `Satoshi-700-italic.woff`, and a variable face as the range of its
weight axis. A name that does say the weight, such as `Satoshi-Bold.ttf`, is
kept; a word that is neither a weight nor a style, such as `Condensed`, is
refused with a request for a name rather than guessed past; and a name given is
used exactly as given. The output says when the name came from the face. A
`.woff2` cannot be asked: its tables are Brotli, so it is served as its name
says, and one whose name says no weight is served as every weight, which is
right for a variable face; the output says so, so a static one can be given a
name that says its weight.

A face already served under the same name is replaced only when asked, with
`--force` or the screen's "Replace a face already served under that name",
because a browser keeps a face for a year under its name. A face is one file: a
`.woff` beside the `.woff2` of the same face is refused. A file in
`templates/fonts/` that is not served — a `.ttf` dropped there, a file that is
not what its name says — is named, with the reason, by `quilzo theme fonts` and
on the Design screen; for a `.ttf` or `.otf` that includes the command that
makes a WOFF of it. The licence still travels with the face: put its text
beside it. Adding or replacing a face takes the authority to publish, on the
screen and on the command line, as installing a layout does: a face is the
glyphs every page that names it is drawn with, and no gate reads a glyph, so
one whose digits are drawn as other digits would change every price on the site
with no word of any page changed.

The filename is still the contract, and a weight range is written either way:
`Satoshi-400-700.woff2` and `Satoshi-400..700.woff2` are both 400 to 700. The
first used to be read as 700 alone, though this documentation and the program's
own error message offered it as a range.

### What the tokens cannot say, and how a site says it anyway

A games studio's site wanted a moving picture behind its hero, a glow on its
headings, section titles running from the text colour into the accent, cut
corners and capital display type, on a site that is only ever dark. None of
that was a token, so the only route was a hand-written layout with a `<style>`
block in it: it worked, nobody could choose it from a screen, and its colours
were ones the contrast check never saw. Each piece is now something a site
opts into, held to the same promise as the tokens. A site that opts into none
of them is drawn as it was: its pages and its token block are the same byte
for byte, which a test holds, and its stylesheet gains only rules that name the
new classes a site opts into, and one fix — a centred hero's eyebrow is
centred now.

**A style layer.** `templates/style.css` is CSS of the site's own, served
after the generated stylesheet rather than instead of it. It is held to the
rule the shipped styles keep: every colour is a token, as `var(--primary)`, or
a mix of tokens with `color-mix()` — no hex, no `rgb()` or its relatives, no
named colours, and the system colours only inside
`@media (forced-colors: active)`. `url()` reaches only `/media/` and
`/fonts/`, there is no `@import`, no `!important` (the reduced-motion and
forced-colours rules underneath are `!important` so nothing outvotes them), no
redefining a token, no taking away the focus outline (a zero width in any
unit, `none` anywhere in it, `initial`, `unset` or `inherit`, an `all` reset,
or a custom property of the layer's that says any of these), and at most 64 KiB. Nor anything a browser would read differently
from the check: a string that runs over a line break, a comment or a quote
mark inside an address with no quotes round it, a `{ }` block in a custom
property, a declaration whose property is not a name, or a control
character. A rule that sets both a text colour and its background from tokens has that pair
checked at 4.5:1 in every scheme the site is served in. A layer with anything
refused in it is not served at all, and `theme check` names each rule; a
`site.css` still replaces everything, layer included. Changing a layer takes
publish authority, in the terminal and on the Design screen alike, because it
is on every page at once. A site package carries one as `site.layer`, and
takes it back with the package.

```bash
quilzo theme layer set arena.css      # checked first; refused rules are named
quilzo theme layer                    # what is there, and whether it is served
quilzo theme check                    # the palette, the backdrop veil and the layer
quilzo theme layer unset
```

With `--json`, `theme layer`, `set` and `unset` each answer with one document:
the layer's path, its size, whether it is served, how many rules are refused
and every finding. A refused `set` prints that document and exits non-zero.
`theme check --json` is the list of every finding, the layer's and the veil's
among them, and exits non-zero when a pair fails or the layer is refused.

What it cannot see is said rather than claimed: a colour pair split across two
rules, text faded afterwards by `opacity` or a filter, and a rule that hides
something the layout draws — the veil over a backdrop, or its stop switch.

**A backdrop.** A hero names a picture or a recording from the library as
`"backdrop_url": "/media/ID"`, and a section does the same with
`"surface": "media"` beside it. It is decoration, and drawn as decoration: an
`<img alt="">` or a `<video>` that is muted, loops, plays inline and is hidden
from assistive technology, with its poster underneath it, gone for a reader who
asked for reduced motion or forced colours, and with a "Stop the moving
background" switch beside it that needs no script (WCAG 2.2.2). Between the
picture and the words is a veil of one colour at one strength — `scrim`, which
is the page background unless set, and `scrim-strength`, 82% unless set — and
the words are checked against the worst picture it could cover: the veil over
black and over white. All the words that sit on it: the body text, the
secondary text a standfirst or a caption is in, and the accent of an eyebrow. A page with a backdrop does not publish while that fails,
and the refusal names the strength that would fix it. A recording with sound
cannot be a backdrop, because muting it throws away what was said in it.

```json
{"hero": {"title": "Games for after dark", "backdrop_url": "/media/ef4b…"},
 "sections": [{"features": {"surface": "media", "backdrop_url": "/media/4379…", "items": []}}]}
```

On the Sections screen, "Put a backdrop behind it" gives a section the field,
and the picker beside it offers the library's pictures and the recordings it
knows to be silent, and says how many recordings it left out. From the
terminal it is `quilzo section backdrop PAGE N /media/ID` (or `hero` for N, and
`--off` to take it away), because an edit writes only the fields a section
already has; it refuses, before writing anything, a file the library does not
hold and a recording not known to be silent. A page with a hero shows it there
above its sections, with "Put a backdrop behind the hero", which opens the same
picker; the hero's words have no screen of their own. A hero's backdrop is also
set with that command, in the page's JSON (`quilzo add`, or an agent's
`write_page`), or by a site package. Under `--json` every `section` edit answers
with the page, what was done, the draft commit and the sections as they stand.

**Silent recordings.** Whether a recording has sound is recorded when it is
added, from the same probe that reads its size. One with sound still needs a
captions track to publish; one with none needs a description instead (WCAG
1.2.1), which the layout takes from the library — the description written when
it was added becomes the video's label — or from a caption beside it. A
recording nothing could listen to, on a machine without ffprobe, is treated as
having sound. `quilzo media list`, its `--json`, and the `list_media` tool an
agent reads say which recordings have sound, which have none, and which are
not known.

**The neon style.** An eighth style: a glow on headings and filled buttons from
the accent, section titles that run from the text colour into it, chamfered
corners and capital display type. The glow is the `glow` token (0 turns it
off). The corners are a choice of their own, `corner`, round or chamfer, which
neon sets to chamfer and any style can use; a chamfer is drawn with
`corner-shape`, which keeps the focus ring whole, and a browser that does not
know it rounds the corner instead. The gradient titles are checked at five
points along them against the background, because a mix of two readable
colours can be an unreadable one, and they fall back to the plain text colour
where the browser cannot clip a background to text, the reader asked for more
contrast, or forced colours are on.

**One scheme.** `scheme` is both (the default), dark or light. A dark site is
served its dark palette whatever a reader's system asks, declares
`color-scheme: dark`, and is checked in dark alone — so it is no longer told
twenty-three times that each colour is the same in both schemes, and a colour
it never set is its dark default rather than a light one on a dark page.

```bash
quilzo theme set style neon
quilzo theme set scheme dark
quilzo theme set glow 12px corner round
```

**A picture on a feature card.** A `features` item takes `image` and `alt`, and
gets its narrower copies as every other picture does.

All of it is on the Design screen too — the neon style beside the others,
corners and schemes in the Look section, the veil and the glow in the token
table, and the layer, with what was refused in it. A layer the screen refuses
is given back as it was typed, with every refused rule named, and one taken
away is given back in the box, unsaved, until the screen is left; somebody who may
edit the design but not publish sees the layer read-only. `quilzo theme
styles --json` lists the styles, corners and schemes for a script. It is also
in a site package's `site` block (`style`, `scheme`, `corner`, `tokens`,
`layer`). The site builder,
from a sentence or over MCP, can choose the style and the scheme; it never
writes a layer, because a model writing CSS is the one part of a site nobody
reads before it is served.

### Changes without a restart

Both servers used to read the design and the settings once, when they started:
a face added to `templates/fonts/` was "not a font this site serves" on the
Design screen until `quilzo serve` restarted, and `site.events` did nothing on
the public site until `quilzo site` restarted. Now:

| | the design (`templates/`: the layouts, the theme, the style layer and the faces) | the settings |
|---|---|---|
| `quilzo serve`, the admin | when the directory changes (looked at no more than once a second, as the admin is used), and on SIGHUP | read when used, as before; the interface's brand, the passkey rules and the API's limits still at a restart |
| `quilzo site`, the public site | with each publish, and on SIGHUP | when the configuration, listings or languages change, with each publish, and on SIGHUP |

The public site takes the design with a publish rather than the moment a file
changes, on purpose. The publish gate is what holds a design to the standard: it
computes every contrast pair the theme makes and renders every page through the
layouts. `quilzo theme set --force` saves a palette that fails, and says the gate
will refuse it; a site that served `templates/` a second after it was written
would put that palette in front of readers with no gate at all. So the preview
shows a change at once, and readers get it with the publish that passed. A style
layer is the same: saved from the Design screen, it is in the preview when the
screen comes back; set with `theme layer set`, or edited by hand, it is in the
preview with the admin's next look at `templates/`; and either way readers get it
with the next publish. A reader's browser asks for `/site.css` again with every
page, as it does for the page, and is answered "not modified" while it has not
changed, so somebody who visited an hour before the publish is not handed the
new page over the old stylesheet. SIGHUP —
`systemctl reload` with the unit in [deploy/](../deploy/) — is the operator
saying so, as a restart was, without dropping a connection.

The site looks for a publish once a second whether or not anybody is visiting,
because it reads the design when it sees one: a site that looked only when
somebody visited would read, an hour after the gate, whatever had been saved in
the hour, and a palette forced past the gate after the publish would go to
readers with it. A publish whose build is refused (below) brings its design with
the next build that succeeds, unless `templates/` has changed since; then it
waits for the next publish, as any other change does.

A rebuilt site keeps what visitors are in the middle of: rate limits and their
counts, the signals it is counting, sign-ins in progress, the chatbots' rating
keys, the newsletter's hourly count and the fediverse queue. Their settings —
`auth.throttle.*` for the site's limits, `chatbot.questions.*`, `fediverse.*`, and
the content API's — take effect at the next restart, because a reload that handed
every visitor a fresh allowance would be a limit that resets whenever somebody
publishes. A reload whose build fails changes nothing: the site serves what it
served, says why, records `site.reload` as a failure in the audit log, and tries
again when something changes again. One whose design does not read — a theme
file that is not JSON, a `page.html` gone — keeps the design it had, takes the
rest, and records the failure with the reason. A reload that changed what readers
get is recorded too, with what triggered it.

That includes a `config.json` caught empty. Writing one with `>`, with `cp`, or
from an editor that writes in place leaves it empty for a moment, and an empty
file reads as every setting at its default: the classification banner,
Strict-Transport-Security and security.txt would go with it. So a site whose
settings said something does not take an empty file as its next ones; write `{}`
to it, or remove it, to put every setting back to its default on purpose. The
chatbots are built again with the settings, so a guardrail set while the site
runs screens what they answer from at once, and they keep the ratings they
handed out.

## Building a whole site from a sentence

A site is a declaration: pages made of sections this program renders, menus,
forms, a question box and a look. So building one is writing a declaration, and
a model can do that without writing any code:

```bash
quilzo site new "a bakery in Leeds: sourdough, rye, and a café upstairs" --install
quilzo site fill                                   # what only you know
quilzo site fill "your address=4 Mill Lane, Leeds"
quilzo publish
```

The kind of site (business, product, restaurant, portfolio, community, event)
picks the pages and sections; a model, when one is allowed, rewrites the words
for the description. Its answer is held to the start it was given: links only
to the site's own pages, sections of kinds that render, forms that pass their
checks, a question box that sends nothing anywhere, and no agents, webhooks or
hosts. The privacy page is not the model's: it is written from what the forms
collect, why, on what basis and for how long.

The builder never makes up a fact. A price, an address, opening hours or
somebody's words that the description does not give are left as
`[[what goes here]]`, and the publish gate refuses a page that still holds
one. Filling one in fills it on every page it is on. Installed pages are
marked for how they were written, by a model or by the builder's template, so
the AI-content disclosure is right without anybody remembering to set it.

The result is a package like any other: its card says what it collects and
shows, a second administrator approves a site with a contact form (or the only
administrator does, on the record), and removing it puts the site back as it
was. The Make screen does the same under Build a whole site and Fill in.

### An agent as the site crew

An agent connected over MCP can do the building too: `site_build` from a
description, `site_import` from an old site's address, or `propose_feature`
with a package it wrote, such as a booking form or a directory. None of these
installs anything. What the agent made waits as a proposal, under Proposed for
you on the Make screen, on Approvals and in `quilzo feature proposals`, until a
person reads its card and installs it as their own decision, with the same
approvals as anything they bring. The agent counts as nobody: a site with a
contact form still needs two people, or the only administrator on the record.
A newer proposal of the same package replaces the older one, at most twenty
wait, and a proposal nobody reads lapses after two weeks.

Once it is installed, `site_blanks` lists what is left to fill in and
`site_fill` fills it, with facts the person gave the agent; a blank it cannot
fill stays one, and keeps its page from being published. A page an agent filled
in is marked as an agent's words, and a page in a package an agent wrote as a
model's, so the AI-content disclosure is right either way. What an agent fills
in waits for a person's approval before it is published, as anything a model
writes does. The person it was filling in for gives it when nobody else may
publish and no count of approvals is set; otherwise somebody else does.

## Taking bookings

A plumber, a salon or a clinic needs a page where somebody picks a time. Here
that is a section, like any other:

```bash
quilzo booking example > bookings.json    # hours, closed dates, services
quilzo booking setup bookings.json
```

and a `booking` section naming a service on any page. The free times are worked
out when the page is asked for: within the hours, in the site's own time zone
and by the clock on the wall on the day the clocks change, not on a closed
date, not sooner than the notice, and clear of every booking and the time left
after it. They are radio buttons drawn as chips, so there is no script. A
visitor books one and is shown it on the same page, from an address only they
were given, with a calendar file to add and a button to cancel. The time is
checked again under a lock as it is booked, so two visitors cannot both get it.

What the public process may touch is the point. A booking is two things kept
apart: the calendar, which says when, for how long and for what, and is read
by the site to offer free times; and who booked, which the site writes once and
never reads. Names, addresses and telephone numbers are read on the Bookings
screen and in `quilzo booking list`, and forgotten a set number of days after
the appointment. `quilzo booking feed` makes a calendar address for the owner's
phone that shows times and services, never names. It is one calendar, taking
one booking at a time; staff with calendars of their own, deposits and
recurring appointments are not here.

A feature package can carry the setup as a `bookings` block beside its booking
page, which is how an agent proposes a site that takes bookings: its card says
what it collects, two people approve it, and an upgrade keeps the owner's
calendar address and any pause. Over MCP, `booking_times` shows an agent the
free times visitors see and nothing about who booked; on the page, a visitor's
own browser agent is offered the booking form as a WebMCP tool, which the
visitor still submits.

## Listing what is on

A venue, a club or a bakery with classes needs a page of what is coming up that
does not need tidying every morning. Events are records like any others, and
one feature sets them up:

```bash
quilzo events setup          # the type, its records, a What's on page, a page for each, the calendar
quilzo records add events title="Rye night" slug=rye-night date=2026-11-14 time=19:30 until=21:00 venue="The bakery"
quilzo publish               # events are content: published like the rest
```

An event has a date, and a time when it is not all day; a last day when it
lasts several, and a time it finishes. They are on the site's clock,
`site.timezone`, as the people going to it say them. The listing of what is to
come keeps an event until its last day is over, comparing with now when it is
read rather than when it was published, so nothing has to be taken down, and
the page showing it carries the minute in its tag so a cache is never told it
has not changed. An event with a time it finishes leaves at that time.

`site.events` names the listing whose records are the site's events, which
`events setup` sets. From it come an `events` section that any page can carry,
the calendar at `/events.ics` that visitors subscribe to, a calendar entry for
each event, and schema.org `Event` data on each event's page: start and end
with the site's offset, the venue or the online address, whether it is
cancelled, postponed or moved online, and where tickets are sold. All of it is
read through the listing, so its field allow-list decides what the calendar
and the structured data say exactly as it decides what the page says.

`upcoming_events` shows an agent what is on over MCP; an agent adds an event
by writing a record, and proposes events for a site that has none with a
package carrying an `events` block.

Events kept in a calendar come in from it:

```bash
quilzo events import club.ics                       # a calendar file
quilzo events import webcal://calendar.example/…    # or where Google, Outlook or Apple publish it
```

Each event, and each time a repeating one happens from a year before to a
year after, becomes an event of the site, on the site's clock whatever zone
the calendar wrote it in, Outlook's Windows zone names included. Brought in
again, the same events are changed rather than added twice, keeping a picture
or a page link somebody gave one since. An event the calendar marks private
is left out, because a site's events are public once published, and a private
calendar's address is its password, so only its host is ever printed or
written down. The events wait in the draft to be looked over and published.

## Keeping a blog

A blog is posts, newest first, each with its own address that keeps working
however many come after it. Posts are records like any others, and one
feature sets them up:

```bash
quilzo blog setup            # the type, its records, a Blog page, a page for each post, the feed
quilzo records add posts title="Rye, at last" slug=rye published=2026-11-14 byline="Sam" body="The rye took three tries."
quilzo publish               # posts are content: published like the rest
```

A post has a title, the end of its page's address, the day it went out, and
what it says, in the same small Markdown a page's body takes: headings,
lists, bold, italic and links. A summary is what the list of posts, the feed
and a search result show; tags, a picture with what it shows, and the day it
was last changed are there when they help.

`site.blog` names the listing whose records are the site's posts, which
`blog setup` sets, and `site.feed` too when the site has no feed. From it
come a `posts` section that any page can carry, showing the newest with when
each went out and who wrote it, and Older and Newer posts a page at a time
(`?page=2`) back to the first; each post's page, with the posts either side
of it; and schema.org `BlogPosting` data on that page. Every post has its
page, however far back: a record's page is found among everything its
listing's conditions keep, not among the rows a page shows at once.

An agent reads the posts through the listing (`run_listing`), writes one as
a record, and proposes a blog for a site that has none with a package
carrying a `blog` block.

## Keeping a newsletter

A newsletter is a list of people who asked for one and the letters sent to
them. Here the letter is a page: write it, publish it, and send it.

```bash
quilzo newsletter test october --to you@example.com   # one copy, to read first
quilzo newsletter send october --yes                  # every confirmed address, once each
```

A `newsletter` section on any page takes sign-ups. Nothing is sent to an
address until it says yes: signing up mails it one link, and the page that
link opens has a button, because mail filters open links to look at them and a
filter is not a person agreeing. An address that never presses it is forgotten
after a week, and one address is mailed a link at most once an hour, so the
form cannot be used to fill somebody's inbox. Every issue goes as its own
message to one address, with a link to leave at the bottom and the
`List-Unsubscribe` and `List-Unsubscribe-Post` headers (RFC 8058) that mail
apps turn into their own unsubscribe button: one POST, no page, no redirect, and
the address is deleted. It is kept afterwards only as a keyed hash, so an old
list imported again cannot put it back.

What the public process may do with the list is the same rule as bookings: it
writes an address once when somebody signs up, writes that they confirmed, and
deletes them when they leave, and never reads an address back. Ids and links
are keyed hashes, made with a key at the store's root that the site can read
and not write, so checking a link reads nothing either. The addresses are read
on the Newsletter screen and in `quilzo newsletter list`.

A list moves both ways. `quilzo newsletter import FILE --agreed "…"` reads an
export from Mailchimp, Substack, Ghost, MailPoet, Buttondown and most others,
finding the columns by name; anybody the file says unsubscribed, bounced or
complained is kept as having left rather than added. `quilzo newsletter export`
writes the confirmed list as the plain CSV every one of those imports.

The page becomes mail by its words, in the order a visitor reads them: title,
lead, picture, text, then each section's heading, paragraphs, items and
buttons, as plain text and as one column of HTML with its styles inline. What a
mail cannot hold, such as a booking or a question box, stays on the page, and
the mail says so and links to it. Sending is paced, written down address by
address, and goes on from where it stopped. An agent can propose an issue over
MCP (`propose_issue`), and see how the list stands (`newsletter_status`, counts
and no addresses); a person sends it, after sending themselves a test. Mail
goes through the relay in `mail.json`, which should sign it with DKIM: that is
what lets a mail app trust the one-click headers.

## Taking payments

A shop needs a till as well as a catalogue, and a till is where a CMS usually
starts holding card numbers, orders and addresses it then has to protect. This
one holds none of them. The provider's hosted checkout takes the card and the
address; Quilzo makes a payment link for each published price and shows a Buy
button only where the link charges exactly what the page says:

```bash
quilzo secret set stripe < key.txt          # a restricted key is enough
quilzo pay enable stripe --ship-to GB,IE    # a second administrator approves
quilzo pay                                  # products for sale, links selling
quilzo pay orders                           # read from Stripe, not kept here
```

A product whose row says `"interval": "month"` (or week, or year) is a
subscription: its price at Stripe is recurring, its payment link starts a
subscription the buyer manages and cancels at Stripe, and its Buy button says
"£12.00 a month". Monthly and yearly at one price are two offers, each with its
own link; an interval Quilzo cannot read is no offer, and no button.

The links follow publishing. A new price gets a new link, and then the old one
is retired. A price no link charges yet shows no button at all, so a page
never offers a checkout at a price it does not show. The site process holds no
key: the admin makes the links, and the site reads only the list of them.

Each sync asks Stripe which links still sell for the key it holds, and a link
that does not is made again. So when the test key a shop was set up on is
replaced by the live one, the next `quilzo pay sync` (or publish) makes live
links and the test-mode ones stop being offered, and a link deleted in Stripe's
dashboard comes back. A live link a test key cannot see is taken off the site
and named, to be retired in Stripe's dashboard.

## Bringing a site you already have

Most sites somebody wants to move have no export file. What every one has is
its pages, so a site comes in by its address:

```bash
quilzo site import https://your-old-site.example --install
```

robots.txt is read first and obeyed; the site's map of itself is used when it
publishes one, its links when it does not; only that host is read, through the
fetcher that refuses private addresses, at a polite pace and within a page
budget. Each page's content becomes a hero and sections, its navigation becomes
the menus, and its name and colour become the look. Pictures come with the
descriptions the site gave them, and a picture it never described is left out
rather than described by somebody who did not write it. Scripts, frames and
forms are left behind and named on the card. Old addresses that change are
redirected, from the site's own redirect map, so links and search results keep
working; `quilzo site` serves that map with any `--redirects` file laid over it,
and `quilzo export` carries it, so they keep working wherever the site goes
next. It is a site package like any other: read, approved, installed and
taken back as one decision.

A site that can export itself comes in from the file instead, with what a
crawl cannot see: which pages are posts, when each went out and who wrote it.

```bash
quilzo site import oldsite.WordPress.2026-10-29.xml --install    # WordPress, or Squarespace's export
quilzo site import crumb.ghost.json --site https://crumb.example # Ghost, and where it was, for its pictures
quilzo site import ./my-hugo-site                                # a folder of Markdown, or its .zip
```

A WordPress or Squarespace export (WXR), a Ghost export, or a folder or zip of
a site's files: the Markdown that Hugo, Jekyll, Eleventy, Astro, Docusaurus or
Gatsby build from, a Notion or Obsidian export, or the pages Webflow exports.
Pages keep their words with their headings, lists, links, bold and italic, and
their pictures; posts become the blog (see Keeping a blog), each with its
picture, author, tags and dates, and the pictures among its words; the menu
comes from the export's own, and every old address of a page or a post
redirects to where it is now. Drafts, private posts and posts for members or
paying subscribers stay behind and are counted on the card, as do comments and
a generator's shortcodes. Nothing in the file is fetched while it is read, and
a folder is read through a root that nothing outside it can be reached from;
pictures come from the folder or through the fetcher that refuses private
addresses. The posts travel as records named by the hash of a staged file, so
the package stays one a person reads, and they are written once, when it is
first installed. It is meant for a site that has none of its own yet: one with
a blog or a home page already refuses it, and says which part.

## Spreadsheets in and out

A catalogue, a price list, a directory or a term's events often already
lives in a spreadsheet. Any collection takes one, and gives itself back as
one:

```bash
quilzo records import products prices.csv --dry-run    # what it would do, writing nothing
quilzo records import products prices.csv --key sku    # a row with a known sku changes that product
quilzo records export products -o products.csv --excel # out again, for Excel
```

A CSV from Excel, Google Sheets, Numbers, Airtable, Notion or Shopify is
read whatever it was saved as: commas, semicolons or tabs between cells,
UTF-8, UTF-16 or older Excel's Windows-1252. Columns are matched to the
type's fields by name, by label, or by what other platforms call them (a
product's Handle is its page link), and `--map 'Heading=field'` matches the
rest by hand. Each value is read as its field's kind: 14/11/2026 and
14 November 2026 as a date, 7.30pm as a time, £1,250.00 as a number, Yes as
true. A date that could be the 3rd of April or the 4th of March is asked
about (`--dates dmy` or `mdy`) rather than read one way, and a value that is
not its kind is reported with its line.

A row is the record already there when its id column names it, or when its
key field matches, the page link unless `--key` says another: that record is
changed by the row and keeps its other fields, and an emptied cell clears
its field. Any other row is a new record, with an id worked out from what
names it, so a sheet brought in twice is the same records. A page link a row
leaves empty is made from its title and kept apart from the others. A
picture named by address is fetched into the media library with what its
alt column says it shows. One row the type refuses refuses the sheet, unless
`--skip-bad` brings the rest and lists it, and the whole sheet is one
commit, in the draft until it is published.

`records export` writes the id first and the type's fields in order, so the
sheet comes back in as the same records, and each picture as the address the
site serves it at, so another site can bring it in too. A cell beginning
`=`, `+`, `-` or `@` that is not a number is written after an apostrophe, so
a spreadsheet opening it does not run it as a formula. `--format json`
writes JSON instead, which import reads the same way. The Data screen does
both: Download as a spreadsheet, and Bring rows in, with the same choices.

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

## Bringing an agent you already have

The same goes for agents. One built on another platform is read into a
declaration here, with a report of what was kept, what was changed to work
here, what was left out and what is yours to decide:

```bash
quilzo agent import .claude/agents/code-reviewer.md          # read it, declare nothing
quilzo agent import agents.yaml --save                       # declare what checks
quilzo agent import bedrock-agent.json -o imported/          # write it out to change first
quilzo agent export code-reviewer --to adk -o .              # and back out again
```

The admin does the same under Agents → Import one from another platform, and
each agent's page has *Take it to another platform*.

| Format | Import | Export | The file |
| --- | --- | --- | --- |
| OpenAI Assistants | yes | | an assistant object, or `GET /v1/assistants` |
| Claude Code subagent | yes | yes | `.claude/agents/NAME.md` |
| Claude Agent SDK | yes | yes | the agents given to `query` or `claude --agents`, as JSON |
| Google ADK agent config | yes | yes | `root_agent.yaml` and its sub-agents |
| Microsoft 365 Copilot declarative agent | yes | yes | `declarativeAgent.json`, schema 1.x |
| Open Agent Specification | yes | yes | an `Agent` component, JSON or YAML |
| Letta Agent File | yes | | an `.af` file |
| Amazon Bedrock Agents | yes | | `get-agent` output with its action groups, or CloudFormation |
| CrewAI | yes | yes | `agents.yaml` |
| AutoGen AgentChat | yes | | an AutoGen Studio component, or a team |

The format is recognised from the file; `--from` names it when it cannot be.
The instructions, the model, helpers it hands work to and its step and time
limits carry over as they were. Read, search and file tools become the
capabilities that do the same here. An HTTP API it called through an OpenAPI
schema becomes tools on that host, the operations that write asked about first,
with the schema written out for `quilzo integrations import`.

Some things do not carry, and the report says which. Code a platform ran for
the agent (a Python tool, a Lambda, a code interpreter), a shell, MCP servers
and other platforms' data sources become decisions: each needs an integration,
a program, or a host it may read, because here nothing is reached that the
declaration does not name. Whatever it was allowed elsewhere, an imported
agent starts at **propose**, or **draft** if it writes: it publishes nothing
until a person gives it more on its page. (A Quilzo declaration is carried
whole, as it was written.) A model named by an alias, such as `sonnet`, is
tried on a gateway route of that name. An agent another vendor runs, offered by
an A2A card, is registered rather than imported: `quilzo fleet add CARD_URL`.

Export writes what the other platform has words for, and lists what it does
not. Budgets, autonomy, asking first and which site an agent reads are this
program's, so they are always on that list.

## Deploying

[deploy/](../deploy/) has what a stable address needs: a Caddyfile that renews its
own certificate, and a hardened systemd unit for the public site. The admin is
deliberately not in any of it — it is loopback and holds credentials, so it is
reached over an SSH port forward rather than a hostname.

## The three processes

```
quilzo serve      the admin        loopback, behind your own auth
quilzo site       the website      the thing you point the internet at
quilzo studio     screen recording loopback, and the only one that runs scripts
```

Separate binaries-in-one, separate ports, separate exposure. The public process
holds no administrator's credential, cannot reach a ref and cannot cause a
commit. On Linux it confines itself with Landlock before it opens anything: it
reads the store and writes only its own state, each kept in a directory of its
own (form submissions, boards, members, chatbot handoffs, analytics, bookings,
the newsletter's list, the shield's state, its followers, the model ledger,
webhook deliveries, a temporary directory) and the audit log's two files. The store's policy, tokens
and configuration, and its root, are out of its reach, and it checks that at
start and refuses to run if they are not. `quilzo site --prepare` makes and
lists those paths, for a service manager that makes the store read-only
(see [deploy/](../deploy/)); run it again after an upgrade that adds one, or
the site starts with that feature off and says which. `--confine=false` runs it
unconfined and says so. A writable content API (`--api --api-writable`) writes
the draft, its objects, refs and `types.json`, which the confined site cannot
reach, so the site refuses to start with one and says to add `--confine=false`,
which takes that reach on; write through the admin otherwise.
It cannot read a submission back: reading the postbag happens in the admin,
behind authentication.

The studio is a separate process for the same reason, arriving from the
opposite direction. The admin's policy is `default-src 'none'` with one script
allowed, its own, by a nonce on each response. It finds a screen by name, keeps
a form's unsaved words for its tab, and sends what the admin's own forms send,
to the admin and nowhere else; every screen works without it. `getDisplayMedia` and `MediaRecorder` are JavaScript
APIs with no form post behind them, and capturing a screen or a microphone is
not a script the admin should carry. So the capture surface is its own process:
**the argument for that header is that the admin's one script does nothing a
form cannot, not that the policy catches the rest.**

### The log writer, which also signs for the log

`quilzo logd` is a fourth process, run as an account of its own; the
reference compose runs it as uid 65533 with no network. The admin and the
site hand it their records over a socket and cannot open the log to rewrite
one, and it computes the chain itself, so they cannot forge a history either.
`quilzo logd status` says whether that separation is in force.

It also holds the key that signs the log's tree heads, with Ed25519 and
ML-DSA-65 as before. On its first start it makes `head.key` (0600, its own)
and `head.pub.json` (0644, the public half) in the directory `--log-dir`
names, and from then on every signature the log's keys make is the writer's:
`quilzo auditlog head`, an agent's or an app's receipt, each round of the
audit stream, an engagement package, `quilzo feature export --sign` and a
registered research plan. Until it held the key, the admin of the reference
compose could make none of them: it tried to create `head.key` in a directory
it can only read, and every one exited with "read-only file system". Letting
it write there would let it rename the log.

The admin asks over the same socket, and a request for a head names how many
entries it covers and nothing else. The writer computes the root over its own
file and dates the head by its own clock, so an admin that has been taken
over cannot have a head signed over entries the log never held, or backdated.
A feature package's or a research plan's signature is made only under the
contexts this program makes them under, never the head's. The admin checks
every head it is handed against the root it read itself and against
`head.pub.json`, and refuses one that disagrees with either rather than
putting it in a receipt.

Every account that may submit a record could ask for a signature too, and a
record and a signature are not the same trust: the public site submits
records, and a feature package or a research plan the writer signs is taken
as this site's own. `--sign-uid` names the uids that may ask, and
`--sign-gid` the groups an account must connect as; with neither, every
account that may submit may ask, as before. The reference compose runs the
site as the admin's uid, since they share the store and every file in it is
that account's, in a group of its own (65531) with the writer's group
beside it for its records, and the writer signs for the admin's group
(65532) only. A uid of the site's own would take every file in the store
changing hands, and is not done. The group is the one the site connects as,
which it could change to the admin's, being a member of it, by running a
set-group-ID program it made itself; it cannot while it runs with
no-new-privileges, as every Quilzo container in the reference compose does.

The writer signs only with a key that is its own alone: `head.key` owned by
its account, at 0600. A key another account made, or one other accounts can
read, is one somebody else may have kept a copy of, and could sign a head
over any root with; a chown or a chmod cannot take a copy back. So the writer
signs nothing with it, keeps writing the log, and says to move `head.key` and
`head.pub.json` aside together (that `head.pub.json` still checks the heads
the old key signed) and start it again, when it makes a new one. `quilzo logd
status` asks the writer for a head over no entries rather than assuming it
signs, and says when it does not, and why (`writer_signs` and
`writer_refuses` in its `--json`); the audit log screen asks the same on
every visit. With the writer stopped, and the key out of this account's
reach as it is under the reference compose, no head can be made: both say
the heads wait for the writer, and every command that signs says to start
it, never to take its key.

There is no setting. Where the log is the admin's own (in the store, or a
writer running as the same account) the key is beside the log and loaded
there, as it always was. Heads saved with `auditlog head --save` stay in the
store, in `log-heads.json`. `head.pub.json` is the file to hand whoever
checks a head or a receipt: `quilzo auditlog verify-head FILE --keys
head.pub.json`, `quilzo agent verify-receipt FILE --keys head.pub.json`. The
audit log screen says when the writer signs the heads, and where that file
is.

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

**What search engines and agents are told.** Every page names where it lives
with a canonical link, once the site has an address, so the same page reached
with a query string or through a redirect is one page and not several competing
with each other; a layout that writes its own keeps it. A page published first
somewhere else names that address instead (`"canonical"`, or "Published first
at" in the editor; a typed page through a `canonical` field its type declares)
and leaves the sitemap, which lists what this site is the
source of. A page that should not be found — a thank-you page, a campaign's
landing page — asks to be left out of results (`"noindex": true`, or the box
in the editor) in its head, its headers and the sitemap. And every page has a
Markdown copy of its words at `/NAME.md`, made from the content rather than
scraped from the markup, linked from the page and from `llms.txt`, for a
language model or a reader's agent; the copy is never indexed and names the
page as canonical.

**What people looked for and did not find.** The cookieless count of views
also counts addresses people asked for that are not on the site, and searches
that found nothing (masked as unanswered questions are, so an address typed
into the search box is not kept). The Analytics screen lists both: each missing
address with the published page it most likely meant — the same last segment,
a spelling one slip away, most of the same words — and, for whoever may
publish, "Redirect it", which writes a permanent redirect the running site
picks up within a second. Never applied by itself: a wrong redirect is worse
than an honest 404. The same from the command line:

```bash
quilzo redirect list
quilzo redirect add /old-prices /shop [--temporary] [--note "the 2024 catalogue"]
quilzo redirect remove /old-prices
```

A redirect that would make a loop or a chain is refused when it is added.

With `site.indexnow` on, each publish tells the search engines that take
IndexNow (Bing, Yandex, Seznam, Naver and others, which share what one is told)
the addresses of the pages that changed — a page that reuses a changed block
among them, never one left out of results, a copy of one elsewhere or a block's
own — with a key the site serves at `/KEY.txt` to show the addresses are its
own. Off by default, since it sends the site's addresses to a third party on
every publish, and it goes out through its own declared network purpose, so an
offline installation refuses it and says why.

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
and is refused without them. The same rules read what an agent writes to
another system, from a run here or through the MCP gateway: a post or a message
that says what they refuse waits for a person, who is shown what they found,
every time. And image licences treated as publish windows, because rights *end*
— a lapsed stock licence leaves a site infringing with an audit trail proving
it was deliberate, and nothing notices.

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

A form takes answers only where the site offers it: a published page, visible
now, that names it (`"form": "enquiry"`) or renders through a layout with the
form's markup pasted in, or a chatbot that may fill it in. A form declared and
placed nowhere, or on a page still in draft or past its date, answers not found,
so it cannot collect anything the owner is not asking for.

A form can take a file — a CV, a photograph of the damage, a signed letter —
with a field of kind `file` (`"accept": ["image"]` to narrow it; images and
documents by default). A file is taken by what its bytes are, never by its name
or the type the browser claimed, with the media library's own checks: an image
must decode, a PDF must be one and do nothing when opened. At most 10 MB a file
and 20 MB a submission. It is kept beside the submission and goes with it — when
it expires, when it is erased, when the form is purged — and staff get it back
only as a download from the Forms screen, named afresh, typed by what it is,
under a policy that runs nothing, with the reading in the audit log.

A question can be asked only on an earlier answer — the order number when the
topic is Returns, who gave it when "It was a gift" is ticked — with
`"when": {"field": "topic", "is": "Returns"}` on the field, or "Asked only when"
in the form builder. The server decides: such a question is required when its
answer was given, and neither required nor kept when it was not, whatever
arrived for it. The page hides it until then with a stylesheet the form serves
at `/form/NAME.css`, using `:has()` and no script; a browser without `:has()`
shows every question with the words that say when it is asked. A condition on a
later field, on a choice the field does not offer, or on anything but a choice
or a box is refused when the form is declared, and consent cannot rest on a box
only some people are asked to tick.

The retention ceiling is enforced by the program. Both long-running servers
sweep on a timer of their own, and `quilzo form expire` still forces it. This
used to say that nothing called it on its own and that a deployment needed a
cron entry — which was true, and meant that an operator who had not read the
paragraph had a site that promised to forget and did not. A declared retention
period and an enforced one are different things, and only the second is worth
anything to the person whose data it is.

An install that runs neither server has nothing sweeping, so `quilzo posture
scan` counts submissions that have outlived their period.

**Scheduled publishing** goes out on time from `quilzo serve`, which sleeps
until the next entry is due and publishes it within a second; an entry that
fell due while the server was down goes out when it starts, and the record
says how late. Each publish is on the authority of the person who scheduled
it, checked again when it fires — somebody who has lost the publisher role
since does not have their launch published for them — and of the identity the
server runs as, and it carries the publisher role and nothing more. Every gate
runs then, against the content as it stands. A deployment that would rather
publish from a timer of its own turns off `schedule.in_server` and runs
`quilzo schedule run`; the two take the same lock, so an entry is never
published twice. The Publishing screen lists what fired in the last thirty
days and why anything was refused, and the posture scan reports an entry that
was due and did not fire.

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

**Two kinds of authority, and only one of them was written down.** The access
model above is the standing kind: a binding says this principal has this role on
this resource, an administrator granted it, it is revocable, and an explicit deny
wins wherever it sits. The other kind arrived later and by accident. A call has a
host who can eject people. A room has a moderator who takes messages down. An
errand has an owner who is the only person who can confirm it. **Nobody granted
any of those**, they expire when the situation does, and each was invented inside the
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
situational costume and needs the standing authority for what it actually does,
which lands on **publish**: the ladder already defines it as the only action with
an outside observer. Every situational role here today acts inside its own
situation; the ones that reached outside (an incident's commander, a detection's
promoter) left with a security team's tools, and the rule is what keeps the next
one honest.

So every situational role declares its powers and, for each, whether the effect
survives — with the reason, because that classification is a judgement and an
unexplained judgement is one nobody can disagree with. A power that reaches
outside and names no standing action is refused, and so is one that acts inside
and demands authority anyway. A guard checks the register covers every package
that reaches for the obvious vocabulary, because the failure this exists to
prevent is a ninth model appearing quietly in the tenth package.

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
  that stops a model shipping unreviewed. What a run writes is the agent's,
  made for the person who started the run, as the run's record names them
  rather than whoever let one of its steps go ahead, and each commit says so.
  With `review.required_approvals` or `approval.required_humans` set, that
  person asked for the change, as they would their own, and somebody else
  approves it; with neither set, they may approve it when nobody else may
  publish, as before.

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
[scripts/agentdojo/README.md](../scripts/agentdojo/README.md) has the method and its
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
this one will and will not allow before it asks for anything. The card's
description starts with the site's own sentence — `site.description`, or
`quilzo site --description` for one run — and then says how its skills are
governed, so an agent choosing between two sites reads what each is for before
how it is run; a site with no description keeps the governance sentence alone.

The device side is deliberately the boring version. A published site is an
installable app with a share target: the operating system offers it in the share
sheet, and a share arrives as **an ordinary multipart form POST** — no service
worker in the path, no JavaScript, no SDK. It lands as a submission with a
retention period and a privacy notice, because content anybody with a URL can
create is the vulnerability every CMS with open registration has had.

### Agents that start on their own

An agent can be given **triggers**: a time (`every day at 07:30
Europe/London`), or something happening on the site. The events are:
- pages going live, the live site rolled back, a draft proposed for review;
- records in a collection changing;
- a form sent, a booking made or cancelled, somebody joining or leaving the
  newsletter;
- a visitor asking a chatbot for a person, and a chatbot that could not
  answer.

This is how the CMS, the chatbots and the agents work through each other:
- a writer drafts a summary when a post goes live;
- a reviewer looks at every draft proposed;
- a helper drafts a reply when a visitor asks for a person;
- a gardener proposes a page when the chatbot keeps failing on a subject.

```
quilzo agent trigger tidy add --on page.published --where /blog \
  --goal "Summarise the new post and propose it for the newsletter"
quilzo agent trigger tidy add --every 24h --at 07:30 --zone Europe/London \
  --goal "Check yesterday's pages for broken links"
quilzo agent trigger tidy               # what starts it, and what each did today
quilzo agent trigger events             # every event an agent can start from
```

The agent's page in the admin has the same, under **When it runs on its own**.

**Authority.** A triggered run acts for the agent's sponsor, checked when it
starts:
- an agent whose sponsor has left, may no longer run it, or whose identity has
  run out does not start;
- it is capped at authoring, whatever its sponsor holds, so nothing that starts
  unattended can do more than draft and propose; publishing, and anything that
  goes out, is still a person's decision;
- a call of a tool that writes to another system (a post, a message, an order)
  waits for a person as asking first does, whatever `ask_first` says, and is
  decided one call at a time, by somebody other than its sponsor where there is
  somebody;
- triggers start it in its sponsor's name, so they are its sponsor's to set, or
  an administrator's. Adding one is a widening, recorded as one.

A run that a visitor's request to a chatbot starts is held in the same way: it
acts for the agent's sponsor with a stranger's words in its goal, and nobody
here started it.

**Sending unattended.** Administrators may let an agent send through one tool
from the runs nobody started:

```
quilzo agent sends tidy grant post_update --why "the shop's updates go out as pages go live"
quilzo pending approve ID         # a second administrator
quilzo agent sends tidy           # what it sends unattended, granted by whom and why
quilzo agent sends tidy revoke post_update
```

- The grant waits for a second administrator, as other privileged changes do,
  and is recorded as a widening with who proposed it and who approved it. A
  store with one administrator has it approved as it is made, and the record
  says so.
- It is for that tool at the host it reaches now. A declaration that points the
  tool somewhere else has not been granted that.
- It lifts only this hold: what the agent asks first, a payment beyond its
  mandates and the exfiltration breaker still wait for a person.
- Taking it back holds the next call at once.

**Safeguards against runaway runs.** Each trigger:
- starts at most its runs for the day (24 unless it says otherwise);
- never starts a second run while its first is going;
- never starts from something its own agent caused.

An event that agents' runs led to carries their names, and once three agents
have started each other it starts nothing more. A schedule that came round
while the server was down fires once when it starts, not once for every time it
missed.

**No people in it.** An event says what kind of thing happened and to what (a
page, a collection, a form, a chatbot), never who, nor what a visitor wrote. The
run is given that as data, after its goal, and reads anything more through the
operations it holds.

**Where an event came from is where it is kept.**
- The confined public site writes the events visitors cause in a log of its own,
  and cannot write the admin's.
- A line in the site's log claiming that a page went live is refused, and the
  refusal is recorded.
- So a site that was broken into cannot make agents believe something was
  published.

`agents.triggers` turns all of it off (nothing starts unless a person runs it),
and `agents.trigger_runs` says how many triggered runs go at once.

### Staff hear what visitors are waiting on

A visitor who asks a chatbot for a person and is never answered is the
commonest way a chatbot fails. `notify.staff` says who is told, by mail or in a
team channel:

```
quilzo secret set team-hook < slack-incoming-webhook.txt
quilzo config set notify.staff mailto:team@example.com,secret:team-hook
```

A channel's incoming-webhook address (Slack, Teams or Discord) is a credential,
since whoever has it can post as the site. So it is kept sealed, and the setting
names it (`secret:NAME`); an address given in the setting itself is refused. The
notice is posted with the site's webhook client, which will not reach this
machine or its network and does not follow redirects.

`notify.events` says what staff are told about: a visitor asking for a person
and a form sent, by default, and any event an agent can start from. An event is
named either way, by its own name (`page.published`) or by the one webhooks are
told it by (`published`), and so it is in `quilzo webhook add --types` and an
agent's `--on`. A notice says which chatbot or form and how many, never who or
what they wrote:

> 2 visitors asked the chatbot "help" for a person. They are waiting in the Inbox.

Notices are gathered a pass at a time, at most thirty go in an hour, and the
rest are counted in the next. Each is in the audit log (`notify.staff`), naming
the credential it used and never the address.

---

### Models from any provider

A gateway route can name a **provider** instead of an address. The address,
the way the provider takes its key, and what it says it does with what it is
sent then come from the provider's profile:

```
quilzo gateway providers                 # by group: this machine, model makers,
                                         # open-model hosts, routers, clouds, regional
quilzo gateway providers azure-openai    # what it keeps, where, and how to add it
quilzo secret set groq < key.txt
quilzo gateway route add fast --provider groq --model llama-3.3-70b-versatile
quilzo gateway route add azure --provider azure-openai --param resource=contoso-ai \
  --model gpt-prod --key-secret azure-prod
```

The **built-in catalogue** has more than forty providers:
- runtimes on this machine (Ollama, llama.cpp, vLLM, LM Studio, SGLang, LocalAI);
- the model makers (OpenAI, Anthropic, Google Gemini, xAI, Mistral, Cohere,
  Perplexity, AI21, DeepSeek);
- open-model hosts (Groq, Together, Fireworks, Cerebras, SambaNova, DeepInfra,
  Hyperbolic, Nebius, Novita, NVIDIA);
- routers (OpenRouter, Hugging Face, GitHub Models);
- clouds (Azure OpenAI, Amazon Bedrock, Cloudflare Workers AI, OVHcloud,
  Scaleway, Ollama Cloud);
- regional providers (Alibaba's Qwen, Moonshot's Kimi, Zhipu and Z.ai, MiniMax,
  SiliconFlow, Baidu, Volcengine, Sarvam, Upstage).

Each profile says where its address came from: the provider's own
documentation or code, widely used integration code, or unverified. An
operator's own `providers.json` beside the store adds profiles, or replaces
built-in ones with a company proxy, and every profile is checked when it is
read.

**A provider's route reaches that provider and nothing else:**
- it is pinned to the provider's host, so a key is never sent anywhere the
  profile does not name;
- a hosted provider is reached only at public addresses, and a local runtime
  only on this network;
- redirects are refused;
- a parameter such as an Azure resource or an AWS region is checked before it
  goes into a host name, so it cannot become a different host.

**Anthropic is spoken natively.** Nearly every provider serves OpenAI's chat
completions, and a profile says which protocol it speaks. Anthropic's profile
speaks its own Messages API, because what an operator chooses Anthropic for is
missing from its OpenAI-compatible endpoint. A route to it can say:
- how hard the model thinks (`--effort low|medium|high|xhigh|max`);
- where it may run (`--geo us`, or `global`, the provider's default);
- whether a request the model's safeguards decline is answered by another of
  Anthropic's models (`--server-fallback`, for the models that take it).

```
quilzo secret set anthropic < key.txt
quilzo gateway route add claude --provider anthropic --model MODEL --geo us --effort high
```

What Anthropic's models refuse is refused where the route is made, not on
every call after:
- a temperature or a top_p;
- `--draws`;
- an effort, a geo or a server fallback on a provider that speaks OpenAI's
  protocol.

The conversation goes as the Messages API takes it:
- system prompts in its own field;
- pictures as base64 blocks;
- tools with their schemas, and a tool's results in the user's turn.

A request that may write at length is streamed and read whole. Usage, cache
reads included, goes into the ledger. Thinking blocks the model returns are
not passed on.

**A request a model declines is not sent round its safeguard.** When a
model's safeguards decline a request (Anthropic's `refusal`), the caller is
told so. The route is not rested, since it is well. The request is not sent on
to the next route, because routing round one provider's safeguard to whichever
has fewer is not a fallback. The ledger counts it among the failed calls,
since it was sent and paid for.

**A chatbot chooses the model that answers it.** Each chatbot can name a
route, or the model a route serves, that answers it first, with the gateway's
other routes behind it:
- a cheaper model for a busy help desk;
- a stronger one for a sales chatbot.

Use `quilzo assistant add NAME --model --route big`, or "Model that answers
first" on the chatbot's page. Add `--route-only` (or "Only that one") to keep
a chatbot to that route alone, for one whose visitors' words may go to one
provider, in one region, and nowhere else. When that route cannot answer, the
chatbot quotes its pages rather than asking another. Agents already choose
theirs by their manifest's model.

**Chatbots can find passages by what they mean.** By default a chatbot finds
the passages that answer a question by their words, here, and sends nothing
anywhere to do it. Name a route added with `--embeds` (an `/embeddings`
endpoint: OpenAI, Mistral, Gemini, Ollama and most others serve one) and
chatbots that answer with a model find passages by meaning too:

```
quilzo gateway route add vectors --provider openai --model MODEL --embeds --price-in 0.02
quilzo config set chatbot.embeddings vectors --reason "find passages by meaning"
quilzo assistant embed                  # now; after each publish it is automatic
```

A visitor asking "may I have a refund on ink I have used" then finds the
passage about returns, which never says "refund".

How it works:
- The site's published passages are embedded once, after each publish, and
  kept by their text's hash, never the text; only new ones are embedded again.
- Each question is embedded as it is asked, charged to the chatbot and masked
  as for any route not allowed personal data.
- A chatbot that only quotes its pages, or is kept to one route, takes no
  part: one promises nothing leaves, the other that its visitors' words go
  nowhere else.
- One route, and no fallback: vectors from two models are not comparable, so
  when that route cannot answer, chatbots rank by words alone.
- Meaning ranks beside words. It lets a passage that shares too few of a
  question's words through only when the two are at least
  `chatbot.embeddings_floor` alike (55% by default). The chatbot's test screen
  shows each passage's similarity, to tune it by.

**A model drafts a video's captions.** A video with no captions does not
publish (WCAG 1.2.2), and writing them by hand is the hour nobody has. A route
added with `--transcribes` (an `/audio/transcriptions` endpoint: OpenAI, Groq,
or whisper.cpp and Speaches on this machine) drafts them:

```
quilzo gateway route add ears --url http://localhost:9000/v1 --model whisper --transcribes --personal
quilzo media transcribe VIDEO --lang en --author dana
quilzo media captions VIDEO DRAFT --lang en      # once a person has read it
```

The rules:
- The draft is stored as a WebVTT file, marked as a model's work and the
  person accountable for it.
- It is never attached. A model hears the words, not the door closing nor who
  is speaking, which is what captions are for; attaching it is a person
  saying it is right.
- A recording's voices cannot be masked the way text is, so it goes only to a
  route allowed personal data (`--personal`).
- The endpoints take a recording of at most 25 MB. One over that is sent as
  its sound alone, about fifteen MB an hour, taken out with ffmpeg when it is
  installed; without it, the refusal says how to take the sound out by hand.
- It is charged by the minute (`--price-minute`) to `media` and to the person.

**A model reads text aloud.** An audio version of an article, a shop's
welcome, a voice-over for a video. A route added with `--speaks` (an
`/audio/speech` endpoint: OpenAI, or Kokoro and Piper on this machine)
reads it:

```
quilzo gateway route add voice --url http://localhost:8880/v1 --model kokoro --speaks --personal
quilzo media speak @welcome.txt --voice af_bella --author dana
```

The rules:
- The recording is stored marked as a synthetic voice, with the model and the
  person accountable, as a generated picture is. A person hearing it is owed
  knowing it is not a person.
- Its words are kept with it as its transcript. No section plays a recording
  yet, and no page shows its words for it: link `/media/ID` from a page by
  hand and put the words beside the link.
- Text holding personal data goes only to a route allowed it. Masking cannot
  help here: a placeholder read aloud is not a recording anybody wants.

**Video from a prompt.** A route added with `--films` names a provider that
makes video — Google's Veo through the Gemini API, or a model on fal's queue —
and `quilzo media film` asks it:

```
quilzo secret set gemini < key.txt
quilzo gateway route add veo --provider google-veo --model veo-3.1-generate-preview --films --price-video 0.75
quilzo media film "a slow pan over a bakery at dawn, steam rising" --aspect 9:16 --author dana
```

Both are asynchronous: the request is taken, asked after until it is done (ten
minutes at the most), and the video fetched. Every address an answer names has
to be https on the provider's own host — a finished fal video on fal's storage
is fetched without the key — and a key never follows a redirect to another
host. What comes back is checked to be an MP4, stored marked as generated with
the model, the prompt and the person accountable, and like every video needs
its captions before a page shows it. The prompt is masked for a route not
allowed personal data, the call is charged to the budget and in the ledger,
and a prompt the provider's filters decline is said so.

**Agents act with a person's own accounts, not one key for everybody.** An
integration used to carry one credential for the whole install: an agent
filing into somebody's calendar did it as whoever owned the key, and every
agent that could reach the integration could do it in every calendar the key
reached. Now people connect their own accounts, on Your accounts in the admin
or with `quilzo connect start NAME`, at providers an administrator declares:

```
quilzo secret set google-oauth < client-secret.txt
quilzo connect provider add google --template google --client-id ID --client-secret google-oauth \
  --scope https://www.googleapis.com/auth/calendar.events
```

The social platforms each speak OAuth their own way, and their templates know
how: `youtube`, `tiktok`, `instagram`, `facebook` and `linkedin` start from the
documented endpoints and the scopes posting needs. TikTok is asked for
`client_key` and its scopes separated by commas. Instagram and Facebook issue
no refresh token, so the token a code buys, which lasts an hour, is exchanged
at once for one that lasts sixty days, and renewed when it is used a day or
more after the last renewal. LinkedIn's refresh token lapses a year after it
was first issued however often it is used, and past that the person is told
to connect again, with the date, rather than LinkedIn being asked. All but
YouTube need `--client-secret`. A provider declared without a template at
one of those platforms' own sites (`www.tiktok.com`, say) speaks that
platform's dialect, and says so; anywhere else it speaks `oauth2`, the
default and what every provider declared before speaks. `--dialect` names
one instead: `oauth2`, `tiktok`, `meta-instagram`, `meta-facebook` or
`linkedin`.

An integration that names a connection (`"connection": "google"`) then goes
with the account of the person the agent acts for, its sponsor, and nobody
else's. Three come ready-made: `quilzo integrations template` declares
Google Calendar, a Microsoft 365 calendar or GitHub issues (reading, and
adding a meeting or an issue), switched off and unpinned for a person to read,
pin and turn on as an imported one is. An agent acting on its own name, or another vendor's agent through
the gateway, has no person and is refused.

**A social media aggregator reaches the first platforms while their app
reviews are pending.** An aggregator holds the platforms' approved apps, and
each account connects through it, so one REST integration posts to several
platforms in week one. Which aggregator is the client's decision, on cost, and
none is written in: its host, the path it takes a post at, and its names for
the text, the media URLs and the platforms come from its own documentation.

```
quilzo config set site.base_url https://shop.example
quilzo integrations template social-aggregator --endpoint api.aggregator.example --path /api/post \
  --fields text=post,media=mediaUrls,platforms=platforms
quilzo secret set social-aggregator-key < key.txt
quilzo integrations pin social-aggregator
```

`--fields` is needed only where its names differ from `text`, `mediaUrls` and
`platforms`; `--secret` names the key, `social-aggregator-key` by default, and
`--auth header:NAME` sends it in a header of its own instead of as a bearer
token. It is declared switched off, with one operation, `publishPost`, a JSON
body of the text and the media, and stays off until an administrator turns it
on; agents call it through their declared tools, as any integration. A media
URL may only be one of this site's own `/media/ID` addresses, which the
aggregator fetches, so an agent steered by something it read cannot have the
client's accounts post a picture from somewhere else. The address is
`site.base_url` as it was when the aggregator was declared: a site that moves
edits it in the body schema in `integrations.json` and pins it again. A body
field the declaration does not name is refused before anything is sent. A
post is tried again, after a busy answer, only when it carries its step's
idempotency key, as every write is. An aggregator whose post nests its fields deeper is
declared the same way and its body schema edited in `integrations.json`, then
pinned again.

Another vendor's agent is an integration too, spoken to over Agent2Agent:
`quilzo integrations import agent-card.json` declares it from its card, switched
off, reaching the host its card says it speaks at. Its skills are the tools,
listed, pinned, allowed and approved as an MCP server's are; a call sends one
message naming the skill and returns what the agent answered, or what the task
it took on came to, asked after until it finishes or ninety seconds pass. A card
whose service address is not on the declared host is refused before anything
is sent, so a card cannot send this installation's credential somewhere else,
and the message carries the step's idempotency key as its id. An agent that
needs more ("input-required") is said so, with what it asked.

A remote MCP server that asks people to sign in — an issue tracker's, a
document store's — is set up from what it publishes, rather than by copying
endpoints from its documentation:

```bash
quilzo connect provider discover tracker https://mcp.tracker.example/mcp
```

Its protected-resource metadata (RFC 9728), named by the 401 it answers with
or at the well-known address, says which authorization server it trusts; that
server's own metadata (RFC 8414, or OpenID discovery) gives the endpoints. PKCE
with S256 is required, and a server that does not say it supports it is
refused. This installation registers there as a public client (RFC 7591) when
the server takes registrations, or uses `--client-id`; a server that answers a
registration with a secret is refused, so a secret is never kept that nobody
chose to keep. The metadata has to be for the server asked about, and the
authorization server's for itself: one server cannot speak for another. Every
request carries the resource indicator (RFC 8707), so a token is for that server
and is sent to it alone. Then an MCP integration naming the connection reaches
it as each person who connected, in Your accounts.

A write an agent makes elsewhere is named by the step of the run that makes it:
an `Idempotency-Key` header, the same for that step however often it is sent —
a run picked up again from its record included — so a service that keeps them
does it once. A call that met a busy service or no answer at all (408, 425,
429, 502, 503, 504, or a dropped connection) is tried again, up to three times,
waiting as `Retry-After` asks (ten seconds at most); a read always, a write only
when it carries its key. One that still did not get through is kept on the
Integrations screen and by `quilzo integrations undelivered`: which agent, run
and step, which integration and tool, the key, and what came back — never the
arguments, which the run's own record holds. Nothing there is sent again by
itself; a person settles it at the far side and takes it off the list.

How it is kept safe:
- **The flow:** authorization code with PKCE (S256), a state that finishes
  once, within ten minutes, and only for the person who started it, in their
  browser; templates for Google, Microsoft and GitHub, every endpoint https.
- **Where a token goes:** each provider names the API hosts its tokens are
  for, and a token goes to those and nowhere else.
- **How it is kept:** sealed under the store's keyring, in a file that names
  nobody; refreshed when due, keeping a rotated refresh token.
- **Disconnecting:** revokes at the provider where it offers that (RFC 7009),
  and forgets it here either way.

**Pictures and writing go through the gateway too.** A route added with
`--draws` (or "It draws pictures" on the Models screen) is an images model,
used by `quilzo media generate` and for nothing else, and charged by the
picture (`--price-picture`). A picture's prompt passes the same guard as words:
- personal data and credentials are taken out before it leaves;
- it is charged to `media` and to the person, each against their budget;
- it goes in the ledger.

The writing assistant (`quilzo assist` and the Assistant screen) goes through the
gateway as `assist`, charged to the person too. Both used to call the one
configured model directly, outside every budget and the ledger, and
`media generate` without masking anything.

Making a picture, a video or a voice (`media generate`, `film`, `speak`) or
drafting captions (`media transcribe`) spends the store's models, so it needs
the use-models permission, as the writing assistant does, and edit-draft to
store what comes back. Somebody denied the models still adds, edits and
captions media.

**The key is sealed.** It is kept encrypted with `quilzo secret set NAME` and
named with `--key-secret`, rather than in an environment variable every process
the server starts would inherit. The Models screen offers the same list and
shows, beside each route, its provider, where it serves from, and whether it
trains on what it is sent.

## Agents asking the site

A visitor's agent should not have to scrape pages built for people. The public
site speaks NLWeb: `/ask?query=…` answers with the published pages that match as
schema.org objects, streamed as server-sent events or, with `streaming=false`,
as one JSON document; `mode=summarize` or `generate` adds the answer the site's
question box gives, with its sources and the disclosure. The same is offered
over MCP at `/mcp`, as one read-only tool called `ask`. It answers only from
what a visitor may read now, writes nothing, and the crawl licence in front of
the whole site decides who may ask, as it does for every page. On a page,
WebMCP marks the forms an agent may fill in for its visitor: search, a
question, a declared form, a booking.

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

People sign in with a passkey or through their organisation's identity
provider, programs with a token, and a role says what either may do. The
differences matter more than the count.

**Passkeys**, added through a one-time link — `quilzo auth enrol WHO` — so no
password is ever set. What the store keeps is public keys, and a copy of it lets
nobody sign in as anybody. A sign-in unlike the person's own (impossible travel,
a session copied to another device) gets no session until a passkey confirms it.

**OpenID Connect** against whatever your organisation already runs —
`quilzo oidc configure --issuer ... --client-id ...`, with PKCE, written from
scratch because there is no dependency to import it from. `quilzo oidc check`
talks to the provider and reports what it actually offers rather than what the
documentation claims.

**SAML**, for the providers that speak only that — `quilzo saml add NAME
--metadata F --url U`, with a preset for each common console (`quilzo saml
presets`). A response nobody signed is refused. Single sign-on can be required,
with named break-glass accounts.

**SCIM provisioning** from Okta, Entra and others — `quilzo scim token`, then
`quilzo scim map GROUP ROLE` for what each of their groups means here. It signs
nobody in; it decides who exists, and somebody deactivated there is suspended
here at once.

**API tokens**, shown once, each with a scope **narrower than the principal
holding it**. That is the part most systems get wrong: a token that inherits its
owner's authority is a copy of that person, and it lives in a CI variable
forever. Here a token is issued for a job and can do that job only.
`quilzo token stale` finds the ones nobody has used.

**Roles**, from reader to admin, scoped to a path, and a deny wins wherever it
sits.
`quilzo auth explain WHO ACTION` answers *why* somebody can or cannot do a thing,
which is the question that actually gets asked, and it answers it by evaluating
the real policy rather than by describing it.

Failed authentication is throttled with a soft lockout. The audit log has a
published commitment to every entry so far, so removing one is detectable rather
than merely forbidden.

### Reviewing who has access

Access granted to unblock somebody is never taken back by itself. So an
administrator reviews, every `access.review.every` (ninety days unless the
organisation declares `ac-02_odp.10`, between 30 and 365), the access only
Quilzo holds:

- every grant made by hand, a role in an app counted once;
- what each identity provider group means here, one item however many people
  are in it;
- every long-lived token.

Sessions end within a day, an agent's identity is renewed rather than
reviewed, a grant provisioning made is the identity provider's to review,
and the site's members hold nothing in the admin, so none of those is in
it. Access to other systems is reviewed in whatever reviews those.

```
quilzo access review start               the snapshot: one review open at a time
quilzo access review items               dormant first, then privileged
quilzo access review decide 3 revoke     applied at once
quilzo access review decide 4 keep --why "edits the handbook"
quilzo access review close
```

Or Review who has access on People, one card and two buttons per item; a
button returns to its card, with what it did or why it was refused. Each
item that is your own says so in both, and waits for another administrator.
With no review open, both say when the last one closed and when the next is
due.

Each item says how and when it was granted, by whom where the store recorded
it (a grant made by hand), until when, and when it was last used: a token's
last use, or the person's last record in the audit log, which is the one
lasting record once sessions are pruned. Only a record of the person doing
something counts, with their identity proved and the act not refused: a
command refused under their name, or a sign-in to their account held by the
lockout, is somebody trying. Nothing for ninety days is dormant, listed first
and proposed for revoke, the same threshold as the posture scan's
`token.stale`. Privileged means administration, the security, compliance or
log areas, or a permission only an administrator otherwise holds.

The rules are the ones that make a review one. The reviewer is a person,
signed in as themselves: a model, a program's token or a name nobody proved
is refused. On People that means signed in with two factors, even in the
grace before two factors are compulsory, since a token pasted into the
sign-in form is how a program would get in; a session with one factor is
told so in place of the buttons. Nobody decides their own access, however
their name is spelled, or a group they are in. Keeping privileged access
needs a reason (Why on People, `--why` on the command line), which is kept
in the review's file (`access/reviews/ID.json`) and never in the audit log,
where the record says only that one was given; a reason of more than one
word goes in quotes, and words left over after a decision are refused rather
than dropped. There is no "reduce": revoke, then grant the lower role.
Starting, listing, deciding and closing each take an administrator of the
whole store; a publisher or an auditor can do none of them.

A revoke goes through the path that granted the access, at once: the binding
is removed, the token revoked with every session minted from it, the
group's mapping taken off and its grants with it. What it gave is refused
from the next request: a revoked token's next request fails outright, and a
revoked grant leaves the person any other grant they hold, which is an item
of its own. A revoke that would leave nobody able to administer the store is
refused, whoever decided it and whenever.

Closing is refused while anything is undecided, and the refusal names which
of the undecided items are your own. An item whose grant was taken away some
other way since the start does not hold it open; it is counted as gone.
Closing reports grants made since the review started as not reviewed by it,
writes `review.closed` with the counts, and writes evidence for the built-in
quarterly control
`quilzo/AC-2 account review`, which `quilzo assurance report` measures like
any other: one review in a six-month window is unproven, two are covered.
With one administrator there is nobody else to decide their own access, so
the review closes alone, says how much of theirs went unreviewed, and
`approval.alone` counts it; not for a day after another administrator was
removed, when nothing is approved alone, and the refusal says until when. In the same way, a group every administrator is
in (the whole staff mapped to reader, say) is everybody's own and nobody's to
decide: it closes undecided, and `review.closed` counts it as `unreviewable`.

When no review has closed within the period, counted from the last close
or, before the first, from the oldest grant a review would cover (at once
for a grant made before grants were dated), the posture scan reports
`access.review-due`, and drift mails it to the security contact as a
reminder, though it is Medium.

The records are `review.started`, `review.keep`, `review.revoke` and
`review.closed`, beside the record the revoked path writes itself
(`auth.revoke`, `token.revoke`, `scim.unmapped`). A token is named in them as
a `credential`, and the person under `principal`, which the log
pseudonymises.

### When the identity provider says a session is over

A session made by single sign-on is Quilzo's own: the provider vouches once, and
the eight hours after that are local. So when the provider ends somebody's
session, sees their password stolen or disables their account, nothing reaches
the session already open here unless the provider can say so. Its security event
stream (OpenID Shared Signals: CAEP and RISC) is how it says so, and Quilzo
listens at `/sso/signals` on the admin:

```
export QUILZO_SIGNALS_SECRET=...      # the stream client's secret; never stored
quilzo signals connect --provider oidc --client-id quilzo-stream
quilzo signals status
```

The stream is bound to one way of signing in, `oidc` or `saml:NAME`, and the
provider's word reaches only the sessions that provider signed in. Connecting is
the whole opt-in: there is no rule to write, and every event only takes access
away, so one administrator connects it, with the authority to grant access.

The provider pushes to `/sso/signals` at the address its sign-in sends people
back to: the origin of the OIDC redirect URI, or the SAML provider's `--url`.
That address has to be https and one the provider can reach: connecting refuses
plain http and a private address written as a number. The `--issuer` is the
OIDC issuer unless given, and has to be given for SAML.

- **With `--client-id`**, for a provider that publishes a stream API, Quilzo
  asks it for the stream, gives it a push secret it never shows, and asks it to
  verify. The client secret is read from `QUILZO_SIGNALS_SECRET`.
- **With `--jwks URL`**, for a provider whose stream is made in its own console,
  Quilzo prints the push address, the audience, the authorization and the events
  to ask for. The authorization is shown once and kept only as a digest.

Give one or the other. The server reads `QUILZO_SIGNALS_SECRET` too, from its
own environment, to ask for the daily verification below; set it wherever
`quilzo serve` is started, or each day's request fails and the stream is
reported as silent.

| The provider says | Quilzo does |
|---|---|
| session-revoked, sessions-revoked; credential-change (update, revoke, delete) | ends that provider's sessions for them opened before the event was issued |
| credential-compromise, account-credential-change-required | the same; every other session they had open then must confirm it is them; the security contact is told |
| account-disabled, account-purged | suspends them as SCIM does: every token, every app they connected, and a deny over the whole site that passkeys and single sign-on refuse |
| account-enabled | lifts the deny it added, and no other |

What keeps that from being turned against the site:

- Every event is a token signed by the provider's published key, for this
  receiver, carrying one event Quilzo asked for. It is pushed with a bearer
  only the transmitter was given, and Quilzo keeps the bearer's digest.
- Who an event is about is read the way the provider names people at sign-in,
  and has to be somebody the access policy already knows. Anything else is
  counted as unmatched and nothing is done.
- The last person who can grant access is never suspended this way: their
  sessions end and the security contact is told.
- At most twenty people an hour are acted on. Past that the cap is recorded
  once an hour and the security contact is told; an event about anybody else
  is answered 503 with a `Retry-After` of when the hour is up, and is not
  remembered as seen, so the provider sends it again then and it is acted on,
  twenty people an hour. An offboarding larger than that finishes by itself
  while the provider keeps retrying; whoever is told can suspend anybody sooner
  by hand, from the provider's own log of whom it disabled.
- A session opened after an event was issued, give or take two minutes for
  the clocks, is one the provider vouched for since, and the event does not
  reach it; nor does a compromise hold again a session that has confirmed it
  is its person since. The same event sent again, after a restart has
  forgotten it was seen, ends and holds nothing new.
- An account-enabled older than the last event acted on for that person is
  refused, after a restart too, so a replay cannot lift a newer suspension. An
  account-disabled or account-purged older than the last account-enabled acted
  on, or no newer than the last one acted on, is refused the same way, so a
  late retry cannot suspend again somebody the provider has enabled since. Each
  is recorded as `signals.stale`.
- The shield's `signals` feature turns the endpoint off. It answers 503 with
  a time to come back, so a transmitter that retries sends the event again
  later.

Once a day the server asks the provider to verify the stream, and the posture
rule `signals.stream-silent` reports a stream that has not answered for a day: a
stream gone quiet looks the same as one with nothing to say. A stream made by
hand in the provider's console (`--jwks`) cannot be asked, and is reported for
that.

`quilzo signals status` and the Protection > Sign-ins screen say the same
things: whose sign-ins the stream speaks for, when it last answered a
verification and whether it has gone silent, why the last request failed if it
did, whether the provider says the stream is enabled, paused or disabled, the
last event, and how many events were received, acted on, unmatched and
refused, and how many deliveries past the hourly cap were told to wait.

`quilzo signals off` turns the stream off here at once, and anything pushed
after is refused. It asks the provider to delete the stream too, with the client
secret from `QUILZO_SIGNALS_SECRET`; when it cannot, or the stream was made in
the provider's console, it says so, and the stream is deleted there by hand.
Denies it added stay until the account is enabled or a person lifts them.

With the admin on loopback, publish only `/scim/v2/` and `/sso/signals` through
the proxy (`deploy/Caddyfile` has the block, commented out). Each act is in the
audit log as `signals.sessions-ended`, `signals.step-up`, `signals.suspended`,
`signals.restored`, `signals.verified`, `signals.stream-status`,
`signals.stale`, `signals.capped` and, at most once an hour, `signals.refused`. Connecting,
turning off and each day's request are `signals.connected`,
`signals.disconnected` and `signals.verify-asked`, and each message to the
security contact is `signals.told`.

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
the browser — and the admin's one script sends only what its own forms would.

### Seeing it, and showing it, before it is published

The preview beside the editor shows what is typed, a moment after typing
stops: rendered through the site's own layouts, as a reader would get it, and
saved nowhere. Without the script, "Show in the preview" does the same.
What is typed and not saved is kept for the tab, so a reload offers to put it
back. Showing unsaved words takes what saving takes: somebody who may only read
sees the saved draft.

A draft can be shown to somebody with no account — a client, a colleague
elsewhere — with a link: `quilzo share PAGE [--days 7]`, or "Make a link" in
the page's editor. The link is to that page as the draft was when it was
shared, not as it is later, so a link sent last week cannot show somebody what
was written since. Its address holds a random secret nobody can guess, shown
once, when the link is made: the store keeps only a digest of it, which is the
ID the link is listed and logged by, so a copy of the store or of a backup
opens nothing. It lives thirty days at the most, and ends at once with
`quilzo share revoke ID` or Revoke in the editor. The public site serves it at
`/shared/SECRET` with a note saying it is a draft and
headers asking that it not be indexed, stored, or referred onward; an ended link
is the site's own 404, the same as one that never was. Sharing takes what
publishing takes, since it shows the page outside; ending a link takes what
editing the page takes. Both are in the audit log.

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

No release is published yet: build from source, or build the container image
from this repository. Each release will publish signed binaries and an image;
[INSTALL](../INSTALL) says how to check them.

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

### With Docker

The image is `gcr.io/distroless/static-debian12:nonroot`: the binary, CA
certificates and a passwd entry. No shell, no package manager, no interpreter,
no libc. It runs as nonroot.

```bash
docker build -t quilzo .
docker run --rm -v quilzo:/srv quilzo --root /srv/store init
docker run --rm -v quilzo:/srv quilzo --root /srv/store demo
docker run -p 8081:8081 -v quilzo:/srv \
  quilzo --root /srv/store site --addr 0.0.0.0:8081
```

Then <http://127.0.0.1:8081>. `demo` publishes, so there is nothing else to run.

**One volume, mounted at `/srv` rather than at the store.** `quilzo demo` writes
templates beside the working directory rather than into the store, so a
deployment that keeps only `/srv/store` loses them and `site` exits with `no
template directory at templates`. Both live under `/srv`, so that is what is
kept.

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
quilzo site new "what the site is for" --name "Its name" --install   # a whole site to fill in
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
`make install prefix=...`, `make dist` — described in [INSTALL](../INSTALL). There
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
docker volume create quilzo-store
docker run --rm -p 8081:8081 -v quilzo-store:/srv/store quilzo \
  site --addr 0.0.0.0:8081 --base-url https://example.org
```

The image's store is `/srv/store`, named in its entrypoint, so mount the
store's volume there; the image runs as uid 65532, which a named volume
suits and a host folder must be made writable for. `deploy/README.md` has
the whole stack with Docker Compose: the admin over HTTPS, the site behind
Caddy, and a log writer of its own.

Behind a reverse proxy every connection is the proxy's, so name it in
`network.trusted_proxies` by its own address — the proxy, a cluster's ingress
or load balancers, or a CDN's published ranges — and the address it forwards
in X-Forwarded-For is the visitor's for every limit, the audit log and the
shield. A range believes every machine in it, so name the smallest that holds
only proxies. `site.trusted_proxy` and `admin.trusted_proxy` believe a proxy
on this machine without naming it, and only there: loopback, 127.0.0.0/8 and
::1. The shield counts what such a proxy forwards but does not block on it
alone. A proxy on a private network, a container bridge or carrier-grade NAT
is believed only when it is named, because anything else on that network can
write X-Forwarded-For as well as the proxy can. Each surface says at start,
with the rest of what it prints, when it believes a proxy on this machine.
With either setting on and no proxy named, the first time a machine on the
network forwards an address that is not believed, the site or the admin says
on standard error which machine it was and the command that names it.

The list is the site's and the admin's both, and naming any proxy in it ends
the assumption for both: a proxy on this machine, in front of either, is then
believed only if it is named too. Naming 127.0.0.1 lets any program on this
machine choose its address on the admin as well as the site, so for Caddy on
this machine in front of the site, turn on `site.trusted_proxy` and name
nothing.

Being named is being believed about somebody else, and nothing more: a
request a proxy sends without X-Forwarded-For is the proxy's, and is counted,
limited and blocked like anybody's. The shield never blocks this machine
itself, or a network added with `quilzo shield trust add`; a machine on a
private network is blocked like any other. A load balancer that does not say
who it carries makes every visitor its address, so add it with
`quilzo shield trust add`, or a block on one visitor is a block on all of
them. The same holds for a container's published port: Docker's own proxy
hands the container a connection from this machine as one from the bridge
gateway, such as 172.17.0.1, so a browser on the host is that address and can
be blocked like any other. `quilzo shield lift ID`, on this machine, ends any
block.

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
  That is the real state of it, and [GOVERNANCE.md](../GOVERNANCE.md) says exactly
  what it takes to change it.

---

## Licence

[Apache License 2.0](../LICENSE). See [NOTICE](../NOTICE) for the third-party
material it carries.

## Contributing

This project wants maintainers, not only patches. Three merged pull requests of
substance and you can have commit access — the bar is written down in
[GOVERNANCE.md](../GOVERNANCE.md) so that nobody has to guess when they qualify.

[CONTRIBUTING.md](../CONTRIBUTING.md) has the two-minute path from clone to running
site, the one rule that will surprise you (no dependencies), and how review
works here. Security reports go through [SECURITY.md](../SECURITY.md), privately.

Contributions are taken under a [DCO](https://developercertificate.org/) —
`git commit -s` — and copyright stays with whoever wrote the code.
[CONTRIBUTING.md](../CONTRIBUTING.md) says what that does and does not guarantee,
stated more carefully than it used to be.
