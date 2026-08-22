# Quilzo — publishing a page from a chat, with nothing that can execute

A Mini App that turns a form in a Telegram chat into a published web page, and
refuses to publish one that a reader could not use.

The interesting part is not the form. It is what the page passes through on its
way out, and what it structurally cannot contain when it gets there.

## Try it

```
quilzo init
quilzo template use sections
quilzo add index=templates/sections.json -m "first page"
quilzo publish

export QUILZO_TELEGRAM_TOKEN=<your bot token>
quilzo telegram check                      # confirms the token, names the bot
quilzo telegram serve --site-url https://your.site
quilzo site --addr 127.0.0.1:8081          # where published pages are read
```

Telegram only opens a Mini App over https, so put a tunnel or a reverse proxy in
front of `:8082` and give @BotFather that address.

To open the surface without registering a bot at all:

```
quilzo telegram link 279058397 --app-url http://127.0.0.1:8082/
```

That mints the same credential the bot would send. It works once.

## What it does

A person taps a button in a chat and gets a form: a title, a line, some
paragraphs, a choice of design. Submitting it writes a page into a
content-addressed store, runs every gate the rest of the system runs, and moves
one pointer. The page is then at `/tg<their-id>`, served by an ordinary static
site.

If a gate refuses, the person sees the gate's own words — which check said no
and why — rather than "could not publish".

## Why it is built this way

**No script, on the surface where a stranger composes content.** The Mini App
serves `script-src 'none'`. Telegram delivers launch parameters in the URL
fragment, which a browser never sends to a server, so reading `initData`
server-side normally means JavaScript on the page lifting it out and posting it
back. Instead the bot mints a signed, single-use, expiring credential in the
query string, which the server does see. Same HMAC-SHA256 keyed on the bot
token, plus a replay defence the fragment approach does not have.

`initData` is implemented in full as well, at `POST /launch`, for anyone running
this with Telegram's SDK. Three details there are easy to get wrong and are
tested against an independently written signer: the bot token is the *message*
in the first HMAC and not the key; `signature` must be excluded from the check
string or every launch from a newer client fails; and the comparison is
constant-time.

**A page cannot carry an element the author did not intend.** The template
language has four constructs — a value, `if`, `for`, `raw` — and no way to add a
fifth. No calls, no arithmetic, no field access, no method invocation. Values are
escaped for the context they land in, so a URL-bearing attribute is escaped as a
URL and `javascript:` is replaced rather than emitted and hoped about. There is
no HTML field in the form, deliberately: the answer to "what if they paste a
script tag" is structural rather than a filter somebody has to maintain.

**Every page is checked before it is served, and refused rather than warned.**
Eleven checks: images have alternative text, heading levels do not skip, link
text means something out of context, form inputs have labels, no autoplay, and
colour contrast computed over the generated stylesheet in both schemes. A
warning nobody reads is a feature nobody has.

**Machine-generated content is marked, and the mark cannot be quietly stripped.**
The EU AI Act's Article 50 transparency obligations took effect on 2 August 2026
and require generated output to carry a machine-readable mark. The marking uses
C2PA's `digitalSourceType` from the IPTC vocabulary — what OpenAI, Google, Meta
and Amazon already emit — rather than a private scheme. C2PA embeds a signed
manifest in the asset, and stripping it is silent; here the record names the
content hash, so removal is *detectable*: the page resolves to a hash with no
provenance, which reports as a gap rather than as human authorship.

**Takedown is a pointer move.** Content is addressed by the SHA-256 of its own
bytes. There is no UPDATE and no DELETE; publishing sets one ref, and withdrawing
sets it back. Every previous version stays addressable, so a takedown is evidence
rather than a deletion nobody can reconstruct.

**No dependencies.** `go.mod` has no `require` block. One static binary. The
container is `distroless/static-debian12:nonroot` — no shell, no package
manager, no libc.

## What is in `src`

| Path | What it is |
| --- | --- |
| `internal/telegram` | This submission: `initData` verification, signed single-use links, form grants, the Mini App surface, a minimal Bot API client |
| `internal/tmpl` | The template language that cannot execute |
| `internal/provenance` | Article 50 marking, bound to the content hash |
| `internal/a11y` | The checks that block a publish |
| `internal/theme` | Design tokens, and the contrast computation over them |
| `internal/csp` | A policy built from what the content references |
| `internal/store` | Content-addressed objects, trees, commits, refs |
| `cmd/quilzo` | 60 commands, including `telegram serve` |

## Tests

```
go test ./...
```

66 packages. The ones most worth reading for this submission:

- `internal/telegram` — every way a launch can be forged, stale or replayed,
  verified against an independently written signer rather than against itself.
  Includes the case where a bad signature must not burn somebody else's link,
  which is a question of check ordering rather than of cryptography.
- `internal/starter` — every shipped design passes the contrast gate in both
  colour schemes, every section kind is exercised by sample content, and the
  layouts pass the scanner this project ships.
- `cmd/quilzo` — a suite that walks its own source: every command declares a
  privilege, every write surface consults the type gate, every capability
  exists in all three interfaces or carries a written reason.

## Known limits

- The single-use record is in memory, which is correct for one process and wrong
  for two. `Spender` is an interface for that reason and the type is called
  `Memory` rather than something that sounds like a default.
- A person publishes one page per Telegram account. Multiple pages per account
  is a naming question, not a technical one, and guessing at it before anybody
  has asked seemed worse than leaving it.
- Telegram's theme parameters are not read, because reading them needs the SDK
  and the SDK needs script. The page follows the reader's light or dark
  preference instead, which is close and costs nothing.

Apache-2.0.
