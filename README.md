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
come out of a plain dictionary and the only operations are lookup, truthiness
and iteration. Every classic sandbox escape is refused at parse time:

```
{{ page.__class__.__mro__ }}
  → 'page.__class__.__mro__' is not a value path. Names and dots only —
    there are no calls, operators or attributes in this language.
```

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

## Verify the store

```
$ scrivet verify
  7 object(s) intact
  every object re-hashed to the id it is filed under
```

A conventional CMS can't answer "has anything in here been altered outside the
application". Tampering with an object on disk is detected on the next read and
by `verify`, because the id *is* the hash of the content.

## Status

Working today: the content store, draft/publish/rollback, diff, history, the
template engine, and `verify`. 40 tests, including every SSTI payload I could
find, XSS in all three escaping contexts, termination limits, tamper detection
and path traversal.

Not built yet: the AI assistant, an admin UI, an HTTP server, media handling,
scheduled publishing, or multi-site. The CLI is the whole product right now.

The assistant is the next piece and the reason for this architecture. An agent
proposing a change writes a commit nobody is serving; reviewing it is a diff, and
rejecting it costs a pointer that never moved. Publishing — the one action with
an outside observer — is the thing worth gating, which is what
[recoup](https://github.com/rsh1k/recoup) is for.

Apache-2.0.
