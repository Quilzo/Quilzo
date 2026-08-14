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

## Status

Working today: the content store, draft/publish/rollback, diff, history, the
template engine, and `verify`. Tests cover every SSTI payload I could find, XSS
in all three escaping contexts, termination limits, tamper detection, and path
traversal through ids that become filenames.

Runs in the container as a non-root user (65532) and works against a read-only
mount, so a rendering deployment never needs write access to the store.

Not built yet: the AI assistant, an admin UI, an HTTP server, media handling,
scheduled publishing, or multi-site. The CLI is the whole product right now.

The assistant is the next piece and the reason for this architecture. An agent
proposing a change writes a commit nobody is serving; reviewing it is a diff, and
rejecting it costs a pointer that never moved. Publishing — the one action with
an outside observer — is the thing worth gating, which is what
[recoup](https://github.com/rsh1k/recoup) is for.

## Licence

Proprietary. All rights reserved — see [LICENSE](LICENSE). No licence is granted
by access to this repository.
