# Dismissed code-scanning alerts, and why

A dismissed alert is a security decision with no diff. Nothing in the code
changes, the alert stops appearing, and six months later the only record is a
280-character field in a web UI that nobody reviewing this repository will
think to open. So the reasoning lives here, in the tree, where it is versioned
alongside the code it is about and where being wrong about it is findable.

One entry per dismissal. Each states the rule, the flow, why the rule's claim
does not hold, and what would have to change for the dismissal to stop being
correct — because that last part is the one that decides whether this file is
worth keeping.

---

## `go/reflected-xss` — alerts #32, #33, #34, #40

**Dismissed** September 2026 as *false positive*.

| alert | sink |
|---|---|
| #32 | `internal/admin/server.go` — `w.Write` of rendered admin page |
| #33 | `internal/public/detail.go` — `w.Write` of rendered detail route |
| #34 | `internal/public/public.go` — `w.Write` of rendered page |
| #40 | `internal/public/searchpage.go` — `w.Write` of rendered search page |

### The flow, from the SARIF rather than from a guess

All four share a single source: `r.FormValue("proposal")` at
`internal/admin/assist.go:178`. The 40-odd step path runs
`assist.ParseProposal` → `Proposal.Templates` → `tmpl.Parse` → literal text
nodes → `tmpl.Render` → `w.Write`.

The step that matters is which half of the template it reaches. **It does not
reach the data.** `internal/tmpl` escapes interpolated values with
`html.EscapeString`, and `escapeURL` replaces a scheme that can execute with
`#unsafe-url` rather than emitting it. It reaches the **template source**, and
comes out as literal text, which a template engine emits verbatim because
literal text in a template is markup.

So CodeQL traced something real. Reading it is what found the gap that
[#90](https://github.com/Quilzo/Quilzo/pull/90) closed. The dismissal is about
the rule's conclusion, not its dataflow.

### Why the rule's claim does not hold

**It is not reflected.** The value is written to templates in the store and
rendered on later requests. Nothing is echoed into the response of the request
that carried it. `go/reflected-xss` is the wrong rule for a stored flow, and
the stored version of the question is answered below.

**No privilege boundary is crossed.** The route is gated on
`auth.ActEditDraft`. That is the same action gating the direct template editor
— `internal/admin/design.go:77` and `internal/admin/nav.go:77`, where the
Design screen is declared with `auth.ActEditDraft`. `internal/auth` defines six
actions (`view`, `edit-draft`, `publish`, `rollback`, `grant`,
`manage-tokens`) and none is template-specific, so template authoring is
`edit-draft` everywhere. Any principal who can reach `/assist` can already
hand-write the same HTML in the template editor. An editor emitting markup they
chose is the feature, not the finding.

**Model-proposed source cannot carry executable markup.** `assist.Validate`
refuses `{% raw %}` escaping opt-outs, and since #90 also refuses `<script>`
elements, script references, inline event handlers and `javascript:`,
`vbscript:` and `data:` URLs. It uses `foreign.ExecutableMarkup`, which reads
the same patterns `internal/foreign` strips from an adopted template, with a
test asserting the detector and the stripper agree in both directions.

**Public responses carry `script-src 'none'`.** Asserted by tests in
`internal/csp` and `internal/public`. Listed last deliberately: it is the
second line, and a dismissal that leaned on it would be arguing the browser
declines to run script this program emitted, which is a weaker claim than not
emitting it.

### What would make this dismissal wrong

Written down because a dismissal with no expiry condition is a decision nobody
can revisit.

- **A template-authoring privilege separate from `edit-draft`.** If a role is
  ever able to edit drafts but not templates, the assist route stops matching
  the template editor and becomes an escalation. Adding an action to
  `internal/auth` is the signal to re-read this.
- **`assist.Validate` losing the executable-markup refusal**, or
  `foreign.ExecutableMarkup` drifting from the strippers. The agreement test in
  `internal/foreign/executable_test.go` is what holds this, and deleting it is
  the event to watch for rather than the check itself changing.
- **A route rendering a template from a source that is not gated on
  `edit-draft`** — anything accepting template markup from an unauthenticated
  request, or from content rather than from an editor.

### The thing this dismissal also fixed, which is not a reason for it

These four alerts froze `internal/public/public.go`,
`internal/public/detail.go`, `internal/public/searchpage.go` and
`internal/admin/server.go`. CodeQL reports pre-existing alerts in *changed*
code as new, and `CodeQL` is a required check on `main`, so any edit to those
four files failed it — which is how
[#89](https://github.com/Quilzo/Quilzo/pull/89) came to be merged with
`--admin` after the SPDX header pass moved every line in the repository by
three.

That is a reason to resolve these alerts honestly. It is not a reason to call
them false, and it is recorded here in that order so nobody later reads the
convenience as the motive.

---

## `go/cookie-secure-not-set` — alerts #42–#50

**Dismissed** September 2026 as *won't fix*.

Nine alerts, one per place this program sets a cookie:
`internal/admin/oidcauth.go`, `nav.go` (two), `passkeys.go`, `sidebar.go`,
`start.go`, `server.go` (two), `theme.go`.

### What the rule wants

*"Cookie 'Secure' attribute is not set to true."* It wants the literal `true`.
Every one of these sets it conditionally:

```go
Secure: r.TLS != nil || s.behindTLSProxy(),
```

So the rule is correct on its own terms — the attribute is not set to `true`,
it is set to an expression that is sometimes false — and it is unsatisfiable
here without changing behaviour for the worse.

### Why it is not being fixed

**A Secure cookie over plain HTTP is dropped by the browser.** The admin binds
to loopback by default, deliberately; the comment on the sign-in cookie has
said the consequence for as long as the cookie has existed:

> or the cookie is refused on a loopback deployment and nobody can sign in at
> all — which is how a security attribute gets removed permanently by whoever
> is trying to get their work done.

Setting `Secure: true` unconditionally would make `quilzo serve` unable to sign
anybody in on its default configuration. The realistic outcome of that is not a
more secure deployment; it is an operator deleting the attribute.

**The condition is the control, not the absence of one.** `Secure` is set
whenever the connection is TLS, and whenever the deployment declares that TLS
is terminated in front of it (`admin.behind_tls_proxy`). What is left
uncovered is plain HTTP with no such declaration, which is loopback — where
there is no network path for the cookie to leak over.

**The rest of the hardening does not depend on this.** These cookies are
`HttpOnly` and `SameSite=Strict`, the site serves `script-src 'none'`, and the
session cookie is refused from a query parameter so it never reaches a log or
a referrer.

### An attempt that did not work, recorded because it did not

These first appeared when the eight call sites moved from
`Secure: r.TLS != nil` to `Secure: s.secureCookie(r)`, so the initial reading
was that the analysis had lost track of a method call. #108 put the comparison
back at each call site for that reason. **It did not close the alerts** — the
analysis had never been following the comparison; it wants a constant.

That change is kept, because a security decision written where it is made is
easier to review than one behind a call, but it should not be described as
having fixed anything.

### What would make this dismissal wrong

- **The admin defaulting to a non-loopback address.** The whole argument rests
  on the uncovered case being loopback. If `serve` ever binds more widely by
  default, `Secure` needs to be unconditional and sign-in needs another way to
  work.
- **`admin.behind_tls_proxy` being removed**, or defaulting to something other
  than off, which would change what the uncovered case is.
- **`SameSite=Strict` or `HttpOnly` going away** from any of these nine. They
  are what makes a medium finding a medium finding rather than a high one.
