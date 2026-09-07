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
