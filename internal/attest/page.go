// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"html/template"
	"time"
)

// Head is one signed head of the organisation's record, as the page shows
// it: how many entries it commits to, their root, when it was signed and by
// which key. The public instance checks the signatures before it serves a
// head (internal/outpost); the page shows what was checked.
type Head struct {
	Size  int
	Root  string
	At    time.Time
	KeyID string
}

// row is one attestation as the page shows it.
type row struct {
	Attestation
	Period, IssuedOn string
	InForce          bool
}

type pageData struct {
	Organisation string
	Contact      string
	Rows         []row
	Policies     []policyRow
	Head         *Head
	Heads        int
	Published    string
	Empty        bool
}

type policyRow struct {
	Policy
	ApprovedOn string
}

// longDate is a date as the page says it: 14 February 2027.
func longDate(d string) string {
	t, err := time.Parse(time.DateOnly, d)
	if err != nil {
		return d
	}
	return t.Format("2 January 2006")
}

// Page is the public attestation page for a file and the heads published
// with it, its status words worked out at now. A nil file is an instance
// that has been sent nothing yet, and says so.
//
// Every value is the file's or a head's, escaped by html/template; the
// page's own words are fixed here and never say "compliant" or "certified".
func Page(f *File, heads []Head, now time.Time) ([]byte, error) {
	d := pageData{Empty: f == nil}
	if f != nil {
		d.Organisation, d.Contact = f.Organisation, f.Contact
		for _, a := range f.Attestations {
			d.Rows = append(d.Rows, row{Attestation: a,
				Period:   longDate(a.PeriodStart) + " to " + longDate(a.PeriodEnd),
				IssuedOn: longDate(a.Issued), InForce: a.Current(now)})
		}
		for _, p := range f.Policies {
			d.Policies = append(d.Policies, policyRow{Policy: p, ApprovedOn: longDate(p.Approved)})
		}
	}
	if n := len(heads); n > 0 {
		h := heads[n-1]
		d.Head, d.Heads = &h, n
		d.Published = h.At.UTC().Format("2 January 2006 at 15:04 UTC")
	}
	var b bytes.Buffer
	if err := pageTemplate.Execute(&b, d); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .Empty}}Security attestations{{else}}{{.Organisation}}: security attestations{{end}}</title>
<link rel="stylesheet" href="/public.css">
</head>
<body>
<a class="skip" href="#main">Skip to the attestations</a>
{{if not .Empty}}<header><p class="org">{{.Organisation}}</p></header>{{end}}
<main id="main">
<h1>Security attestations</h1>
{{if .Empty}}
<p>Nothing has been published here yet.</p>
{{else}}
<p class="lead">The reports and certificates {{.Organisation}} holds, the periods they cover, who issued
  them, and the policies in force. This page lists what independent parties put their names to, and
  shows no operational figures.</p>

<h2 id="held">Reports and certificates held</h2>
{{if .Rows}}
<div class="table-wrap" role="region" aria-labelledby="held" tabindex="0">
<table>
  <caption>Reports and certificates held by {{.Organisation}}</caption>
  <thead><tr><th scope="col">What is held</th><th scope="col">Against</th><th scope="col">Period</th>
    <th scope="col">Issued by</th><th scope="col">Issued</th><th scope="col">Status</th><th scope="col">How to obtain it</th></tr></thead>
  <tbody>
  {{range .Rows}}
  <tr>
    <th scope="row">{{.Title}}{{with .Scope}}<span class="note">{{.}}</span>{{end}}</th>
    <td>{{.Framework}}</td>
    <td>{{.Period}}</td>
    <td>{{.Issuer}}</td>
    <td>{{.IssuedOn}}</td>
    <td>{{if .InForce}}<span class="state in-force"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M6.4 11.2 3 7.8l1.1-1.1 2.3 2.3 5.5-5.5L13 4.6z"/></svg>In force</span>{{else}}<span class="state expired"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M4.1 3 3 4.1 6.9 8 3 11.9 4.1 13 8 9.1l3.9 3.9 1.1-1.1L9.1 8 13 4.1 11.9 3 8 6.9z"/></svg>Expired</span>{{end}}</td>
    <td>{{if .Available}}{{.Available}}{{else}}Ask, as below{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
</div>
{{else}}
<p>None is listed.</p>
{{end}}

<h2 id="policies">Policies in force</h2>
{{if .Policies}}
<div class="table-wrap" role="region" aria-labelledby="policies" tabindex="0">
<table>
  <caption>Policies {{.Organisation}} has approved</caption>
  <thead><tr><th scope="col">Policy</th><th scope="col">Version</th><th scope="col">Approved</th></tr></thead>
  <tbody>
  {{range .Policies}}<tr><th scope="row">{{.Title}}</th><td>{{.Version}}</td><td>{{.ApprovedOn}}</td></tr>
  {{end}}
  </tbody>
</table>
</div>
{{else}}
<p>None is listed.</p>
{{end}}

{{if .Contact}}
<h2 id="ask">Asking for a report</h2>
<p>{{.Contact}}</p>
{{end}}
{{end}}

<h2 id="record">The signed record</h2>
{{if .Head}}
<p>The decisions and changes in this organisation's security record are written to an append-only
  log, and each head of the log is signed. The newest head published here:</p>
<dl class="head">
  <dt>Entries it commits to</dt><dd>{{.Head.Size}}</dd>
  <dt>Root</dt><dd><code>{{.Head.Root}}</code></dd>
  <dt>Signed</dt><dd>{{.Published}}</dd>
  <dt>Key</dt><dd><code>{{.Head.KeyID}}</code></dd>
</dl>
<p>Every head published so far is in <a href="/heads.json">the head feed</a>. A head somebody outside the
  organisation keeps fixes the record up to it: an entry changed afterwards no longer matches the root.</p>
{{else}}
<p>No head of the record has been published here yet.</p>
{{end}}
</main>
<footer>
  <p>This page is served by a public instance that holds only what was sent to it, signed, and nothing
    else. <a href="/.well-known/security.txt">How to report a vulnerability</a>.</p>
</footer>
</body>
</html>
`))

// Stylesheet is the page's, served at /public.css: light and dark from the
// reader's setting, forced colours left to the system, no motion, focus
// always visible, and a layout that reflows to 320 pixels with the tables
// scrolling inside their own region rather than the page sideways.
var Stylesheet = []byte(`:root {
  color-scheme: light dark;
  --bg: #ffffff; --fg: #1b1c1f; --muted: #44474e; --line: #c4c6d0; --link: #0842a0;
  --ok-bg: #d7f5df; --ok-fg: #0b3d1a; --old-bg: #ece6e2; --old-fg: #3b2f29; --focus: #0842a0;
}
@media (prefers-color-scheme: dark) {
  :root { --bg: #111318; --fg: #e3e2e6; --muted: #c4c6d0; --line: #44474e; --link: #aac7ff;
    --ok-bg: #0f3d1f; --ok-fg: #c6f0d2; --old-bg: #3b2f29; --old-fg: #f1e1d9; --focus: #aac7ff; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 1rem/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
header, main, footer { max-width: 64rem; margin: 0 auto; padding: 0 1rem; }
header .org { font-weight: 600; margin: 1rem 0 0; }
h1 { font-size: 2rem; line-height: 1.2; margin: 1.5rem 0 1rem; }
h2 { font-size: 1.35rem; margin: 2rem 0 .75rem; }
.lead { font-size: 1.1rem; max-width: 46rem; }
a { color: var(--link); text-underline-offset: .15em; }
a:focus-visible, .table-wrap:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
.skip { position: absolute; left: -999px; top: 0; padding: .5rem 1rem; background: var(--bg); }
.skip:focus { left: 1rem; }
.table-wrap { overflow-x: auto; max-width: 100%; }
table { border-collapse: collapse; width: 100%; min-width: 36rem; }
caption { text-align: left; font-weight: 600; padding: .25rem 0 .5rem; }
th, td { text-align: left; vertical-align: top; padding: .5rem .75rem; border-bottom: 1px solid var(--line); }
thead th { border-bottom-width: 2px; }
.note { display: block; font-weight: 400; color: var(--muted); font-size: .9rem; }
.state { display: inline-flex; align-items: center; gap: .3rem; padding: .1rem .5rem; border-radius: .4rem;
  min-height: 24px; white-space: nowrap; }
.state .icon { width: 1rem; height: 1rem; fill: currentColor; }
.in-force { background: var(--ok-bg); color: var(--ok-fg); }
.expired { background: var(--old-bg); color: var(--old-fg); }
dl.head { display: grid; grid-template-columns: max-content 1fr; gap: .25rem 1rem; }
dl.head dt { font-weight: 600; }
dl.head dd { margin: 0; }
code { font-family: ui-monospace, "SFMono-Regular", Menlo, monospace; overflow-wrap: anywhere; }
footer { margin-top: 3rem; padding-bottom: 2rem; color: var(--muted); border-top: 1px solid var(--line); }
@media (max-width: 30rem) { dl.head { grid-template-columns: 1fr; } h1 { font-size: 1.6rem; } }
@media (forced-colors: active) {
  .state { border: 1px solid CanvasText; }
  a:focus-visible, .table-wrap:focus-visible { outline-color: Highlight; }
}
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; scroll-behavior: auto !important; } }
`)
