// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/seckit"
)

// The security kit's parts, each rendered alone and on one page, run
// through the accessibility checks and held to the rules the checks cannot
// read from markup alone: a caption and header scopes on every table, a
// word and an icon with its own text alternative on every status, the
// provenance of every figure behind a control a keyboard opens and not a
// hover, the hash beside the button of an approval, and no script.

var kitNow = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

const kitHash = "sha256:abababababababababababababababababababababababababababababababab"

func kitFigure(t *testing.T) seckit.Figure {
	t.Helper()
	f, err := seckit.New(seckit.FigureOf{N: 412, Of: 500, Unit: "accounts with a second factor",
		Sources: []seckit.Source{{Name: "Entra ID", Href: "/register/record/0123456789abcdef0123456789abcdef"}},
		At:      kitNow.Add(-50 * time.Hour), Hash: kitHash, Grade: register.GradeConnector, Now: kitNow, Window: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// kitParts is each part with a value for it, as a screen would pass it.
func kitParts(t *testing.T) map[string]any {
	t.Helper()
	f := kitFigure(t)
	table, err := seckit.NewTable("Coverage by domain", []string{"Domain", "Accounts", "Status", "Last run", "Commit"},
		[]seckit.Row{{Head: seckit.LinkCell("/register/kind/control", "Identity"), Cells: []seckit.Cell{
			seckit.FigureCell(f), seckit.BadgeCell(seckit.Failing), seckit.TimeCell(kitNow), seckit.HashCell(kitHash)}},
			{Head: seckit.TextCell("Endpoints"), Cells: []seckit.Cell{
				{}, seckit.BadgeCell(seckit.NoEvidence), {}, {}}}})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"kit-header": seckit.Header{Title: "Posture of record", Lead: "Within the declared scope: what is known, and how fresh."},
		"kit-tiles": []seckit.Tile{{Label: "Identity", Figure: f, Status: seckit.Stale, Href: "/register"},
			{Label: "Endpoints", Status: seckit.NoEvidence}},
		"kit-table": table,
		"kit-evidence": []seckit.Evidence{{Title: "Weekly MFA test", Status: seckit.Passing, At: kitNow,
			Grade: register.GradeConnector, Hash: kitHash, Source: seckit.Source{Name: "Entra ID"}, Href: "/register"}},
		"kit-badge": seckit.Alone,
		"kit-approval": seckit.Approval{What: "Accept the risk R-12", Hash: kitHash,
			Who: "Anybody who may accept risks, other than the person who raised it", Needed: 1, Of: 1, Alone: true,
			Action: "/register/approve", Fields: []seckit.Field{{Name: "id", Value: "r12"}}, Button: "Approve the risk"},
		"kit-timeline": []seckit.Event{{At: kitNow, What: "Exception granted", By: "d000…0001", Status: seckit.Waiting, Hash: kitHash},
			{At: kitNow.Add(time.Hour), What: "Exception lapsed", Status: seckit.Lapsed}},
		"kit-empty": seckit.Empty{Title: "No controls yet", Body: "A control is something the organisation does to meet a requirement.",
			Href: "/register", Action: "What the register holds"},
		"kit-errors": []seckit.Problem{{Field: "owner", Label: "Owner", Message: "Say who answers for it"},
			{Field: "ref", Label: "Reference", Message: "A reference is one line"}},
		"kit-live": "Saved. The register stands at abababababab.",
	}
}

// kitPage is one part on a page of its own, as the accessibility checks
// read a page.
func kitPage(t *testing.T, srv *Server, name string, v any) string {
	t.Helper()
	var b bytes.Buffer
	if err := srv.tpl.ExecuteTemplate(&b, name, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	h1 := "<h1>The part</h1>"
	if name == "kit-header" {
		h1 = ""
	}
	return `<!doctype html><html lang="en"><head><title>Kit</title></head><body><main id="main">` + h1 +
		b.String() + `<form><label for="owner">Owner</label><input id="owner" aria-describedby="owner-error">` +
		`<label for="ref">Reference</label><input id="ref"></form></main></body></html>`
}

func TestEverySecurityKitPartIsAccessible(t *testing.T) {
	srv, _ := setup(t)
	parts := kitParts(t)
	var all strings.Builder
	defined := regexp.MustCompile(`\{\{define "(kit-[a-z-]+)"\}\}`).FindAllStringSubmatch(kitSource(t), -1)
	if len(defined) < 12 {
		t.Fatalf("only %d parts are defined; the kit is assets/seckit.html", len(defined))
	}
	for _, d := range defined {
		name := d[1]
		v, ok := parts[name]
		if !ok {
			// A part used by the others, rendered with them.
			continue
		}
		page := kitPage(t, srv, name, v)
		all.WriteString(page)
		for _, f := range a11y.Check(name, page).Findings {
			if f.Severity == a11y.Blocking {
				t.Errorf("%s: %s (%s): %s", name, f.Rule, f.Criterion, f.Detail)
			}
		}
		if strings.Count(page, "<h1") != 1 {
			t.Errorf("%s puts %d h1 on the page; a page has one", name, strings.Count(page, "<h1"))
		}
	}
	html := all.String()
	for _, rule := range []struct {
		what string
		ok   bool
	}{
		{"no script", !strings.Contains(html, "<script")},
		{"no style attribute", !strings.Contains(html, "style=")},
		{"a caption on the table", strings.Contains(html, "<caption>Coverage by domain</caption>")},
		{"every column heading scoped", strings.Count(html, `<th scope="col">`) == 5},
		{"every row heading scoped", strings.Count(html, `<th scope="row">`) == 2 && strings.Count(html, "<th>") == 0},
		{"the figure as n of N", strings.Contains(html, `<span class="kit-n">412</span> of <span class="kit-of">500</span>`)},
		{"its provenance behind a disclosure", strings.Contains(html, `<details class="kit-prov">`) &&
			strings.Contains(html, "Entra ID") && strings.Contains(html, kitHash) &&
			strings.Contains(html, `<time datetime="2026-11-22T08:00:00Z">22 Nov 2026, 08:00 UTC</time>`)},
		{"stale facts said in words", strings.Contains(html, "2 days old") && strings.Contains(html, ">Stale<")},
		{"each status a word", strings.Contains(html, `<span class="kit-badge-word">Failing</span>`)},
		{"each status's icon with its own text alternative", strings.Contains(html, `role="img" aria-label="Problem"`)},
		{"the approval's hash beside its button", regexp.MustCompile(`(?s)<button type="submit"[^>]*>Approve the risk</button>.{0,200}abababababab`).MatchString(html)},
		{"the whole hash of what is approved", strings.Contains(html, `<code class="kit-hash">`+kitHash+`</code>`)},
		{"an approval made alone said so", strings.Contains(html, "only person eligible")},
		{"who may approve", strings.Contains(html, "other than the person who raised it")},
		{"the error summary as an alert that links to each field", strings.Contains(html, `role="alert"`) &&
			strings.Contains(html, `href="#owner"`) && strings.Contains(html, "There are 2 problems")},
		{"an update announced", strings.Contains(html, `role="status"`)},
		{"no score", !regexp.MustCompile(`(?i)score|\d%`).MatchString(html)},
	} {
		if !rule.ok {
			t.Errorf("the kit has %s and does not", rule.what)
		}
	}
	// The error beside its field, named in words and tied to it.
	var b bytes.Buffer
	if err := srv.tpl.ExecuteTemplate(&b, "kit-field-error", seckit.Problem{Field: "owner", Label: "Owner", Message: "Say who answers for it"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `id="owner-error"`) || !strings.Contains(b.String(), "Say who answers for it") ||
		!strings.Contains(b.String(), `aria-label="Error"`) {
		t.Errorf("the error beside a field is %s", b.String())
	}
}

// An approval request that cannot be shown whole, without the hash of what
// is approved or without who may approve, offers no button: the hash beside
// the button is what the person's authentication is bound to, and a button
// beside nothing approves something they were not shown.
func TestAnApprovalRequestWithoutItsHashOffersNoButton(t *testing.T) {
	srv, _ := setup(t)
	whole := kitParts(t)["kit-approval"].(seckit.Approval)
	for what, change := range map[string]func(*seckit.Approval){
		"no hash":          func(a *seckit.Approval) { a.Hash = "" },
		"nobody who may":   func(a *seckit.Approval) { a.Who = "" },
		"nothing to say":   func(a *seckit.Approval) { a.What = "" },
		"no number needed": func(a *seckit.Approval) { a.Needed = 0 },
	} {
		a := whole
		change(&a)
		var b bytes.Buffer
		if err := srv.tpl.ExecuteTemplate(&b, "kit-approval", a); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(b.String(), "<button") || strings.Contains(b.String(), "<form") {
			t.Errorf("an approval request with %s offers its button: %s", what, b.String())
		}
	}
	var b bytes.Buffer
	if err := srv.tpl.ExecuteTemplate(&b, "kit-approval", whole); err != nil || !strings.Contains(b.String(), "<button") {
		t.Errorf("a whole approval request offers no button (%v): %s", err, b.String())
	}
}

// A figure that was never made shows that nothing was measured, never a
// nought: an empty tile is not a tile that counted none.
func TestAnUnmeasuredFigureIsNotANought(t *testing.T) {
	srv, _ := setup(t)
	var b bytes.Buffer
	if err := srv.tpl.ExecuteTemplate(&b, "kit-tile", seckit.Tile{Label: "Vendors"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Not measured") || strings.Contains(b.String(), ">0<") {
		t.Errorf("an unmeasured tile reads %s", b.String())
	}
}

// The kit's look works without colour: every status rule has a border for
// forced colours, nothing in it moves, and nothing in it is wider than a
// phone.
func TestTheKitsStylesHoldInForcedColoursAndAtNarrowWidths(t *testing.T) {
	css := stylesheet(t)
	i := strings.Index(css, "/* -- security kit")
	if i < 0 {
		t.Fatal("the stylesheet has no section for the security kit")
	}
	kit := css[i:]
	if j := strings.Index(kit[1:], "/* -- "); j > 0 {
		kit = kit[:j+1]
	}
	if !strings.Contains(kit, "@media (forced-colors: active)") || !strings.Contains(kit, "CanvasText") {
		t.Error("the kit says nothing for forced colours")
	}
	if regexp.MustCompile(`animation|transition`).MatchString(kit) {
		t.Error("something in the kit moves")
	}
	for _, m := range regexp.MustCompile(`(?:^|[;{\s])(?:width|min-width):\s*(\d+)(px|rem)`).FindAllStringSubmatch(kit, -1) {
		n := 0
		for _, c := range m[1] {
			n = n*10 + int(c-'0')
		}
		if m[2] == "px" && n > 320 || m[2] == "rem" && n > 20 {
			t.Errorf("the kit sets a width of %s%s, wider than a phone", m[1], m[2])
		}
	}
	if !strings.Contains(kit, "overflow-wrap: anywhere") {
		t.Error("a hash in the kit does not wrap, and takes a narrow page with it")
	}
	// A live region is in the page before its words arrive. One hidden
	// while it is empty is not in the accessibility tree when they do, and
	// is not announced by every screen reader; an empty one takes no room.
	for _, m := range regexp.MustCompile(`(?s)([^{}]*\.kit-(?:live|errors)[^{}]*)\{([^}]*)\}`).FindAllStringSubmatch(kit, -1) {
		if regexp.MustCompile(`display:\s*none|visibility:\s*hidden`).MatchString(m[2]) {
			t.Errorf("the kit hides a live region: %s{%s}", strings.TrimSpace(m[1]), m[2])
		}
	}
}

func kitSource(t *testing.T) string {
	t.Helper()
	b, err := assets.ReadFile("assets/seckit.html")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
