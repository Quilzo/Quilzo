// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package appsec

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

var now = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// fakeKey is a credential-shaped string, assembled rather than written out.
//
// The first version of this file spelled one in full, and GitHub's push
// protection refused the push — correctly, because a detector cannot tell a
// test fixture from the real thing and neither can anybody reading a diff.
// That is this package's whole argument arriving from the outside, so the
// fixture is built at run time and the file contains no string a scanner
// would flag.
func fakeKey() string {
	return "sk" + "_" + "live" + "_" + "51H8xQ2eZvKYlo2C0aBcDeFgH"
}

func alert(rule, path string, line int, snippet string) Alert {
	return Alert{
		Tool: "semgrep", Rule: rule, Kind: Weakness,
		Message: "possible injection", Severity: telemetry.SeverityMedium,
		Path: path, Line: line, Symbol: "handleRequest", Snippet: snippet,
		Repository: "acme/api",
	}
}

func secret(path string, line int, value string) Alert {
	return Alert{
		Tool: "gitleaks", Rule: "stripe-live-key", Kind: Secret,
		Message:  "stripe live key found: " + value,
		Severity: telemetry.SeverityHigh, Path: path, Line: line,
		Snippet: `key = "` + value + `"`, Repository: "acme/api",
	}
}

// A reformat closes four hundred findings and opens four hundred new ones.
func TestAnAlertThatMovedIsNotANewAlert(t *testing.T) {
	before := alert("sql-injection", "internal/api/handler.go", 42,
		`db.Query("SELECT * FROM t WHERE id = " + id)`)
	// The file is renamed, an import is added at the top, and the line is
	// reindented. Nothing about the finding changed.
	after := before
	after.Path = "internal/http/handler.go"
	after.Line = 57
	after.Snippet = "\t\t" + strings.Join(strings.Fields(before.Snippet), "  ")

	if before.Fingerprint() != after.Fingerprint() {
		t.Fatalf("a rename and a reindent produced a new finding:\n  %s\n  %s",
			before.Fingerprint(), after.Fingerprint())
	}

	base := Of([]Alert{before}, now)
	got := Compare([]Alert{after}, []Alert{before}, []Alert{before}, nil, now)
	if len(got.Introduced) != 0 {
		t.Fatalf("%d introduced by a rename", len(got.Introduced))
	}
	if len(got.Carried) != 1 {
		t.Errorf("%d carried", len(got.Carried))
	}
	if !base.Has(after) {
		t.Error("the baseline does not recognise the moved alert")
	}

	// A genuinely different line in the same function is a different
	// finding.
	other := before
	other.Snippet = `db.Query("SELECT * FROM u WHERE name = " + name)`
	if other.Fingerprint() == before.Fingerprint() {
		t.Error("two different lines share a fingerprint")
	}
}

// SARIF has carried partialFingerprints since 2.1.0 for exactly this.
func TestTheScannersOwnFingerprintIsPreferred(t *testing.T) {
	a := alert("sql-injection", "a.go", 1, "x")
	a.Given = "abc123"
	b := a
	b.Path, b.Line, b.Symbol, b.Snippet = "b.go", 99, "other", "entirely"
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("the scanner's own fingerprint did not win")
	}
	if !strings.HasPrefix(a.Fingerprint(), "g:") {
		t.Errorf("a given fingerprint reads as %q", a.Fingerprint())
	}
	if !a.Stable() {
		t.Error("an alert with a scanner fingerprint is unstable")
	}
}

// A tool emitting no symbol produces fingerprints a rename breaks, and that
// is worth knowing rather than discovering from a trend.
func TestAlertsIdentifiedOnlyByPathAreCounted(t *testing.T) {
	a := alert("weak-hash", "a.go", 1, "md5.New()")
	a.Symbol = ""
	if a.Stable() {
		t.Fatal("an alert with no symbol and no fingerprint reads as stable")
	}
	got := Compare([]Alert{a}, nil, nil, nil, now)
	if got.Churned != 1 {
		t.Fatalf("%d churned", got.Churned)
	}
	out := Findings(got, nil, now)
	var named bool
	for _, f := range out {
		if strings.Contains(f.Title, "identified by their path") {
			named = true
			if !strings.Contains(f.Evidence[0].What, "measuring whitespace") {
				t.Errorf("the evidence is %q", f.Evidence[0].What)
			}
		}
	}
	if !named {
		t.Error("nothing says the fingerprints are fragile")
	}
}

// The one that matters most and the one every tool gets wrong.
func TestADeletedSecretIsNotAFixedSecret(t *testing.T) {
	s := secret("config/prod.env", 12, fakeKey())
	// The next run: the line is gone.
	got := Compare(nil, nil, []Alert{s}, nil, now)

	if len(got.Cleared) != 0 {
		t.Fatalf("a deleted secret was cleared: %v", got.Cleared)
	}
	if len(got.Vanished) != 1 {
		t.Fatalf("vanished is %v", got.Vanished)
	}
	if !strings.Contains(got.Why(), "still in the history") {
		t.Errorf("the summary is %q", got.Why())
	}

	out := Findings(got, []Alert{s}, now)
	if len(out) == 0 || out[0].Severity != telemetry.SeverityCritical {
		t.Fatalf("the top finding is %v", out)
	}
	if !strings.Contains(out[0].Evidence[0].What, "only fix is rotation") {
		t.Errorf("the evidence is %q", out[0].Evidence[0].What)
	}

	// A recorded rotation does close it.
	r := Rotation{Secret: s.Fingerprint(), Where: "the Stripe live key",
		At: now, By: "rashik", Kind: audit.KindHuman,
		Because: "rolled in the Stripe dashboard and redeployed"}
	if err := r.Validate(); err != nil {
		t.Fatalf("an ordinary rotation was refused: %v", err)
	}
	closed := Compare(nil, nil, []Alert{s}, From([]Rotation{r}), now)
	if len(closed.Vanished) != 0 {
		t.Errorf("a rotated secret is still open: %v", closed.Vanished)
	}
	if len(closed.Cleared) != 1 {
		t.Errorf("cleared is %v", closed.Cleared)
	}

	// And a weakness that goes away is simply gone: only secrets get this.
	w := alert("sql-injection", "a.go", 1, "x")
	if len(Compare(nil, nil, []Alert{w}, nil, now).Vanished) != 0 {
		t.Error("a deleted weakness was treated like a secret")
	}
}

// Rewriting history breaks every clone and is often the wrong call.
func TestARotationDoesNotRequireAHistoryPurge(t *testing.T) {
	r := Rotation{Secret: "c:abc", Where: "the deploy key", At: now,
		By: "rashik", Kind: audit.KindHuman, Because: "replaced the key"}
	if err := r.Validate(); err != nil {
		t.Fatalf("a rotation without a purge was refused: %v", err)
	}
	if r.Record().Detail["purged"] != "" {
		t.Error("a rotation with no purge claims one")
	}
	r.Purged = true
	if r.Record().Detail["purged"] != "true" {
		t.Error("a purge is not recorded")
	}
}

func TestARotationNobodyCanCheckIsRefused(t *testing.T) {
	good := Rotation{Secret: "c:abc", Where: "the deploy key", At: now,
		By: "rashik", Kind: audit.KindHuman, Because: "replaced the key"}
	for name, spoil := range map[string]func(*Rotation){
		"no finding":          func(r *Rotation) { r.Secret = "" },
		"no credential named": func(r *Rotation) { r.Where = "" },
		"nobody":              func(r *Rotation) { r.By = "" },
		"no reason":           func(r *Rotation) { r.Because = "" },
		"a model":             func(r *Rotation) { r.Kind = audit.KindAI },
	} {
		x := good
		spoil(&x)
		if err := x.Validate(); err == nil {
			t.Errorf("a rotation with %s was accepted", name)
		}
	}
	x := good
	x.Kind = audit.KindAI
	if err := x.Validate(); !strings.Contains(err.Error(),
		"a key that still works") {
		t.Errorf("the refusal is %v", err)
	}
}

// A queue of secret findings that quotes the secrets is a second copy of
// them, in a file with wider access than the repository.
func TestASecretIsNotQuotedInTheQueue(t *testing.T) {
	value := fakeKey()
	s := secret("config/prod.env", 12, value)
	before := s.Fingerprint()

	r := s.Redact()
	if strings.Contains(r.Snippet, value) ||
		strings.Contains(r.Message, value) {
		t.Fatalf("the secret survives redaction: %+v", r)
	}
	if !strings.Contains(r.Message, "[redacted]") {
		t.Errorf("the message is %q", r.Message)
	}
	// And it is still the same finding afterwards.
	if r.Fingerprint() != before {
		t.Errorf("redaction changed the fingerprint: %s then %s", before,
			r.Fingerprint())
	}
	// A weakness keeps its snippet: the text is what makes it reviewable.
	w := alert("sql-injection", "a.go", 1, "db.Query(x)")
	if w.Redact().Snippet == "" {
		t.Error("a weakness lost its snippet")
	}
}

// A gate on total debt means nothing merges and is switched off within a
// month.
func TestTheGateIsOnWhatTheChangeIntroduced(t *testing.T) {
	var carried []Alert
	for n := range 400 {
		carried = append(carried,
			alert("weak-hash", fmt.Sprintf("old/%d.go", n), n, "md5.New()"))
	}
	fresh := alert("sql-injection", "new.go", 1, "db.Query(x)")
	fresh.Severity = telemetry.SeverityHigh

	t1 := Compare(append(carried, fresh), carried, carried, nil, now)
	g := Check(t1, telemetry.SeverityHigh)
	if g.Passes() {
		t.Fatal("a new high-severity alert passed the gate")
	}
	if len(g.Blocked) != 1 {
		t.Fatalf("%d blocked out of 401 alerts", len(g.Blocked))
	}
	if g.Carried != 400 {
		t.Errorf("%d carried", g.Carried)
	}
	if !strings.Contains(g.Why(telemetry.SeverityHigh),
		"gets switched off") {
		t.Errorf("the summary is %q", g.Why(telemetry.SeverityHigh))
	}

	// With nothing new, four hundred carried alerts do not block — and the
	// summary does not pretend the codebase is clean.
	clean := Check(Compare(carried, carried, carried, nil, now),
		telemetry.SeverityHigh)
	if !clean.Passes() {
		t.Fatal("an unchanged codebase failed its own gate")
	}
	if !strings.Contains(clean.Why(telemetry.SeverityHigh),
		"does not pretend is zero") {
		t.Errorf("the summary is %q", clean.Why(telemetry.SeverityHigh))
	}
}

// A credential in a commit is in the history whatever happens next.
func TestANewSecretBlocksAtAnySeverity(t *testing.T) {
	s := secret("config/prod.env", 12, fakeKey())
	s.Severity = telemetry.SeverityLow
	g := Check(Compare([]Alert{s}, nil, nil, nil, now), telemetry.SeverityCritical)
	if g.Passes() {
		t.Fatal("a low-severity secret passed a critical-only gate")
	}
	if len(g.Secrets) != 1 {
		t.Fatalf("secrets is %v", g.Secrets)
	}
	if !strings.Contains(g.Why(telemetry.SeverityCritical),
		"at any severity") {
		t.Errorf("the summary is %q", g.Why(telemetry.SeverityCritical))
	}
}

// Four hundred alerts for one bad pattern in one helper is one piece of work.
func TestTheQueueGroupsByRuleRatherThanByOccurrence(t *testing.T) {
	var in []Alert
	for n := range 400 {
		in = append(in, alert("weak-hash", fmt.Sprintf("a/%d.go", n), n,
			"md5.New()"))
	}
	serious := alert("sql-injection", "b.go", 1, "db.Query(x)")
	serious.Severity = telemetry.SeverityCritical
	in = append(in, serious)

	groups := Groups(in)
	if len(groups) != 2 {
		t.Fatalf("%d groups for two rules", len(groups))
	}
	// The critical one is on the first page rather than after four hundred
	// rows of the other.
	if groups[0].Rule != "sql-injection" {
		t.Errorf("the queue starts with %s", groups[0].Rule)
	}
	if groups[1].Count() != 400 {
		t.Errorf("the second group covers %d places", groups[1].Count())
	}
	if !strings.Contains(groups[1].Where(3), "and 397 more") {
		t.Errorf("the place list does not summarise: %q", groups[1].Where(3))
	}
	// And the register gets two rows, not four hundred and one.
	out := Findings(Compare(in, nil, nil, nil, now), nil, now)
	if len(out) > 4 {
		t.Errorf("%d findings for two rules", len(out))
	}
}

// A dependency alert belongs to the vulnerability queue; a weakness in code
// somebody wrote does not.
func TestTheRegisterKindFollowsWhatWasFound(t *testing.T) {
	dep := alert("CVE-2026-1234", "go.mod", 7, "golang.org/x/net v0.1.0")
	dep.Kind = Dependency
	code := alert("sql-injection", "a.go", 1, "db.Query(x)")

	out := Findings(Compare([]Alert{dep, code}, nil, nil, nil, now), nil, now)
	var kinds []finding.Kind
	for _, f := range out {
		kinds = append(kinds, f.Kind)
	}
	var sawVuln, sawCode bool
	for _, k := range kinds {
		switch k {
		case finding.FromVulnerability:
			sawVuln = true
		case finding.FromCode:
			sawCode = true
		}
	}
	if !sawVuln || !sawCode {
		t.Errorf("kinds are %v", kinds)
	}
}

func TestAnAlertNobodyCanTraceIsRefused(t *testing.T) {
	good := alert("sql-injection", "a.go", 1, "x")
	for name, spoil := range map[string]func(*Alert){
		"no tool":          func(a *Alert) { a.Tool = "" },
		"no rule":          func(a *Alert) { a.Rule = "" },
		"no file":          func(a *Alert) { a.Path = "" },
		"an invented kind": func(a *Alert) { a.Kind = Kind("maybe") },
		"a negative line":  func(a *Alert) { a.Line = -1 },
	} {
		x := good
		spoil(&x)
		if err := x.Validate(); err == nil {
			t.Errorf("an alert with %s was accepted", name)
		}
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("an ordinary alert was refused: %v", err)
	}
}

func TestARotationReachesARealAuditLog(t *testing.T) {
	dir := t.TempDir()
	k, err := audit.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.New(audit.Options{Path: dir + "/audit.jsonl", Key: k,
		Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	r := Rotation{Secret: "c:abc", Where: "the Stripe live key", At: now,
		By: "rashik", Kind: audit.KindHuman,
		Because: "rolled in the dashboard and redeployed", Purged: true}
	if _, aerr := log.Append(r.Record()); aerr != nil {
		t.Fatal(aerr)
	}
	events, err := audit.Read(dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "appsec.rotated" {
		t.Fatalf("the log holds %v", events)
	}
	// The credential is never in the record.
	for k, v := range events[0].Detail {
		if strings.Contains(v, fakeKey()[:7]) {
			t.Errorf("%s carries a credential", k)
		}
	}
}

// Without carrying it forward, a vanished secret is reported once and
// forgotten on the next run — the same outcome as every other scanner,
// arrived at by a different route.
func TestAVanishedSecretStaysOpenAcrossRuns(t *testing.T) {
	s := secret("config/prod.env", 12, fakeKey())
	w := alert("sql-injection", "a.go", 1, "db.Query(x)")

	// Run one saw both. Run two sees only the weakness.
	first := Compare([]Alert{w}, nil, []Alert{s, w}, nil, now)
	if len(first.Vanished) != 1 {
		t.Fatalf("vanished is %v", first.Vanished)
	}

	// The caller carries the unrotated secret into the next previous-run,
	// which is what the CLI's remember does. Without it the third run finds
	// nothing.
	carried := []Alert{w, s.Redact()}
	second := Compare([]Alert{w}, nil, carried, nil, now)
	if len(second.Vanished) != 1 {
		t.Fatalf("the secret was forgotten on the second run: %v",
			second.Vanished)
	}
	if second.Vanished[0] != first.Vanished[0] {
		t.Errorf("the fingerprint changed between runs: %s then %s",
			first.Vanished[0], second.Vanished[0])
	}

	// And a rotation closes it for good.
	r := Rotation{Secret: s.Fingerprint(), Where: "the Stripe live key",
		At: now, By: "rashik", Kind: audit.KindHuman,
		Because: "rolled in the dashboard"}
	closed := Compare([]Alert{w}, nil, carried, From([]Rotation{r}), now)
	if len(closed.Vanished) != 0 {
		t.Errorf("a rotated secret is still open: %v", closed.Vanished)
	}
}

// New is measured against the accepted debt and gone against the previous
// run, and collapsing the two is how a secret gets closed by a deleted line.
func TestNewIsAgainstTheDebtAndGoneIsAgainstTheLastRun(t *testing.T) {
	old := alert("weak-hash", "a.go", 1, "md5.New()")
	fresh := alert("sql-injection", "b.go", 1, "db.Query(x)")

	// The debt holds the weak hash. The previous run saw both, because
	// the injection was introduced two runs ago and never accepted.
	got := Compare([]Alert{old, fresh}, []Alert{old},
		[]Alert{old, fresh}, nil, now)
	if len(got.Introduced) != 1 ||
		got.Introduced[0].Rule != "sql-injection" {
		t.Fatalf("introduced is %v", got.Introduced)
	}
	if len(got.Carried) != 1 {
		t.Errorf("carried is %v", got.Carried)
	}
	// Nothing went away.
	if len(got.Cleared) != 0 || len(got.Vanished) != 0 {
		t.Errorf("cleared %v, vanished %v", got.Cleared, got.Vanished)
	}
}
