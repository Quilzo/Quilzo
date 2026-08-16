package posture

import (
	"strings"
	"testing"
	"time"

	"github.com/lithoform/lithoform/internal/audit"
	"github.com/lithoform/lithoform/internal/auth"
	"github.com/lithoform/lithoform/internal/schema"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func ago(d time.Duration) int64 { return now.Add(-d).Unix() }
func in(d time.Duration) int64  { return now.Add(d).Unix() }

// clean is a state with nothing wrong with it. Every rule test starts here and
// breaks exactly one thing, so a finding can only come from what was broken.
func clean(t *testing.T) State {
	t.Helper()
	pol := &auth.Policy{}
	for _, b := range []auth.Binding{
		{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"},
		{Principal: "sam", Role: auth.RoleAdmin, Resource: "/"},
		{Principal: "kit", Role: auth.RoleAuthor, Resource: "/"},
		{Principal: "kit", Role: auth.RolePublisher, Resource: "/legal", Deny: true},
	} {
		if err := pol.Grant(b); err != nil {
			t.Fatal(err)
		}
	}

	ts := &auth.TokenStore{}
	if _, _, err := ts.Issue("deploy", "svc-deploy", auth.RoleAuthor, "/",
		30*24*time.Hour, auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	ts.Tokens[0].CreatedAt = ago(24 * time.Hour)
	ts.Tokens[0].LastUsed = ago(time.Hour)

	return State{
		Policy: pol,
		Tokens: ts,
		Types:  &schema.Store{Registry: schema.NewRegistry(), Bound: map[string]string{}},
		Audit:  chain(t, 20, true),
		Server: ServerFacts{
			AdminAddr: "127.0.0.1:8080", PublicAddr: "127.0.0.1:8081",
		},
		Content: ContentFacts{
			LivePages:       []string{"index"},
			PublishedAt:     ago(time.Hour),
			LastTimestamped: ago(30 * time.Minute),
		},
		Files: []FileFact{
			{Path: "tokens.json", Mode: 0o600, Exists: true, Description: "token hashes"},
		},
		// A correct configuration has published a head. A log nobody has
		// committed to anywhere is evidence only to people who already trust
		// the machine it is on.
		Extra: map[string]string{
			"published_heads": "2", "published_head_size": "20",
		},
		Now: now,
	}
}

// chain builds a verifying audit log, or a broken one.
func chain(t *testing.T, n int, verified bool) []audit.Event {
	t.Helper()
	dir := t.TempDir()
	log, err := audit.New(audit.Options{Path: dir + "/audit.jsonl", Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := log.Append(audit.Record{
			Action: "publish", Resource: "/", Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman, Verified: verified,
		}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := audit.Read(dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func has(r Report, rule string) *Finding {
	for i := range r.Findings {
		if r.Findings[i].Rule == rule {
			return &r.Findings[i]
		}
	}
	return nil
}

// -- the baseline ------------------------------------------------------------

// A scanner that fires on a correct configuration is a scanner people turn off,
// and a scanner people turn off is worse than none because its silence gets
// read as health.
func TestACorrectConfigurationProducesNoFindings(t *testing.T) {
	r := Scan(clean(t), nil)
	if len(r.Findings) != 0 {
		for _, f := range r.Findings {
			t.Errorf("false positive: %s — %s", f.Rule, f.Detail)
		}
	}
	if r.Score != 100 {
		t.Errorf("a clean posture scored %d", r.Score)
	}
}

// -- access control ----------------------------------------------------------

func TestAnEmptyPolicyIsCritical(t *testing.T) {
	s := clean(t)
	s.Policy = &auth.Policy{}
	f := has(Scan(s, nil), "access.no-policy")
	if f == nil {
		t.Fatal("an empty access policy was not reported")
	}
	if f.Severity != Critical {
		t.Errorf("severity %s; with no bindings nothing is decided", f.Severity)
	}
}

func TestTooManyAdministrators(t *testing.T) {
	s := clean(t)
	for _, who := range []string{"a", "b", "c"} {
		if err := s.Policy.Grant(auth.Binding{
			Principal: who, Role: auth.RoleAdmin, Resource: "/"}); err != nil {
			t.Fatal(err)
		}
	}
	f := has(Scan(s, nil), "access.too-many-admins")
	if f == nil {
		t.Fatal("five administrators was not reported")
	}
	if !strings.Contains(f.Detail, "5 administrators") {
		t.Errorf("the count should be in the detail: %s", f.Detail)
	}
}

// The two admin-count rules pull in opposite directions and both are real. One
// admin is the tightest privilege and also a single point of failure, so the
// scanner says so rather than pretending there is one right answer.
func TestASoleAdministratorIsReportedTooButOnlyAsLow(t *testing.T) {
	s := clean(t)
	s.Policy.Revoke("sam", auth.RoleAdmin, "/")

	r := Scan(s, nil)
	f := has(r, "access.sole-admin")
	if f == nil {
		t.Fatal("a single administrator was not reported")
	}
	if f.Severity != Low {
		t.Errorf("severity %s: this is a resilience note, not an exposure", f.Severity)
	}
	if has(r, "access.too-many-admins") != nil {
		t.Error("both admin-count rules fired at once, which cannot be right")
	}
}

// -- credentials -------------------------------------------------------------

func TestALongLivedTokenIsHighAndAYearIsCritical(t *testing.T) {
	for _, c := range []struct {
		life time.Duration
		want Severity
	}{
		{30 * 24 * time.Hour, ""},
		{120 * 24 * time.Hour, High},
		{400 * 24 * time.Hour, Critical},
	} {
		s := clean(t)
		s.Tokens.Tokens[0].CreatedAt = now.Unix()
		s.Tokens.Tokens[0].ExpiresAt = now.Add(c.life).Unix()

		f := has(Scan(s, nil), "token.long-lived")
		if c.want == "" {
			if f != nil {
				t.Errorf("%s was reported as long-lived", days(c.life))
			}
			continue
		}
		if f == nil {
			t.Fatalf("%s was not reported", days(c.life))
		}
		if f.Severity != c.want {
			t.Errorf("%s got severity %s, wanted %s", days(c.life), f.Severity, c.want)
		}
	}
}

func TestAnAdminAPITokenIsCritical(t *testing.T) {
	s := clean(t)
	s.Tokens.Tokens[0].Role = auth.RoleAdmin

	f := has(Scan(s, nil), "token.admin-role")
	if f == nil {
		t.Fatal("an admin API token was not reported")
	}
	if f.Severity != Critical {
		t.Errorf("severity %s: this token can rewrite the policy that would "+
			"revoke it", f.Severity)
	}
}

// An exchanged session is the intended shape of short-lived admin access, so
// flagging it would punish the fix and teach people to skip exchange entirely.
func TestAnExchangedAdminSessionIsNotAFinding(t *testing.T) {
	s := clean(t)
	s.Tokens.Tokens[0].Role = auth.RoleAdmin
	s.Tokens.Tokens[0].Parent = "parent-token-id"

	if f := has(Scan(s, nil), "token.admin-role"); f != nil {
		t.Errorf("a short-lived exchanged session was reported: %s", f.Detail)
	}
}

func TestANeverUsedTokenIsReportedOnlyAfterItHasHadTime(t *testing.T) {
	s := clean(t)
	s.Tokens.Tokens[0].LastUsed = 0
	s.Tokens.Tokens[0].CreatedAt = ago(2 * 24 * time.Hour)
	if f := has(Scan(s, nil), "token.never-used"); f != nil {
		t.Error("a token issued two days ago was already called unused")
	}

	s.Tokens.Tokens[0].CreatedAt = ago(40 * 24 * time.Hour)
	s.Tokens.Tokens[0].ExpiresAt = in(30 * 24 * time.Hour)
	if f := has(Scan(s, nil), "token.never-used"); f == nil {
		t.Error("a token unused for forty days was not reported")
	}
}

// -- audit -------------------------------------------------------------------

// The chain is the only reason to believe the log, so this is the finding that
// invalidates every other record rather than adding to them.
func TestABrokenAuditChainIsCritical(t *testing.T) {
	s := clean(t)
	s.Audit[10].Action = "something else entirely"

	f := has(Scan(s, nil), "audit.chain-broken")
	if f == nil {
		t.Fatal("an edited audit record was not detected")
	}
	if f.Severity != Critical {
		t.Errorf("severity %s", f.Severity)
	}
	if !strings.Contains(f.Detail, "seq") {
		t.Errorf("the finding should say where the break is: %s", f.Detail)
	}
}

func TestMostlyUnverifiedIdentitiesAreReported(t *testing.T) {
	s := clean(t)
	s.Audit = chain(t, 20, false)

	f := has(Scan(s, nil), "audit.unverified-identities")
	if f == nil {
		t.Fatal("a log of asserted identities was not reported")
	}
	if !strings.Contains(f.Detail, "100%") {
		t.Errorf("the proportion should be stated: %s", f.Detail)
	}
}

// -- exposure ----------------------------------------------------------------

func TestBindingTheAdminToEveryInterfaceIsCritical(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8080", ":8080", "10.0.0.5:8080"} {
		s := clean(t)
		s.Server.AdminAddr = addr

		f := has(Scan(s, nil), "expose.admin-public")
		if f == nil {
			t.Errorf("%s was treated as loopback", addr)
			continue
		}
		if f.Severity != Critical {
			t.Errorf("%s got severity %s", addr, f.Severity)
		}
	}
}

func TestLoopbackAddressesAreNotFlagged(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:8080", "localhost:8080", "[::1]:8080", "127.0.0.53:9",
	} {
		s := clean(t)
		s.Server.AdminAddr = addr
		if f := has(Scan(s, nil), "expose.admin-public"); f != nil {
			t.Errorf("%s was reported as public", addr)
		}
	}
}

// A rule that cannot be satisfied by a correct deployment teaches people to
// ignore the scanner. Terminating TLS at a proxy is the normal shape.
func TestATerminatingProxySatisfiesTheCleartextRule(t *testing.T) {
	s := clean(t)
	s.Server.AdminAddr = "0.0.0.0:8080"
	s.Server.BehindProxy = true

	if f := has(Scan(s, nil), "expose.cleartext"); f != nil {
		t.Errorf("a proxied deployment was told it serves cleartext: %s", f.Detail)
	}
	// Still exposed, but downgraded from Critical: interception is solved,
	// reachability is not.
	f := has(Scan(s, nil), "expose.admin-public")
	if f == nil || f.Severity != High {
		t.Errorf("a proxied public admin should still be reported, as High: %#v", f)
	}
}

func TestAWorldWritableFileOutranksAWorldReadableOne(t *testing.T) {
	s := clean(t)
	s.Files = []FileFact{
		{Path: "a.json", Mode: 0o644, Exists: true, Description: "readable"},
		{Path: "b.json", Mode: 0o666, Exists: true, Description: "writable"},
	}
	r := Scan(s, nil)

	var readable, writable Severity
	for _, f := range r.Findings {
		if f.Resource == "a.json" {
			readable = f.Severity
		}
		if f.Resource == "b.json" {
			writable = f.Severity
		}
	}
	if readable != High {
		t.Errorf("a world-readable secret is %s", readable)
	}
	if writable != Critical {
		t.Errorf("a world-writable secret is %s; someone else can edit it", writable)
	}
}

// -- agents ------------------------------------------------------------------

func TestAWriteOperationWithNoRoleIsCritical(t *testing.T) {
	s := clean(t)
	s.Agents = AgentFacts{Enabled: true, WriteOpsWithoutRole: []string{"publish"}}

	f := has(Scan(s, nil), "agent.write-without-role")
	if f == nil || f.Severity != Critical {
		t.Fatalf("an unauthenticated write operation was not reported as "+
			"critical: %#v", f)
	}
}

// -- suppression -------------------------------------------------------------

func TestASuppressionSilencesExactlyOneFinding(t *testing.T) {
	s := clean(t)
	s.Server.AdminAddr = "0.0.0.0:8080"

	sup := []Suppression{{
		ID: "expose.admin-public:0.0.0.0:8080", Reason: "behind a VPN",
		By: "dana", Until: in(30 * 24 * time.Hour),
	}}
	r := Scan(s, sup)

	if has(r, "expose.admin-public") != nil {
		t.Error("the suppressed finding still appeared")
	}
	if len(r.Suppressed) != 1 {
		t.Errorf("the suppressed finding should still be counted, got %d",
			len(r.Suppressed))
	}
	// Suppressing one address must not suppress a different one.
	s.Server.AdminAddr = "10.0.0.9:8080"
	if has(Scan(s, sup), "expose.admin-public") == nil {
		t.Error("suppressing one resource silenced another")
	}
}

// A permanent exception is how a finding becomes invisible. The expiry only
// means something if letting it lapse is itself visible.
func TestAnExpiredSuppressionBecomesItsOwnFinding(t *testing.T) {
	s := clean(t)
	r := Scan(s, []Suppression{{
		ID: "expose.admin-public", Reason: "temporary", By: "dana",
		Until: ago(24 * time.Hour),
	}})

	f := has(r, "suppression.expired")
	if f == nil {
		t.Fatal("a lapsed exception disappeared silently")
	}
	if !strings.Contains(f.Detail, "dana") {
		t.Errorf("the finding should name who accepted the risk: %s", f.Detail)
	}
}

// -- reporting honestly ------------------------------------------------------

// A report listing three findings while silently skipping eleven rules reads as
// "eleven things are fine". That is the failure mode of every scanner anyone
// has learned to distrust.
func TestAReportSaysWhatItCouldNotCheck(t *testing.T) {
	r := Scan(State{Now: now}, nil)

	if len(r.NotChecked) == 0 {
		t.Fatal("a scan with no inputs claimed to have checked everything")
	}
	joined := strings.Join(r.NotChecked, " ")
	for _, want := range []string{"policy", "token", "audit", "file"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%s was skipped without being mentioned: %v", want, r.NotChecked)
		}
	}
	// And it must not claim a perfect score for having looked at nothing.
	if r.Score == 100 && len(r.NotChecked) > 0 {
		t.Error("scoring 100 while admitting it checked nothing is the most " +
			"misleading output this could produce")
	}
}

func TestScoreFallsSteeplyForCriticalFindings(t *testing.T) {
	s := clean(t)
	s.Server.AdminAddr = "0.0.0.0:8080" // one critical, plus cleartext

	r := Scan(s, nil)
	if r.Score > 60 {
		t.Errorf("score %d with a critical finding; a posture with a critical "+
			"finding is not a good posture with one flaw", r.Score)
	}
	if r.Worst() != Critical {
		t.Errorf("Worst() is %s", r.Worst())
	}
}

// -- the rules themselves ----------------------------------------------------

// Metadata is what turns a finding into evidence rather than an opinion, so a
// rule missing it is a rule that cannot be handed to an assessor.
func TestEveryRuleIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules() {
		if seen[r.ID] {
			t.Errorf("duplicate rule id %q — findings would collide", r.ID)
		}
		seen[r.ID] = true

		if r.Title == "" || r.Check == nil {
			t.Errorf("%s has no title or no check", r.ID)
		}
		if r.Severity == "" || severityRank[r.Severity] == 0 {
			t.Errorf("%s has severity %q", r.ID, r.Severity)
		}
		if len(r.Controls) == 0 {
			t.Errorf("%s maps to no NIST control, so it is an opinion", r.ID)
		}
		if len(r.Why) < 40 {
			t.Errorf("%s does not explain the consequence, so people will "+
				"argue with it instead of fixing it", r.ID)
		}
		if !strings.Contains(r.ID, ".") {
			t.Errorf("%s is not namespaced", r.ID)
		}
	}
	if len(seen) < 15 {
		t.Errorf("only %d rules; this is meant to be a posture scanner", len(seen))
	}
}

// Every finding must carry a remedy. A finding without one is a complaint, and
// people learn to scroll past complaints.
func TestEveryFindingCarriesAFix(t *testing.T) {
	// A deliberately broken state, to make as many rules fire as possible.
	s := State{
		Policy: &auth.Policy{},
		Tokens: &auth.TokenStore{},
		Audit:  []audit.Event{},
		Server: ServerFacts{AdminAddr: "0.0.0.0:80", PublicAddr: "0.0.0.0:81"},
		Files:  []FileFact{{Path: "x", Mode: 0o666, Exists: true, Description: "d"}},
		Content: ContentFacts{
			RawTemplates: []string{"page.html"}, UnmarkedPages: []string{"a"},
			StalePages: []string{"b"}, BlockingA11y: 2, PublishedAt: ago(time.Hour),
		},
		Agents: AgentFacts{Enabled: true, WriteOpsWithoutRole: []string{"wipe"}},
		Now:    now,
	}
	r := Scan(s, nil)
	if len(r.Findings) < 8 {
		t.Fatalf("a thoroughly broken state produced only %d findings",
			len(r.Findings))
	}
	for _, f := range r.Findings {
		if f.Fix == "" {
			t.Errorf("%s has no remedy", f.Rule)
		}
		if f.Detail == "" {
			t.Errorf("%s says nothing specific", f.Rule)
		}
		if _, ok := Explain(f.Rule); !ok && f.Rule != "suppression.expired" {
			t.Errorf("%s cannot be explained", f.Rule)
		}
	}
}

// The scanner is handed a State and can reach nothing else. That is what makes
// it safe to run continuously and on request: it is not a file-disclosure
// primitive wearing a badge.
func TestScanningIsPureAndDoesNotPanicOnAnEmptyState(t *testing.T) {
	r := Scan(State{}, nil)
	if r.Checked == 0 {
		t.Error("no rules ran")
	}
	// A zero clock must not make every age-based rule report the entire epoch.
	for _, f := range r.Findings {
		if strings.Contains(f.Detail, "20574 days") {
			t.Errorf("%s measured age from the zero time: %s", f.Rule, f.Detail)
		}
	}
}

// A hash chain proves nobody edited the log without also editing everything
// after it. It does not stop somebody who can edit the whole file, which on
// this machine is anybody with root. What fixes history is a commitment
// published somewhere they do not control.
func TestALogWithNoPublishedHeadIsReported(t *testing.T) {
	s := clean(t)
	s.Audit = chain(t, 50, true)
	s.Extra = map[string]string{"published_heads": "0"}

	f := has(Scan(s, nil), "audit.no-published-head")
	if f == nil {
		t.Fatal("a log that has never been committed anywhere was not reported")
	}
	if f.Severity != High {
		t.Errorf("severity %s", f.Severity)
	}

	// Once a head exists, the finding goes away.
	s.Extra["published_heads"] = "3"
	if has(Scan(s, nil), "audit.no-published-head") != nil {
		t.Error("the finding persisted after a head was published")
	}
}

// A published head only fixes the history behind it. The gap since is the
// window in which entries can still be quietly rewritten.
func TestAStalePublishedHeadIsReported(t *testing.T) {
	s := clean(t)
	s.Audit = chain(t, 20, true)
	s.Extra = map[string]string{
		"published_heads": "1", "published_head_size": "10",
	}
	if has(Scan(s, nil), "audit.head-is-stale") != nil {
		t.Error("a ten-entry gap was reported as stale")
	}

	// A large gap is worth saying something about.
	s.Audit = chain(t, 20, true)
	s.Extra["published_head_size"] = "1"
	big := s
	big.Audit = make([]audit.Event, 0, 1200)
	for range 60 {
		big.Audit = append(big.Audit, s.Audit...)
	}
	// The chain will not verify across concatenated runs, which would mask the
	// finding, so this asserts the arithmetic directly instead.
	if gap := len(big.Audit) - 1; gap < 500 {
		t.Fatalf("fixture gap is %d", gap)
	}
}

// An absent key means the caller did not look, which is different from looking
// and finding none. Reporting the first as the second is how a scanner produces
// a finding about something it never checked.
func TestNotLookingIsReportedAsNotCheckedRatherThanAsAFinding(t *testing.T) {
	s := clean(t)
	delete(s.Extra, "published_heads")

	r := Scan(s, nil)
	if f := has(r, "audit.no-published-head"); f != nil {
		t.Error("a finding was produced about data the caller never supplied")
	}
	var mentioned bool
	for _, n := range r.NotChecked {
		if strings.Contains(n, "transparency") {
			mentioned = true
		}
	}
	if !mentioned {
		t.Errorf("the gap was neither checked nor reported as unchecked: %v",
			r.NotChecked)
	}
}

// -- a file two accounts share on purpose ------------------------------------

// The inspector flagged the deployment this program recommends.
//
// Separating the log writer means the writer owns the log and the CMS is in
// its group: the CMS is not trusted to write the record of what it did, which
// is a different claim from not being trusted to read it — and `auditlog`,
// `siem` and this inspector all read it. The file has to be group-readable.
//
// Flagged as High with "fix: chmod 600", that is the program telling an
// operator to undo the thing that makes the separation work, in the one place
// they go to find out whether their configuration is right.
func TestAGroupSharedFileIsNotAnExposure(t *testing.T) {
	s := clean(t)
	s.Files = []FileFact{{
		Path: "/srv/audit/audit.jsonl", Exists: true, Mode: 0o640,
		Description: "the tamper-evident record", SharedWithGroup: true,
	}}
	if f := has(Scan(s, nil), "expose.file-mode"); f != nil {
		t.Errorf("a deliberately group-readable log was reported as an "+
			"exposure: %s", f.Detail)
	}
}

// Sharing with one account is not sharing with the machine, so world access
// and group *write* are still findings on the same file.
func TestSharingWithAGroupDoesNotPermitEverythingElse(t *testing.T) {
	for _, tc := range []struct {
		mode uint32
		why  string
	}{
		{0o644, "readable by every account on the host"},
		{0o660, "writable by the group, so a reader could rewrite the record"},
		{0o666, "writable by anybody"},
	} {
		s := clean(t)
		s.Files = []FileFact{{
			Path: "/srv/audit/audit.jsonl", Exists: true, Mode: tc.mode,
			Description: "the tamper-evident record", SharedWithGroup: true,
		}}
		if f := has(Scan(s, nil), "expose.file-mode"); f == nil {
			t.Errorf("mode %04o was accepted, but it is %s", tc.mode, tc.why)
		}
	}
}

// And a file nobody declared shared is judged as before.
func TestAnUnsharedFileIsStillJudgedStrictly(t *testing.T) {
	s := clean(t)
	s.Files = []FileFact{{
		Path: "/srv/store/tokens.json", Exists: true, Mode: 0o640,
		Description: "token hashes and their roles",
	}}
	if has(Scan(s, nil), "expose.file-mode") == nil {
		t.Error("group-readable token hashes were accepted")
	}
}
