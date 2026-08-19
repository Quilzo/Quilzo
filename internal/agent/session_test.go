package agent

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func testSession(t *testing.T, k Kind) *Session {
	t.Helper()
	m, err := New(k, "under-test", knownOps())
	if err != nil {
		t.Fatal(err)
	}
	return NewSession(m, nil)
}

// A capability not in the manifest is refused, and the refusal says which.
func TestAnUndeclaredCapabilityIsRefused(t *testing.T) {
	s := testSession(t, KindRetrieval)

	if err := s.Authorize("read_page"); err != nil {
		t.Fatalf("a declared capability was refused: %v", err)
	}
	err := s.Authorize("write_page")
	if err == nil {
		t.Fatal("a retrieval agent was allowed to write")
	}
	if !IsRefusal(err) {
		t.Errorf("the error is not a Refusal, so a caller cannot tell " +
			"'you may not' from 'it broke'")
	}
	if !strings.Contains(err.Error(), "write_page") {
		t.Errorf("the refusal does not name the missing capability: %v", err)
	}
}

// Autonomy is re-checked at the chokepoint, not only at validation.
//
// A stored manifest is a file. It is not a proof about the object in memory,
// and the object in memory is what the run is actually enforcing.
func TestAutonomyIsRecheckedAtTheChokepoint(t *testing.T) {
	// A manifest that would not validate, constructed directly — the shape a
	// bug or a hand-edited file produces.
	m := Manifest{
		Name: "inconsistent", Kind: KindRetrieval, Purpose: "look harmless",
		Capabilities: []string{"read_page", "write_page", "publish"},
		Autonomy:     AutonomyPropose,
		Budget:       Budget{Steps: 10, Tools: 5, Duration: Duration(time.Minute)},
	}
	s := NewSession(m, nil)

	if err := s.Authorize("write_page"); err == nil {
		t.Error("a propose-only session performed a write because the " +
			"capability list said so; the two have to agree at the gate")
	}
	if err := s.Authorize("publish"); err == nil {
		t.Error("a propose-only session published")
	}
}

// Editing the stored manifest cannot widen a run already in flight.
func TestASessionIsNotWidenedByEditingTheManifest(t *testing.T) {
	m, err := New(KindRetrieval, "bot", knownOps())
	if err != nil {
		t.Fatal(err)
	}
	s := NewSession(m, nil)

	// The caller still holds the manifest and edits it mid-run.
	m.Capabilities = append(m.Capabilities, "write_page")
	m.Autonomy = AutonomyPublish

	if err := s.Authorize("write_page"); err == nil {
		t.Fatal("widening the manifest widened a session already running")
	}
}

// The step budget stops the run rather than warning about it.
func TestTheStepBudgetRefuses(t *testing.T) {
	m := Manifest{
		Name: "looper", Kind: KindTask, Purpose: "go round",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyDraft,
		Budget: Budget{Steps: 3, Tools: 2, Duration: Duration(time.Hour)},
	}
	s := NewSession(m, nil)

	for i := range 3 {
		if err := s.Authorize("read_page"); err != nil {
			t.Fatalf("step %d was refused early: %v", i, err)
		}
	}
	if err := s.Authorize("read_page"); err == nil {
		t.Fatal("the step budget did not stop the run")
	}
	if steps, _, _ := s.Spent(); steps != 3 {
		t.Errorf("spent %d steps, want 3 — a refused step must not be charged", steps)
	}
}

// So does the wall-clock budget.
func TestTheDurationBudgetRefuses(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	m := Manifest{
		Name: "slow", Kind: KindTask, Purpose: "take too long",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyDraft,
		Budget: Budget{Steps: 100, Tools: 10, Duration: Duration(time.Minute)},
	}
	s := NewSession(m, clock)

	if err := s.Authorize("read_page"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if err := s.Authorize("read_page"); err == nil {
		t.Fatal("the run continued past its duration budget")
	}
}

// An agent reaches only the hosts it declared.
func TestAnAgentReachesOnlyDeclaredHosts(t *testing.T) {
	m := Manifest{
		Name: "caller", Kind: KindOperator, Purpose: "run errands",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyPropose,
		Tools: []Tool{{
			Name: "crm", Host: "api.example.com", Purpose: "look up a customer",
		}},
		Budget: Budget{Steps: 10, Tools: 2, Duration: Duration(time.Hour)},
	}
	s := NewSession(m, nil)

	if err := s.MayReach("api.example.com"); err != nil {
		t.Fatalf("a declared host was refused: %v", err)
	}
	// Case is not a security boundary.
	if err := s.MayReach("API.Example.COM"); err != nil {
		t.Errorf("the same host in different case was refused: %v", err)
	}
	for _, bad := range []string{
		"evil.example.com",
		"api.example.com.evil.net", // suffix trick
		"169.254.169.254",          // the metadata endpoint
		"localhost",
		"",
	} {
		if err := s.MayReach(bad); err == nil {
			t.Errorf("the agent was allowed to reach %q", bad)
		}
	}
}

// An agent with no declared tools reaches nothing.
//
// The operator template ships this way on purpose: it is the most useful
// archetype and by a distance the most dangerous, so every host is a decision.
func TestAnAgentWithNoToolsReachesNothing(t *testing.T) {
	s := testSession(t, KindOperator)
	err := s.MayReach("api.example.com")
	if err == nil {
		t.Fatal("an agent declaring no tools reached the internet")
	}
	if !strings.Contains(err.Error(), "declares no tools") {
		t.Errorf("the refusal does not explain why: %v", err)
	}
}

// The tool budget is separate from the step budget.
func TestTheToolBudgetIsSeparate(t *testing.T) {
	m := Manifest{
		Name: "caller", Kind: KindOperator, Purpose: "errands",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyPropose,
		Tools:  []Tool{{Name: "x", Host: "a.example.com", Purpose: "p"}},
		Budget: Budget{Steps: 100, Tools: 2, Duration: Duration(time.Hour)},
	}
	s := NewSession(m, nil)
	for range 2 {
		if err := s.MayReach("a.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MayReach("a.example.com"); err == nil {
		t.Fatal("the tool budget did not stop outbound calls")
	}
}

// A retrieval agent cannot be asked for the draft.
func TestARetrievalAgentCannotReadTheDraft(t *testing.T) {
	s := testSession(t, KindRetrieval)

	if err := s.Retrieve("live", "article", "en"); err != nil {
		t.Fatalf("reading live was refused: %v", err)
	}
	err := s.Retrieve("draft", "article", "en")
	if err == nil {
		t.Fatal("a live-scoped agent read the draft; that is a disclosure " +
			"with a friendly interface")
	}
}

// Type and locale scopes narrow retrieval, and empty means unrestricted.
func TestRetrievalScopeNarrowsByTypeAndLocale(t *testing.T) {
	m := Manifest{
		Name: "narrow", Kind: KindRetrieval, Purpose: "answer",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyPropose,
		Retrieval: Retrieval{
			Ref: "live", Types: []string{"article"}, Locales: []string{"en"},
		},
		Budget: Budget{Steps: 10, Tools: 2, Duration: Duration(time.Hour)},
	}
	s := NewSession(m, nil)

	if err := s.Retrieve("live", "article", "en-GB"); err != nil {
		t.Errorf("en-GB was refused by a scope naming en: %v", err)
	}
	if err := s.Retrieve("live", "article", ""); err != nil {
		t.Errorf("an untyped/unlocalised page was refused: %v", err)
	}
	if err := s.Retrieve("live", "legal", "en"); err == nil {
		t.Error("a type outside the scope was read")
	}
	if err := s.Retrieve("live", "article", "de"); err == nil {
		t.Error("a locale outside the scope was read")
	}
}

// Reading stored content taints the run, and a tainted run does not publish
// itself.
//
// This is the CaMeL-shaped rule. A page an agent reads may have been written by
// anybody who can write a page — a form submission, an importer, a previous
// agent — so output downstream of it is not evidence that the agent decided
// anything.
func TestReadingStoredContentTaintsTheRun(t *testing.T) {
	m := Manifest{
		Name: "publisher", Kind: KindTask, Purpose: "ship",
		Capabilities: []string{"read_page", "publish"},
		Autonomy:     AutonomyPublish,
		Retrieval:    Retrieval{Ref: "live"},
		Budget:       Budget{Steps: 10, Tools: 2, Duration: Duration(time.Hour)},
		// Deliberately not requiring approval, to isolate the taint rule.
		HumanApproval: false,
	}
	s := NewSession(m, nil)

	if ok, _ := s.Publishable(); !ok {
		t.Fatal("a publish-autonomy run that read nothing was not publishable")
	}
	if err := s.Retrieve("live", "", ""); err != nil {
		t.Fatal(err)
	}
	if !s.Tainted() {
		t.Fatal("reading stored content did not taint the run")
	}
	ok, why := s.Publishable()
	if ok {
		t.Fatal("a run downstream of untrusted content published itself")
	}
	if !strings.Contains(why, "person") {
		t.Errorf("the refusal does not say who decides: %q", why)
	}
}

// Approval cannot be escaped, and neither can autonomy.
func TestPublishingRequiresBothAutonomyAndApproval(t *testing.T) {
	draft := Manifest{
		Name: "drafter", Kind: KindTask, Purpose: "write",
		Capabilities: []string{"write_page"}, Autonomy: AutonomyDraft,
		Budget: Budget{Steps: 5, Tools: 2, Duration: Duration(time.Hour)},
	}
	if ok, _ := NewSession(draft, nil).Publishable(); ok {
		t.Error("a draft-autonomy run was publishable")
	}

	needsPerson := draft
	needsPerson.Autonomy = AutonomyPublish
	needsPerson.HumanApproval = true
	if ok, _ := NewSession(needsPerson, nil).Publishable(); ok {
		t.Error("a run requiring approval published without one")
	}
}

// Refusals are kept, because "it tried to publish four times" is a finding and
// "12 refusals" is a number.
func TestRefusalsAreRecordedForTheLog(t *testing.T) {
	s := testSession(t, KindRetrieval)
	for range 3 {
		_ = s.Authorize("publish")
	}
	got := s.Refusals()
	if len(got) != 3 {
		t.Fatalf("recorded %d refusals, want 3", len(got))
	}
	for _, r := range got {
		if r.Op != "publish" || r.Agent != "under-test" {
			t.Errorf("a refusal lost its detail: %+v", r)
		}
	}
}

// The budget is correct when a supervisor runs delegates in parallel.
//
// A budget that only holds single-threaded is wrong exactly when the agent is
// being most expensive. Run with -race.
func TestTheBudgetHoldsUnderConcurrency(t *testing.T) {
	const limit = 50
	m := Manifest{
		Name: "parallel", Kind: KindSupervisor, Purpose: "fan out",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyDraft,
		Budget: Budget{Steps: limit, Tools: 5, Duration: Duration(time.Hour)},
	}
	s := NewSession(m, nil)

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Authorize("read_page"); err == nil {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowed != limit {
		t.Errorf("%d operations were allowed against a budget of %d", allowed, limit)
	}
}
