package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The operations the machine interface actually registers, for tests that need
// a capability set to validate against.
func knownOps() map[string]bool {
	return map[string]bool{
		"read_page": true, "list_pages": true, "write_page": true,
		"write_record": true, "publish": true, "diff": true,
		"run_listing": true, "list_terms": true, "agent_activity": true,
		"check_accessibility": true, "check_translations": true,
	}
}

// Every template validates as written.
//
// A template that has to be edited before it passes teaches people to edit
// until the error stops, which is the opposite of what a starting point is for.
func TestEveryTemplateValidates(t *testing.T) {
	if len(Catalogue()) < 8 {
		t.Fatalf("only %d templates; the catalogue is incomplete", len(Catalogue()))
	}
	for _, tpl := range Catalogue() {
		m, err := New(tpl.Manifest.Kind, "test-agent", knownOps())
		if err != nil {
			t.Errorf("the %s template does not validate: %v", tpl.Manifest.Kind, err)
			continue
		}
		if m.Budget.Steps <= 0 {
			t.Errorf("%s has no step budget", tpl.Manifest.Kind)
		}
		if strings.TrimSpace(tpl.When) == "" || strings.TrimSpace(tpl.Research) == "" {
			t.Errorf("%s has no When or Research note; a template nobody can "+
				"tell apart from its neighbour is one somebody picks at random",
				tpl.Manifest.Kind)
		}
	}
}

// A template is a starting point, not shared state.
//
// The manifests live in a package-level map, so returning them without copying
// means every agent made from a template aliases the same capability slice —
// and widening one agent widens the template and every sibling made afterwards.
func TestATemplateIsNotSharedWithWhatIsMadeFromIt(t *testing.T) {
	a, err := New(KindRetrieval, "one", knownOps())
	if err != nil {
		t.Fatal(err)
	}
	a.Capabilities[0] = "write_page"

	b, err := New(KindRetrieval, "two", knownOps())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range b.Capabilities {
		if c == "write_page" {
			t.Fatal("editing one agent's capabilities changed the template, " +
				"so the next agent made from it silently gained a write")
		}
	}
}

// The retrieval archetype cannot write, and cannot read the draft.
//
// These two are the whole security argument for the shape most people will
// reach for first: a support bot that can be talked into writing is a
// vandalism channel, and one reading the draft is a disclosure channel.
func TestTheRetrievalBotCannotWriteOrSeeUnpublishedContent(t *testing.T) {
	m, err := New(KindRetrieval, "support", knownOps())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range m.Capabilities {
		if IsWrite(c) {
			t.Errorf("the retrieval template holds %q, which writes", c)
		}
	}
	if m.Autonomy != AutonomyPropose {
		t.Errorf("the retrieval template is %s, want propose", m.Autonomy)
	}
	if m.Retrieval.Ref != "live" {
		t.Errorf("the retrieval template reads %q; a bot answering from the "+
			"draft is a disclosure with a friendly interface", m.Retrieval.Ref)
	}
	if m.Memory.Any() {
		t.Error("the retrieval template remembers; the stateless version has " +
			"no privacy surface and is the right default")
	}
}

// Autonomy and capabilities have to agree.
func TestAProposeOnlyAgentCannotHoldAWrite(t *testing.T) {
	m := Manifest{
		Name: "sneaky", Kind: KindRetrieval, Purpose: "look harmless",
		Capabilities: []string{"read_page", "write_page"},
		Autonomy:     AutonomyPropose,
		Budget:       Budget{Steps: 5, Tools: 5, Duration: Duration(time.Minute)},
	}
	err := m.Validate(knownOps())
	if err == nil {
		t.Fatal("a propose-only agent was allowed to hold write_page, so a " +
			"manifest reviewed as read-only can write")
	}
	if !strings.Contains(err.Error(), "write") {
		t.Errorf("the refusal does not explain the conflict: %v", err)
	}
}

// Publishing carries a person, always.
func TestPublishAutonomyForcesHumanApproval(t *testing.T) {
	m := Manifest{
		Name: "publisher", Kind: KindTask, Purpose: "ship it",
		Capabilities: []string{"publish"},
		Autonomy:     AutonomyPublish,
		Budget:       Budget{Steps: 5, Tools: 5, Duration: Duration(time.Minute)},
	}
	if err := m.Validate(knownOps()); err != nil {
		t.Fatal(err)
	}
	if !m.HumanApproval {
		t.Error("an agent that can publish does not require approval; " +
			"publishing is the one action with an outside observer")
	}
}

// A capability nothing offers is a claim, not a configuration.
func TestACapabilityNoInterfaceOffersIsRefused(t *testing.T) {
	m := Manifest{
		Name: "hopeful", Kind: KindTask, Purpose: "do a thing",
		Capabilities: []string{"delete_everything"},
		Autonomy:     AutonomyDraft,
		Budget:       Budget{Steps: 5, Tools: 5, Duration: Duration(time.Minute)},
	}
	if err := m.Validate(knownOps()); err == nil {
		t.Fatal("a capability no interface registers was accepted; it would " +
			"read as working configuration until the day it was needed")
	}
}

// Memory needs an expiry, and cannot outlive the ceiling.
func TestMemoryNeedsARetentionPeriod(t *testing.T) {
	base := func() Manifest {
		return Manifest{
			Name: "rememberer", Kind: KindArchivist, Purpose: "remember",
			Capabilities: []string{"read_page"},
			Autonomy:     AutonomyPropose,
			Budget:       Budget{Steps: 5, Tools: 5, Duration: Duration(time.Minute)},
		}
	}

	m := base()
	m.Memory = Memory{Episodic: true} // no Retain
	if err := m.Validate(knownOps()); err == nil {
		t.Error("an agent was allowed to remember with no retention period")
	}

	m = base()
	m.Memory = Memory{Episodic: true, Retain: MaxRetain + Duration(time.Hour)}
	if err := m.Validate(knownOps()); err == nil {
		t.Error("an agent was allowed to remember past the ceiling")
	}
}

// A tool names one host, and never a wildcard.
//
// The host allowlist is the exfiltration control. A wildcard makes it a promise
// about DNS that whoever registers a subdomain gets to break.
func TestAToolHostIsExactAndPurposeful(t *testing.T) {
	base := func(host, purpose string) Manifest {
		return Manifest{
			Name: "caller", Kind: KindOperator, Purpose: "run errands",
			Capabilities: []string{"read_page"},
			Autonomy:     AutonomyPropose,
			Tools:        []Tool{{Name: "crm", Host: host, Purpose: purpose}},
			Budget:       Budget{Steps: 5, Tools: 5, Duration: Duration(time.Minute)},
		}
	}
	for _, bad := range []string{"*.example.com", "https://example.com/x", "example.com:443", ""} {
		m := base(bad, "look things up")
		if err := m.Validate(knownOps()); err == nil {
			t.Errorf("the host %q was accepted", bad)
		}
	}
	m := base("api.example.com", "")
	if err := m.Validate(knownOps()); err == nil {
		t.Error("a tool with no stated purpose was accepted")
	}
	m = base("api.example.com", "look up a customer record")
	if err := m.Validate(knownOps()); err != nil {
		t.Errorf("a well-formed tool was refused: %v", err)
	}
}

// An unbounded agent is refused.
func TestAnAgentWithNoBudgetIsRefused(t *testing.T) {
	m := Manifest{
		Name: "forever", Kind: KindAutonomous, Purpose: "keep going",
		Capabilities: []string{"read_page"},
		Autonomy:     AutonomyPropose,
	}
	if err := m.Validate(knownOps()); err == nil {
		t.Fatal("an agent with no budget was accepted; a goal-seeking one in " +
			"a loop is the ordinary way an unbounded bill arrives")
	}
}

// Delegation narrows and never widens.
//
// Without this a supervisor is a way to launder capability: delegate to an
// agent that holds more, and the restriction on the supervisor was decoration.
func TestDelegationCannotWiden(t *testing.T) {
	parent := Manifest{
		Name: "lead", Kind: KindSupervisor, Purpose: "delegate",
		Capabilities: []string{"read_page", "list_pages"},
		Autonomy:     AutonomyDraft,
		Memory:       Memory{Episodic: true, Retain: hours(24)},
		Budget:       Budget{Steps: 10, Tools: 5, Duration: mins(5)},
	}
	greedy := Manifest{
		Name: "worker", Kind: KindTask, Purpose: "do more than allowed",
		Capabilities: []string{"read_page", "write_page", "publish"},
		Autonomy:     AutonomyPublish,
		Memory:       Memory{Episodic: true, Semantic: true, Retain: MaxRetain},
		Budget:       Budget{Steps: 999, Tools: 999, Duration: mins(600)},
	}

	got := parent.Narrow(greedy)

	for _, c := range got.Capabilities {
		if c == "write_page" || c == "publish" {
			t.Errorf("the delegate kept %q, which its supervisor does not hold", c)
		}
	}
	if got.Autonomy != AutonomyDraft {
		t.Errorf("the delegate is %s and its supervisor is draft", got.Autonomy)
	}
	if got.Budget.Steps != 10 || got.Budget.Tools != 5 {
		t.Errorf("the delegate's budget %+v exceeds its supervisor's", got.Budget)
	}
	if got.Memory.Semantic {
		t.Error("the delegate remembers a tier its supervisor does not")
	}
	if got.Memory.Retain > hours(24) {
		t.Errorf("the delegate retains for %s, longer than its supervisor",
			got.Memory.Retain)
	}
}

// Approval is sticky through delegation.
func TestADelegateCannotEscapeAnApprovalRequirement(t *testing.T) {
	parent := Manifest{
		Name: "lead", Kind: KindSupervisor, Purpose: "delegate",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyDraft,
		HumanApproval: true,
		Budget:        Budget{Steps: 10, Tools: 5, Duration: mins(5)},
	}
	child := Manifest{
		Name: "worker", Kind: KindTask, Purpose: "work",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyDraft,
		HumanApproval: false,
		Budget:        Budget{Steps: 5, Tools: 5, Duration: mins(5)},
	}
	if !parent.Narrow(child).HumanApproval {
		t.Error("a delegate escaped its supervisor's approval requirement")
	}
}

// Only a supervisor delegates.
func TestOnlyASupervisorDelegates(t *testing.T) {
	m := Manifest{
		Name: "pretender", Kind: KindTask, Purpose: "do a thing",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyDraft,
		Delegates: []string{"somebody"},
		Budget:    Budget{Steps: 5, Tools: 5, Duration: mins(5)},
	}
	if err := m.Validate(knownOps()); err == nil {
		t.Error("a non-supervisor was allowed to delegate")
	}
}

// A manifest round-trips through JSON, durations included.
//
// It is stored as a content-addressed object, so it has to come back as what
// went in — and a duration that serialises as a nanosecond count is unreadable
// in a stored object somebody is trying to review.
func TestAManifestRoundTripsReadably(t *testing.T) {
	m, err := New(KindArchivist, "memory", knownOps())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"2160h0m0s"`) {
		t.Errorf("the retention period is not readable in the stored form: %s", raw)
	}
	var back Manifest
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Memory.Retain != m.Memory.Retain {
		t.Errorf("retention came back as %s, sent %s", back.Memory.Retain, m.Memory.Retain)
	}
	if len(back.Capabilities) != len(m.Capabilities) {
		t.Error("the capability list did not survive the round trip")
	}
}
