package a2a

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

func known() map[string]bool {
	return map[string]bool{
		"read_page": true, "list_pages": true, "write_page": true,
		"write_record": true, "publish": true, "diff": true,
		"run_listing": true, "list_terms": true,
	}
}

func opts() Options {
	return Options{
		SiteName: "Marginalia", BaseURL: "https://shop.example",
		Version: "1.0.0", Provider: "Marginalia Ltd",
	}
}

func retrieval(t *testing.T) agent.Manifest {
	t.Helper()
	m, err := agent.New(agent.KindRetrieval, "support", known())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The card describes the gate, and the two cannot disagree.
//
// This is the whole reason the card is generated rather than written: an API
// Evangelist survey in July 2026 found most published agent cards are not valid
// A2A, which is what happens when a description lives beside the thing it
// describes instead of being derived from it.
func TestTheCardSaysWhatTheSessionEnforces(t *testing.T) {
	m := retrieval(t)
	c := From(map[string]agent.Manifest{"support": m}, known(), opts())
	if err := c.Validate(); err != nil {
		t.Fatalf("the generated card is not valid A2A: %v", err)
	}

	g, ok := c.Governance["support"]
	if !ok {
		t.Fatal("no governance published for the only skill")
	}

	// Every capability the card advertises is one the session actually grants,
	// and every one it withholds is actually refused. Checked against a live
	// session, not against the manifest a second time.
	sess := agent.NewSession(m, nil)
	for _, cap := range g.Capabilities {
		if err := sess.Authorize(cap); err != nil {
			t.Errorf("the card advertises %q and the session refuses it: %v", cap, err)
		}
	}
	fresh := agent.NewSession(m, nil)
	for _, absent := range []string{"publish", "write_page", "write_record"} {
		if contains(g.Capabilities, absent) {
			continue
		}
		if err := fresh.Authorize(absent); err == nil {
			t.Errorf("the card withholds %q and the session allows it", absent)
		}
	}

	// Writes is derived, so it cannot contradict the list above.
	if g.Writes {
		t.Error("a retrieval agent is published as writing")
	}
	if g.Autonomy != string(m.Autonomy) {
		t.Errorf("autonomy published as %q, manifest says %q", g.Autonomy, m.Autonomy)
	}
	if g.Budget.Steps != m.Budget.Steps {
		t.Errorf("budget published as %d steps, manifest says %d",
			g.Budget.Steps, m.Budget.Steps)
	}
}

// A writing agent is published as one, and a reading agent is not.
//
// Writes is derived from the capability list rather than declared, so it cannot
// contradict it — but a test that only ever looked at a retrieval agent could
// not tell the difference between "derived correctly" and "hard-coded false".
// A sabotage making it always false passed the first version of this suite.
func TestWritesIsDerivedFromTheCapabilitiesNotAssumed(t *testing.T) {
	read := retrieval(t)

	// Built directly rather than from a template, so the fixture holds a write
	// capability by construction and the test cannot pass because a template
	// happened to change.
	write := agent.Manifest{
		Name: "editor", Kind: agent.KindTask,
		Purpose:      "Draft product copy from an outline.",
		Capabilities: []string{"read_page", "write_page"},
		Autonomy:     agent.AutonomyDraft,
		Budget: agent.Budget{Steps: 6, Tools: 2,
			Duration: agent.Duration(time.Minute)},
	}
	if err := write.Validate(known()); err != nil {
		t.Fatalf("the writing fixture does not validate: %v", err)
	}

	c := From(map[string]agent.Manifest{
		"support": read, "editor": write}, known(), opts())

	if c.Governance["support"].Writes {
		t.Error("a read-only agent is published as writing")
	}
	if !c.Governance["editor"].Writes {
		t.Error("an agent holding a write capability is published as " +
			"read-only, so a caller would delegate to it believing its " +
			"output cannot change anything")
	}
}

// A manifest this build would refuse to run is not advertised.
//
// The direction that matters: a caller delegating to a skill that cannot start
// has been misled by the card, which is worse than finding no card at all.
func TestAManifestThatWouldNotRunIsNotAdvertised(t *testing.T) {
	good := retrieval(t)
	// A capability no interface offers. Constructed directly, which is the
	// shape a hand-edited file produces.
	bad := good
	bad.Name = "stale"
	bad.Capabilities = []string{"read_page", "operate_the_lift"}

	c := From(map[string]agent.Manifest{"support": good, "stale": bad},
		known(), opts())

	if _, there := c.Governance["stale"]; there {
		t.Error("an unrunnable manifest was published with governance")
	}
	for _, s := range c.Skills {
		if s.ID == "stale" {
			t.Error("an unrunnable manifest was advertised as a skill")
		}
	}
	if len(c.Skills) != 1 {
		t.Errorf("want one skill, got %d", len(c.Skills))
	}
	if err := c.Validate(); err != nil {
		t.Errorf("dropping it left the card invalid: %v", err)
	}
}

// The card refuses to be served rather than being served wrong.
func TestValidateCatchesTheWaysACardGoesWrong(t *testing.T) {
	base := From(map[string]agent.Manifest{"support": retrieval(t)}, known(), opts())

	for name, break_ := range map[string]func(*Card){
		"no protocol version": func(c *Card) { c.ProtocolVersion = "" },
		"no name":             func(c *Card) { c.Name = "" },
		"plain http url":      func(c *Card) { c.URL = "http://shop.example/x" },
		"relative url":        func(c *Card) { c.URL = "/.well-known/agent-card.json" },
		"no transport":        func(c *Card) { c.PreferredTransport = "" },
		"no input modes":      func(c *Card) { c.DefaultInputModes = nil },
		"nil skills":          func(c *Card) { c.Skills = nil },
		"skill with no id": func(c *Card) {
			c.Skills[0].ID = ""
		},
		"skill with no description": func(c *Card) {
			c.Skills[0].Description = ""
		},
		"duplicate skill id": func(c *Card) {
			c.Skills = append(c.Skills, c.Skills[0])
		},
		"skill with no governance": func(c *Card) {
			delete(c.Governance, "support")
		},
		"governance for a skill nobody offers": func(c *Card) {
			c.Governance["ghost"] = c.Governance["support"]
		},
		"no budget": func(c *Card) {
			g := c.Governance["support"]
			g.Budget.Steps = 0
			c.Governance["support"] = g
		},
	} {
		c := clone(t, base)
		break_(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: served anyway", name)
		}
	}

	// And the untouched card is valid, or every case above passes for the
	// wrong reason.
	if err := base.Validate(); err != nil {
		t.Fatalf("the unbroken card is invalid, so this test proves nothing: %v", err)
	}
}

// Loopback over http is allowed, because that is where somebody develops.
func TestLoopbackIsAllowedOverPlainHTTP(t *testing.T) {
	o := opts()
	o.BaseURL = "http://127.0.0.1:8081"
	c := From(map[string]agent.Manifest{"support": retrieval(t)}, known(), o)
	if err := c.Validate(); err != nil {
		t.Errorf("a development card on loopback was refused: %v", err)
	}
}

// The card is JSON a stranger can parse, and the governance extension is keyed
// where a consumer that does not know it can skip it.
func TestTheCardRoundTripsAsJSON(t *testing.T) {
	c := From(map[string]agent.Manifest{"support": retrieval(t)}, known(), opts())
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"protocolVersion", "name", "url", "preferredTransport", "version",
		"capabilities", "defaultInputModes", "defaultOutputModes", "skills",
	} {
		if _, there := back[required]; !there {
			t.Errorf("the serialised card has no %q", required)
		}
	}
	if _, there := back["extensions"]; !there {
		t.Error("the governance extension did not serialise")
	}
	// Capabilities are published as false rather than omitted: a card claiming
	// streaming it does not have is what makes published cards untrustworthy.
	caps, _ := back["capabilities"].(map[string]any)
	if caps["streaming"] != false {
		t.Errorf("streaming published as %v; this server does not implement it",
			caps["streaming"])
	}
}

// Memory is absent when there is none, and stated with a retention when there is.
//
// "No memory" and "memory with no stated retention" must not look the same to a
// caller deciding whether to send it anything.
func TestMemoryIsAbsentOrComplete(t *testing.T) {
	plain := retrieval(t)
	c := From(map[string]agent.Manifest{"support": plain}, known(), opts())
	if c.Governance["support"].Memory != nil && !plain.Memory.Episodic {
		t.Error("memory was published for an agent that keeps none")
	}

	remembers := plain
	remembers.Memory = agent.Memory{
		Episodic: true, Retain: agent.Duration(72 * time.Hour)}
	c2 := From(map[string]agent.Manifest{"support": remembers}, known(), opts())
	m := c2.Governance["support"].Memory
	if m == nil {
		t.Fatal("an agent that keeps episodic memory published none")
	}
	if m.Retain == "" || m.Retain == "0s" {
		t.Errorf("memory published with retention %q, which is the state that "+
			"makes it a personal-data store nobody agreed to", m.Retain)
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func clone(t *testing.T, c Card) Card {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var out Card
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	// json.Unmarshal leaves a nil map when the key is absent; the tests mutate
	// it, so give it back.
	if out.Governance == nil {
		out.Governance = map[string]Governance{}
	}
	return out
}

var _ = strings.TrimSpace
