package agent

import (
	"strings"
	"testing"
)

func mcpIntegration() Integration {
	return Integration{
		Name: "issues", Kind: IntegrationMCP, Enabled: true,
		Purpose:  "file and read issues on the tracker",
		Endpoint: "mcp.tracker.example.com",
		Uses:     []string{"create_issue", "list_issues"},
	}
}

// Nothing is reachable until somebody turns it on.
//
// The whole point of making integrations optional: a customer who wants none
// carries none, and the attack surface of a feature they did not ask for is
// not theirs.
func TestNothingIsEnabledByDefault(t *testing.T) {
	in := mcpIntegration()
	in.Enabled = false
	s := Integrations{Declared: []Integration{in}}

	if got := s.Enabled(); len(got) != 0 {
		t.Fatalf("%d integrations were reachable without being enabled", len(got))
	}
	if _, err := s.Resolve("create_issue"); err == nil {
		t.Error("a disabled integration resolved a tool")
	}
	// And a struct somebody pasted from an example is off, because the zero
	// value of Enabled is false.
	var pasted Integration
	if pasted.Enabled {
		t.Error("the zero value of an integration is enabled")
	}
}

// Running a local program needs a second, separate decision.
func TestAProcessIntegrationNeedsTheInstallToAllowProcesses(t *testing.T) {
	proc := Integration{
		Name: "legacy", Kind: IntegrationProcess, Enabled: true,
		Purpose: "talk to the old system",
		Command: "/opt/bridge/run",
		Digest:  "sha256:" + strings.Repeat("a", 64),
		Uses:    []string{"lookup"},
	}
	s := Integrations{Declared: []Integration{proc}}

	if got := s.Enabled(); len(got) != 0 {
		t.Error("a process integration ran without the install allowing " +
			"processes; that is arbitrary code execution beside the store")
	}
	s.AllowProcess = true
	if got := s.Enabled(); len(got) != 1 {
		t.Error("allowing processes did not enable the declared one")
	}
}

// A local program is pinned, or it is refused.
func TestAProcessIntegrationMustBePinnedAndAbsolute(t *testing.T) {
	base := func() Integration {
		return Integration{
			Name: "bridge", Kind: IntegrationProcess, Enabled: true,
			Purpose: "bridge", Command: "/opt/bridge/run",
			Digest: "sha256:" + strings.Repeat("b", 64),
			Uses:   []string{"lookup"},
		}
	}
	b := base()
	if err := b.Validate(); err != nil {
		t.Fatalf("a well-formed process integration was refused: %v", err)
	}

	unpinned := base()
	unpinned.Digest = ""
	if err := unpinned.Validate(); err == nil {
		t.Error("an unpinned local program was accepted")
	}

	onPath := base()
	onPath.Command = "bridge"
	if err := onPath.Validate(); err == nil {
		t.Error("a command resolved from PATH was accepted; that is whichever " +
			"program happened to be there")
	}

	junk := base()
	junk.Digest = "sha256:not-a-digest"
	if err := junk.Validate(); err == nil {
		t.Error("a malformed digest was accepted")
	}
}

// The tool allow-list is the answer to tool poisoning.
//
// An MCP server can add a tool, or redefine one, after the day somebody decided
// to trust it. A client that calls whatever is advertised has delegated its
// capability list to a third party's next release.
func TestAnIntegrationCannotClaimEveryTool(t *testing.T) {
	in := mcpIntegration()
	in.Uses = nil
	if err := in.Validate(); err == nil {
		t.Error("an integration naming no tools was accepted, which means " +
			"whatever the far side offers")
	}

	in = mcpIntegration()
	in.Uses = []string{"*"}
	if err := in.Validate(); err == nil {
		t.Error("a wildcard tool list was accepted")
	}

	in = mcpIntegration()
	in.Uses = []string{"create_issue", "create_issue"}
	if err := in.Validate(); err == nil {
		t.Error("a duplicated tool name was accepted")
	}
}

// A tool the install did not name is not callable, even from a trusted server.
func TestOnlyNamedToolsResolve(t *testing.T) {
	s := Integrations{Declared: []Integration{mcpIntegration()}}

	if _, err := s.Resolve("create_issue"); err != nil {
		t.Fatalf("a named tool did not resolve: %v", err)
	}
	// The far side added this one last Tuesday.
	if _, err := s.Resolve("delete_project"); err == nil {
		t.Fatal("a tool the install never named resolved; the capability " +
			"list has been delegated to whoever ships the server")
	}
}

// Two integrations offering the same tool is refused, not resolved by order.
func TestAmbiguousToolsAreRefusedRatherThanOrdered(t *testing.T) {
	a := mcpIntegration()
	b := mcpIntegration()
	b.Name = "issues-backup"
	b.Endpoint = "mcp.other.example.com"
	s := Integrations{Declared: []Integration{a, b}}

	_, err := s.Resolve("create_issue")
	if err == nil {
		t.Fatal("an ambiguous tool resolved; which one ran would depend on " +
			"list order, and nobody reviewed the order")
	}
	if !strings.Contains(err.Error(), "issues") {
		t.Errorf("the refusal does not name the candidates: %v", err)
	}
}

// Endpoints follow the same exact-host rule as agent tools.
func TestAnIntegrationEndpointIsOneExactHost(t *testing.T) {
	for _, bad := range []string{
		"*.example.com", "https://example.com/api", "example.com:8443", "",
	} {
		in := mcpIntegration()
		in.Endpoint = bad
		if err := in.Validate(); err == nil {
			t.Errorf("the endpoint %q was accepted", bad)
		}
	}
}

// The kinds do not borrow each other's fields.
func TestTheKindsDoNotOverlap(t *testing.T) {
	in := mcpIntegration()
	in.Command = "/usr/bin/something"
	if err := in.Validate(); err == nil {
		t.Error("an mcp integration naming a command was accepted")
	}

	proc := Integration{
		Name: "p", Kind: IntegrationProcess, Purpose: "x",
		Command: "/opt/x", Digest: "sha256:" + strings.Repeat("c", 64),
		Endpoint: "example.com", Uses: []string{"t"},
	}
	if err := proc.Validate(); err == nil {
		t.Error("a process integration naming an endpoint was accepted")
	}
}

// Every declaration is validated, not only the enabled ones.
//
// A declaration that does not validate is a landmine for whoever enables it
// later, and "it was fine until I turned it on" is a report nobody can act on.
func TestDisabledDeclarationsAreStillValidated(t *testing.T) {
	broken := mcpIntegration()
	broken.Enabled = false
	broken.Endpoint = "*.wildcard.example.com"

	s := Integrations{Declared: []Integration{broken}}
	if err := s.Validate(); err == nil {
		t.Fatal("a broken declaration passed because it was disabled")
	}
}

// Two integrations cannot share a name.
func TestNamesAreUnique(t *testing.T) {
	s := Integrations{Declared: []Integration{mcpIntegration(), mcpIntegration()}}
	if err := s.Validate(); err == nil {
		t.Error("two integrations shared a name")
	}
}

// The enabled hosts are what an agent's tool allow-list can be built from.
func TestHostsReportsOnlyWhatIsEnabled(t *testing.T) {
	on := mcpIntegration()
	off := mcpIntegration()
	off.Name = "other"
	off.Endpoint = "off.example.com"
	off.Enabled = false

	s := Integrations{Declared: []Integration{on, off}}
	hosts := s.Hosts()
	if len(hosts) != 1 || hosts[0] != "mcp.tracker.example.com" {
		t.Errorf("hosts are %v; a disabled integration's host is reachable", hosts)
	}
}
