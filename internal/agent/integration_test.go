// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

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
	// A well-formed one is refused too, and for the other reason: nothing in
	// this build calls a process integration. The rules below still fire
	// first, so a malformed declaration gets its own specific error rather
	// than the generic one — which is why the kind check is last in Validate
	// and not first.
	b := base()
	err := b.Validate()
	if err == nil {
		t.Fatal("a process integration validated, and nothing executes one")
	}
	if !strings.Contains(err.Error(), "nothing in this build calls one") {
		t.Errorf("a well-formed process integration was refused for the "+
			"wrong reason: %v", err)
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

func TestAGatewayPolicyMeansWhatItSays(t *testing.T) {
	base := func() Integration {
		return Integration{Name: "tracker", Kind: IntegrationMCP, Purpose: "file issues", Endpoint: "tracker.example",
			Uses: []string{"create_issue"}, Writes: true, Gateway: &GatewayPolicy{Role: "author"}}
	}
	ok := base()
	if err := ok.Validate(); err != nil || ok.Gateway.DailyLimit() != DefaultGatewayDaily {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Integration){
		"a reader offered writes": func(in *Integration) { in.Gateway.Role = "reader" },
		"no such role":            func(in *Integration) { in.Gateway.Role = "owner" },
		"asks about another tool": func(in *Integration) { in.Gateway.Ask = []string{"delete_repo"} },
		"too many calls":          func(in *Integration) { in.Gateway.Daily = 1000000 },
		"not an MCP server": func(in *Integration) {
			in.Kind, in.Endpoint, in.Command, in.Digest = IntegrationProcess, "", "/usr/bin/x", "sha256:"+strings.Repeat("a", 64)
		},
	} {
		in := base()
		change(&in)
		if err := in.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	in := base()
	in.Writes, in.Gateway.Role, in.Gateway.Ask, in.Gateway.Daily = false, "reader", []string{"create_issue"}, 20
	if err := in.Validate(); err != nil || !in.Gateway.Asks("create_issue") || in.Gateway.Asks("x") || in.Gateway.DailyLimit() != 20 {
		t.Fatalf("%v", err)
	}
}

// A server inside the network is declared with its port, its path and the
// range it is in; each is checked for what it can mean.
func TestAServerOnTheOwnNetworkIsDeclaredNarrowly(t *testing.T) {
	in := mcpIntegration()
	in.Endpoint, in.Port, in.Path = "tools.corp.example", 8443, "/mcp"
	in.Reach = []string{"10.20.0.0/16", "10.30.4.5"}
	if err := in.Validate(); err != nil {
		t.Fatalf("a narrow declaration was refused: %v", err)
	}
	if got, want := in.URL(), "https://tools.corp.example:8443/mcp"; got != want {
		t.Errorf("URL %q, want %q", got, want)
	}

	for name, change := range map[string]func(*Integration){
		"metadata":    func(in *Integration) { in.Reach = []string{"169.254.169.254/32"} },
		"all of it":   func(in *Integration) { in.Reach = []string{"0.0.0.0/0"} },
		"public":      func(in *Integration) { in.Reach = []string{"8.8.8.0/24"} },
		"not a range": func(in *Integration) { in.Reach = []string{"corp"} },
		"too many": func(in *Integration) {
			in.Reach = strings.Split("10.0.0.0/24 10.0.1.0/24 10.0.2.0/24 10.0.3.0/24 10.0.4.0/24 10.0.5.0/24 10.0.6.0/24 10.0.7.0/24 10.0.8.0/24", " ")
		},
		"port":     func(in *Integration) { in.Port = 70000 },
		"query":    func(in *Integration) { in.Path = "/mcp?x=1" },
		"escape":   func(in *Integration) { in.Path = "/m%63p" },
		"climbs":   func(in *Integration) { in.Path = "/a/../admin" },
		"no slash": func(in *Integration) { in.Path = "mcp" },
		"private, undeclared": func(in *Integration) {
			in.Endpoint, in.Reach = "10.20.1.2", nil
		},
		"metadata literal": func(in *Integration) {
			in.Endpoint, in.Reach = "169.254.169.254", []string{"10.0.0.0/8"}
		},
	} {
		bad := mcpIntegration()
		change(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	lit := mcpIntegration()
	lit.Endpoint, lit.Reach = "10.20.1.2", []string{"10.20.0.0/16"}
	if err := lit.Validate(); err != nil {
		t.Errorf("a private address inside its declared range was refused: %v", err)
	}
	if got := mcpIntegration().URL(); got != "https://mcp.tracker.example.com/" {
		t.Errorf("a plain declaration's URL is %q", got)
	}
	if got := mcpIntegration().Where(); got != "mcp.tracker.example.com" {
		t.Errorf("a plain declaration reads as %q", got)
	}
	if got := in.Where(); got != "tools.corp.example:8443/mcp" {
		t.Errorf("a declaration inside the network reads as %q", got)
	}
}
