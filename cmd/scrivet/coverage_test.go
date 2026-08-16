package main

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// Every capability has to be reachable from the interface people actually use.
//
// This exists because the gap got large without anybody noticing: thirty-nine
// commands on the command line, about ten areas in the admin, and seven tools
// over MCP. Each feature was built, tested and shipped correctly — on one
// surface — and "the GUI comes later" turned out to mean it did not come.
//
// The table below is the answer, and the point is that it is a table. A gap
// with a written reason is a decision; a gap with nothing next to it is an
// oversight, and this test cannot tell them apart unless somebody writes the
// reason down. Adding a command means adding a row, and the row is where you
// notice you have built something nobody can see.
type surfaces struct {
	// GUI is the admin path that reaches this, or empty with a reason.
	GUI string
	// MCP is the tool name, or empty with a reason.
	MCP string
	// Why explains any gap. Required whenever GUI or MCP is empty.
	Why string
}

var coverage = map[string]surfaces{
	// -- reachable everywhere it should be ------------------------------------
	"add":        {GUI: "/page/", MCP: "write_page"},
	"diff":       {GUI: "/", MCP: "diff"},
	"publish":    {GUI: "/publish", MCP: "publish"},
	"rollback":   {GUI: "/rollback"},
	"log":        {GUI: "/history"},
	"auditlog":   {GUI: "/logs"},
	"review":     {GUI: "/review"},
	"provenance": {GUI: "/provenance", MCP: "check_provenance"},
	"posture":    {GUI: "/security"},
	"auth":       {GUI: "/people"},
	"token":      {GUI: "/people"},
	"records":    {GUI: "/records"},
	"record":     {GUI: "/records"},
	"a11y":       {GUI: "/page/", MCP: "check_accessibility"},

	// -- built, and not yet visible -------------------------------------------
	//
	// Each of these is a real gap with a real cost, listed rather than left to
	// be discovered. They are the work queue, in rough order of how much of the
	// product is invisible without them.
	"config":     {GUI: "/settings"},
	"type":       {Why: "GAP: content types define what may be stored and cannot be seen"},
	"types":      {Why: "GAP: same as type"},
	"env":        {Why: "GAP: environments and promotion are terminal-only"},
	"media":      {Why: "GAP: uploads cannot be made from the interface people use"},
	"scan":       {Why: "GAP: the security scanner has no screen"},
	"csp":        {Why: "GAP: the generated policy is not shown anywhere"},
	"schedule":   {Why: "GAP: scheduled publishing is invisible"},
	"lang":       {Why: "GAP: languages are terminal-only"},
	"lock":       {Why: "GAP: locks are advisory and unlistable in the admin"},
	"ext":        {Why: "GAP: extensions are registered from a terminal only"},
	"webhook":    {Why: "GAP: webhooks are terminal-only"},
	"vault":      {Why: "GAP: encryption at rest is terminal-only"},
	"compliance": {Why: "GAP: the SBOM and crypto inventory have no screen"},
	"export":     {Why: "GAP: no way to export from the interface"},
	"import":     {Why: "GAP: no way to import from the interface"},
	"verify":     {Why: "GAP: integrity checking is terminal-only"},
	"agents":     {Why: "GAP: agent activity is terminal-only"},
	"anchor":     {Why: "GAP: timestamping is terminal-only"},
	"timestamp":  {Why: "GAP: as anchor"},
	"stamp":      {Why: "GAP: as anchor"},
	"siem":       {Why: "GAP: export to a SIEM is terminal-only"},
	"assist":     {Why: "GAP: the assistant has no screen"},
	"template":   {Why: "GAP: starters can only be applied from a terminal"},
	"templates":  {Why: "GAP: as template"},
	"oidc":       {Why: "GAP: identity provider setup is terminal-only"},

	// -- deliberately not in the interface ------------------------------------
	"init": {Why: "creates the store, which is what you do before there is an " +
		"interface to open"},
	"serve": {Why: "starts the interface; a button inside it could not"},
	"site":  {Why: "starts the public server, for the same reason"},
	"logd":  {Why: "runs as another account and must not be startable from this one"},
	"mcp":   {Why: "is the machine interface; it does not appear inside itself"},
	"audit": {Why: "reads template files given as arguments and never opens the store"},
	"render": {Why: "renders to a file for a pipeline; the admin previews " +
		"instead, at /preview/"},
	"config-show":  {Why: "not a command"},
	"help":         {Why: "prints usage"},
	"-h":           {Why: "prints usage"},
	"--help":       {Why: "prints usage"},
	"version":      {Why: "prints a version"},
	"locales":      {Why: "an alias of lang"},
	"environments": {Why: "an alias of env"},
	"webhooks":     {Why: "an alias of webhook"},
	"extensions":   {Why: "an alias of ext"},
	"prov":         {Why: "an alias of provenance"},
	"locks":        {Why: "an alias of lock"},
}

// Every dispatched command must appear, with a route or a reason.
func TestEveryCommandIsReachableOrExplained(t *testing.T) {
	cmds := dispatchedCommands(t)
	if len(cmds) < 30 {
		t.Fatalf("found only %d commands; the parse is wrong and a test that "+
			"sees nothing passes", len(cmds))
	}
	var undeclared []string
	for _, c := range cmds {
		s, ok := coverage[c]
		if !ok {
			undeclared = append(undeclared, c)
			continue
		}
		if s.GUI == "" && strings.TrimSpace(s.Why) == "" {
			t.Errorf("%q has no admin route and no reason. Either add the "+
				"screen or write down why it does not need one — an "+
				"unexplained gap is indistinguishable from an oversight, "+
				"which is how this one got to twenty-six.", c)
		}
	}
	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		t.Errorf("these commands are dispatched and not in the coverage "+
			"table:\n  %s\nAdding a command means adding a row, which is "+
			"where you notice you have built something nobody can see.",
			strings.Join(undeclared, "\n  "))
	}
}

// Any route the table claims must actually be served, or the table is a
// description of a product that does not exist.
func TestEveryClaimedRouteIsServed(t *testing.T) {
	served := map[string]bool{}
	for _, r := range adminRoutes(t) {
		served[r] = true
	}
	if len(served) < 10 {
		t.Fatalf("found %d admin routes; the parse is wrong", len(served))
	}
	for cmd, s := range coverage {
		if s.GUI == "" {
			continue
		}
		if !served[s.GUI] {
			t.Errorf("%q claims the admin serves %q and it does not",
				cmd, s.GUI)
		}
	}
}

// The size of the gap, reported rather than asserted.
//
// No threshold, because a number that fails the build would be turned into a
// number that passes it. This prints, so that anybody running the suite sees
// how much of the product is invisible.
func TestReportHowMuchIsNotInTheInterface(t *testing.T) {
	var gaps []string
	for cmd, s := range coverage {
		if strings.HasPrefix(s.Why, "GAP:") {
			gaps = append(gaps, cmd+" — "+strings.TrimPrefix(s.Why, "GAP: "))
		}
	}
	sort.Strings(gaps)
	t.Logf("%d capabilities are not in the admin interface:", len(gaps))
	for _, g := range gaps {
		t.Logf("    %s", g)
	}
}

// adminRoutes reads the mux registrations out of the admin package.
func adminRoutes(t *testing.T) []string {
	t.Helper()
	body := readFile(t, "../../internal/admin/server.go")
	var out []string
	for _, line := range strings.Split(body, "\n") {
		i := strings.Index(line, `mux.HandleFunc("`)
		if i < 0 {
			i = strings.Index(line, `mux.Handle("`)
			if i < 0 {
				continue
			}
		}
		rest := line[i:]
		start := strings.Index(rest, `"`) + 1
		end := strings.Index(rest[start:], `"`)
		if end <= 0 {
			continue
		}
		out = append(out, rest[start:start+end])
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
