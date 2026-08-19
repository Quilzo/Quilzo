package main

import (
	"os"
	"regexp"
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
	// MCP are the operation names this command's capability is reachable
	// through, or empty with a reason in NoMCP. A list because the machine
	// interface is not one-to-one with the command line and pretending it is
	// would mean leaving operations out of the table to make the shape fit.
	MCP []string
	// Why explains a missing screen. Required whenever GUI is empty.
	Why string
	// NoMCP explains why this is not on the machine interface. Required
	// whenever MCP is empty, and required to be a real argument rather than a
	// shrug: this column sat unasserted through the whole first pass, which is
	// how it ended up describing seven operations against thirty-nine
	// commands.
	//
	// The line this project draws: anything that reads, and anything that
	// authors content, belongs on the agent surface. Anything that changes who
	// may do what, what code runs, or what the keys are, does not — because a
	// prompt injection in a page the agent is reading is a plausible route to
	// whatever the agent can call, and "it could grant itself a role" is a
	// sentence nobody should be able to write about their CMS.
	NoMCP string
}

var coverage = map[string]surfaces{
	// -- content, on all three surfaces ---------------------------------------
	"add":        {GUI: "/page/", MCP: []string{"write_page", "read_page", "list_pages"}},
	"diff":       {GUI: "/", MCP: []string{"diff"}},
	"publish":    {GUI: "/publish", MCP: []string{"publish"}},
	"provenance": {GUI: "/provenance", MCP: []string{"check_provenance"}},
	"a11y":       {GUI: "/page/", MCP: []string{"check_accessibility"}},
	"records":    {GUI: "/records", MCP: []string{"list_records", "list_collections"}},
	"record":     {GUI: "/records", MCP: []string{"write_record"}},
	"type":       {GUI: "/types", MCP: []string{"list_types"}},
	"types":      {GUI: "/types", MCP: []string{"list_types"}},
	"media":      {GUI: "/media", MCP: []string{"list_media"}},
	"env":        {GUI: "/publishing", MCP: []string{"pipeline_status"}},
	"schedule":   {GUI: "/publishing", MCP: []string{"pipeline_status"}},
	"lang":       {GUI: "/languages", MCP: []string{"check_translations"}},
	"scan":       {GUI: "/security/scan", MCP: []string{"scan_content"}},
	"verify":     {GUI: "/security/integrity", MCP: []string{"verify_store"}},
	"compliance": {GUI: "/security/inventory", MCP: []string{"inventory"}},
	"agents":     {GUI: "/security/agents", MCP: []string{"agent_activity"}},
	"agent": {GUI: "/agents",
		NoMCP: "declares what a model may do. An agent that can write an " +
			"agent manifest can write itself a wider one, which turns every " +
			"other capability boundary into a suggestion — this is the same " +
			"reason auth and token are off this surface, and it is the more " +
			"important instance of it"},
	"brand": {GUI: "/publishing",
		NoMCP: "the rules deciding what this business may claim. A model that " +
			"can edit them can delete the one standing between its own copy " +
			"and the public, which is the gate rather than a setting"},
	"peer": {GUI: "/transfer",
		NoMCP: "pairs this store with another and adopts what it sent. A " +
			"model that can add a peer can name one it controls and then " +
			"adopt it, which is a write endpoint assembled out of two reads"},
	"export":   {GUI: "/transfer", MCP: []string{"export_site"}},
	"ipfs":     {GUI: "/decentralised", MCP: []string{"content_id"}},
	"form":     {GUI: "/forms", NoMCP: "submissions are what members of the public typed; an agent that can read the postbag is a data breach with a tool call"},
	"forms":    {GUI: "/forms", NoMCP: "as form"},
	"listing":  {GUI: "/listings", MCP: []string{"run_listing"}},
	"listings": {GUI: "/listings", MCP: []string{"run_listing"}},
	"terms":    {GUI: "/structure", MCP: []string{"list_terms"}},
	"taxonomy": {GUI: "/structure", MCP: []string{"list_terms"}},
	"menu":     {GUI: "/structure", MCP: []string{"list_menus"}},
	"menus":    {GUI: "/structure", MCP: []string{"list_menus"}},

	// -- in the interface, and off the agent surface on purpose ---------------
	"rollback": {GUI: "/rollback",
		NoMCP: "moves what the public sees to a different commit. Publishing " +
			"forward runs every gate; rolling back runs none, because the " +
			"target already passed them once — which makes it the cheapest " +
			"way for an agent to serve old content and the one operation " +
			"where a person should be looking at the screen"},
	"log":      {GUI: "/history", NoMCP: "the diff and pipeline status answer what an agent needs; a full commit walk is a large amount of context for a question nobody asked"},
	"review":   {GUI: "/review", NoMCP: "is the human decision point; an agent has diff and check_accessibility, which are its two halves"},
	"posture":  {GUI: "/security", NoMCP: "is a list of exactly where this deployment's defences are thin, which is a target list"},
	"auditlog": {GUI: "/logs", NoMCP: "holds who did what, pseudonymously; agent_activity gives an agent its own record without handing it everybody else's"},
	"config":   {GUI: "/settings", NoMCP: "changes the security floors. An agent that can widen a limit can widen the limit that was stopping it"},
	"auth":     {GUI: "/people", NoMCP: "grants roles. Nothing that decides who may do what belongs on this surface"},
	"token":    {GUI: "/people", NoMCP: "mints credentials, for the same reason"},
	"oidc":     {GUI: "/integrations", NoMCP: "points sign-in at an identity provider; changing it changes who can become an administrator"},
	"ext":      {GUI: "/integrations", NoMCP: "registers a process this store executes. Arbitrary code execution, reached by asking"},
	"webhook":  {GUI: "/integrations", NoMCP: "adds an outbound destination for content, which is exfiltration with a configuration screen"},
	"vault":    {GUI: "/security/integrity", NoMCP: "handles key material"},
	"siem":     {GUI: "/integrations", NoMCP: "exports the audit log and can be asked to reveal identifiers"},
	"csp":      {GUI: "/security/policy", NoMCP: "is derived from published content and read on a screen; there is nothing an agent does with it"},
	"lock":     {GUI: "/publishing", NoMCP: "is a courtesy between people about who is mid-edit, and an agent is not one of them"},
	"import":   {GUI: "/transfer", NoMCP: "reads a file from disk this process was handed; there is no path by which an agent supplies one"},
	"demo": {GUI: "/transfer",
		NoMCP: "installs a whole application over an empty store, including " +
			"content types and a template; an agent that could do this could " +
			"replace a site with a demonstration of one"},
	"template":  {GUI: "/transfer", NoMCP: "replaces a whole page with sample content, which is a destructive operation with a friendly name"},
	"templates": {GUI: "/transfer", NoMCP: "as template"},
	"assist":    {GUI: "/assist", NoMCP: "asks a model to write a site, and this surface is already being driven by one"},
	"anchor":    {GUI: "/security/integrity", NoMCP: "submits to an external calendar and costs real time; verify_store answers the question an agent has"},
	"timestamp": {GUI: "/security/integrity", NoMCP: "as anchor"},
	"stamp":     {GUI: "/security/integrity", NoMCP: "as anchor"},

	// -- deliberately not in the interface either -----------------------------
	"init": {Why: "creates the store, which is what you do before there is an " +
		"interface to open",
		NoMCP: "creates the store an agent would already have to be connected to"},
	"serve": {Why: "starts the interface; a button inside it could not",
		NoMCP: "starts a server"},
	"site": {Why: "starts the public server, for the same reason",
		NoMCP: "starts a server"},
	"logd": {Why: "runs as another account and must not be startable from this one",
		NoMCP: "runs as another account"},
	"mcp": {Why: "is the machine interface; it does not appear inside itself",
		NoMCP: "is this surface"},
	"audit": {Why: "reads template files given as arguments and never opens the store",
		NoMCP: "takes file paths as arguments"},
	"render": {Why: "renders to a file for a pipeline; the admin previews " +
		"instead, at /preview/",
		NoMCP: "writes a file for a pipeline"},
	"__sandbox": {Why: "is not a command anybody types: it is the shim this " +
		"program re-executes itself as to confine an extension",
		NoMCP: "is a shim, and confining an extension is not an operation an " +
			"agent performs"},
	"config-show": {Why: "not a command", NoMCP: "not a command"},
	"help": {Why: "prints usage",
		NoMCP: "prints usage; the operation list is how an agent discovers this"},
	"-h":           {Why: "prints usage", NoMCP: "as help"},
	"--help":       {Why: "prints usage", NoMCP: "as help"},
	"version":      {Why: "prints a version", NoMCP: "prints a version"},
	"locales":      {Why: "an alias of lang", MCP: []string{"check_translations"}},
	"environments": {Why: "an alias of env", MCP: []string{"pipeline_status"}},
	"webhooks":     {Why: "an alias of webhook", NoMCP: "as webhook"},
	"extensions":   {Why: "an alias of ext", NoMCP: "as ext"},
	"prov":         {Why: "an alias of provenance", MCP: []string{"check_provenance"}},
	"locks":        {Why: "an alias of lock", NoMCP: "as lock"},
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
		if len(s.MCP) == 0 && strings.TrimSpace(s.NoMCP) == "" {
			t.Errorf("%q has no MCP operation and no reason. This column was "+
				"in the table and asserted by nothing for a whole pass, which "+
				"is how it came to describe seven operations against "+
				"thirty-nine commands. Add the operation or write down why an "+
				"agent must not have it.", c)
		}
		// A reason has to be an argument. "n/a" and "no" are what somebody
		// writes to make a test go green, and a column full of them is the
		// same as no column — which is what this column was.
		//
		// "as webhook" is allowed, and only when webhook is a row that carries
		// a real reason: an alias should point at the thing it is an alias of
		// rather than repeat its argument and then drift from it.
		if len(s.MCP) == 0 && !isRealReason(s.NoMCP) {
			t.Errorf("%q gives %q as its reason for not being on the machine "+
				"interface, which is not one", c, s.NoMCP)
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

// Any operation the table claims must actually be registered.
//
// The mirror of the route check, and it exists because the MCP column spent a
// whole pass being a description of intentions. A name in this table that no
// call to Register produces is a claim that an agent can do something it
// cannot.
func TestEveryClaimedMCPOperationIsRegistered(t *testing.T) {
	registered := registeredOperations(t)
	if len(registered) < 15 {
		t.Fatalf("found %d MCP operations; the parse is wrong and a test that "+
			"sees nothing passes", len(registered))
	}
	for cmd, s := range coverage {
		for _, op := range s.MCP {
			if !registered[op] {
				t.Errorf("%q claims the MCP server offers %q and nothing "+
					"registers it", cmd, op)
			}
		}
	}
}

// And every registered operation must be in the table.
//
// The other direction, which is the one that catches an operation added to the
// agent surface without anybody deciding it belonged there. An agent surface
// grows by accident more easily than either of the other two, because adding a
// tool is twenty lines and nobody has to draw a screen.
func TestEveryRegisteredMCPOperationIsAccountedFor(t *testing.T) {
	claimed := map[string]bool{}
	for _, s := range coverage {
		for _, op := range s.MCP {
			claimed[op] = true
		}
	}
	var loose []string
	for op := range registeredOperations(t) {
		if !claimed[op] {
			loose = append(loose, op)
		}
	}
	if len(loose) > 0 {
		sort.Strings(loose)
		t.Errorf("these MCP operations are registered and no row in the "+
			"coverage table accounts for them:\n  %s\nEvery capability an "+
			"agent can reach should be one somebody decided it should reach.",
			strings.Join(loose, "\n  "))
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

	// And the same count for the machine interface, which is deliberately not
	// zero: an agent surface that reaches everything is an agent surface with
	// nothing withheld from a prompt injection.
	var withheld int
	for _, s := range coverage {
		if len(s.MCP) == 0 && s.NoMCP != "" && s.Why == "" {
			withheld++
		}
	}
	t.Logf("%d capabilities are in the interface and withheld from agents, "+
		"each with a reason next to it", withheld)
}

// registeredOperations reads the operation names out of the MCP source.
func registeredOperations(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, file := range []string{"mcp.go", "mcpops.go"} {
		for _, m := range reOpName.FindAllStringSubmatch(readFile(t, file), -1) {
			out[m[1]] = true
		}
	}
	return out
}

// The name field of an mcp.Operation literal. Whitespace-insensitive, because
// gofmt aligns struct literals differently depending on what is beside them
// and a fixed-spacing match silently found nine of eighteen operations.
var reOpName = regexp.MustCompile(`(?m)^\s*Name:\s*"([a-z_]+)"`)

// isRealReason rejects a reason that is not one.
//
// Either three words of argument, or a reference to another row — "as
// webhook" — which is how an alias should be written: pointing at the
// argument rather than repeating it and then drifting from it.
func isRealReason(why string) bool {
	fields := strings.Fields(why)
	if len(fields) == 2 && fields[0] == "as" {
		if _, ok := coverage[fields[1]]; ok {
			return true
		}
	}
	return len(fields) >= 3
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

// A capability hiding inside a flag.
//
// The table above is keyed by command, and that granularity is what let a whole
// operation go missing from the interface for months: removing a page lived at
// `quilzo add --remove NAME`, so the row for "add" pointed at /page/ and was
// perfectly true about writing pages while saying nothing about deleting them.
// Every screen test passed, because a capability with no screen has nothing to
// fail on. It was found by building an application and wanting to delete
// something.
//
// Most flags are parameters — a message, an address, an author — and belong to
// whatever their command already covers. The ones that are separate
// capabilities are the ones that take something away, so those are the ones
// asked about here: a flag whose name is a verb of removal has to be reachable
// from the interface, or say why not.
func TestEveryRemovalFlagIsReachableFromTheInterface(t *testing.T) {
	// Where each removal flag lives in the admin, or why it does not.
	removal := map[string]surfaces{
		"add.remove": {GUI: "/page/delete",
			MCP:   []string{"write_page"},
			NoMCP: ""},
	}

	verbs := regexp.MustCompile(
		`^(remove|delete|drop|purge|erase|revoke|unbind|cancel|clear)`)
	declared := regexp.MustCompile(
		`fs\.(?:String|Bool|Int|Duration|Float64)\("([a-z-]+)"`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]bool{}
	for _, r := range adminRoutes(t) {
		routes[r] = true
	}

	found := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body := readFile(t, e.Name())
		// The command a flag belongs to is the flag set it was created on,
		// which is named at the NewFlagSet call above it.
		command := ""
		for _, line := range strings.Split(body, "\n") {
			if i := strings.Index(line, `NewFlagSet("`); i >= 0 {
				rest := line[i+len(`NewFlagSet("`):]
				if j := strings.Index(rest, `"`); j > 0 {
					command = rest[:j]
				}
			}
			m := declared.FindStringSubmatch(line)
			if m == nil || !verbs.MatchString(m[1]) {
				continue
			}
			found++
			key := command + "." + m[1]
			s, listed := removal[key]
			if !listed {
				t.Errorf("%s takes something away and is not in the removal "+
					"table.\n  A flag that removes is a capability, not a "+
					"parameter, and the command-level table above cannot see "+
					"it. Add %q with the admin path that reaches it, or a "+
					"written reason there is none.", key, key)
				continue
			}
			if s.GUI == "" {
				if !isRealReason(s.Why) {
					t.Errorf("%s has no interface and no reason worth the name",
						key)
				}
				continue
			}
			if !routes[s.GUI] {
				t.Errorf("%s claims the interface serves %q and it does not",
					key, s.GUI)
			}
		}
	}
	// The guard every source-walking test in this repo needs: one that matches
	// nothing passes forever.
	if found == 0 {
		t.Fatal("no removal flags were found at all, so this test is checking " +
			"nothing — the pattern has stopped matching the source")
	}
}

// A command nobody can find is a command nobody has.
//
// `quilzo demo` shipped working, declared its privilege, sat in the coverage
// table with a screen and a reason — and was absent from the help text, so the
// only way to discover it was to read the dispatch switch. Every check above
// passed, because each of them asks whether a command is *declared* somewhere
// and none of them asks whether a person could find it.
//
// The help output is the index of this program. A command missing from it is
// missing, whatever the tables say.
func TestEveryCommandAppearsInTheHelp(t *testing.T) {
	help := readFile(t, "main.go")
	// The help text is a raw string literal in main.go, and every line in it
	// begins "  quilzo ". Reading the source rather than running the command
	// keeps this a source check like the others around it.
	listed := map[string]bool{}
	for _, line := range strings.Split(help, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "quilzo ") {
			continue
		}
		rest := strings.TrimPrefix(line, "quilzo ")
		if i := strings.IndexAny(rest, " \t"); i > 0 {
			rest = rest[:i]
		}
		listed[rest] = true
	}
	if len(listed) < 30 {
		t.Fatalf("only %d commands were found in the help text; the parse is "+
			"wrong and a test that reads nothing passes", len(listed))
	}

	// Aliases are read out of the dispatch switch rather than listed here.
	// `case "records", "record":` makes the second an alias of the first, and
	// help rightly documents one of them. A hand-written list would need
	// maintaining and would quietly excuse the next real omission that happened
	// to be added to it.
	alias := aliasesOf(t)

	// Self-referential, and the only entries excused. A person reading `quilzo
	// help` has already found help.
	selfEvident := map[string]bool{"help": true, "-h": true, "--help": true}

	for _, c := range dispatchedCommands(t) {
		if listed[c] || selfEvident[c] {
			continue
		}
		if primary, is := alias[c]; is && listed[primary] {
			continue
		}
		t.Errorf("%q is dispatched and does not appear in `quilzo help`. "+
			"The only way to find it is to read the source, which means it "+
			"ships for nobody.", c)
	}
}

// aliasesOf maps every secondary name in a dispatch case to the first one.
func aliasesOf(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	re := regexp.MustCompile(`case ("[a-z-]+"(?:, "[a-z-]+")+):`)
	for _, m := range re.FindAllStringSubmatch(readFile(t, "main.go"), -1) {
		names := regexp.MustCompile(`"([a-z-]+)"`).FindAllStringSubmatch(m[1], -1)
		for _, n := range names[1:] {
			out[n[1]] = names[0][1]
		}
	}
	return out
}

// State that two processes share must be written atomically.
//
// The admin and the site are separate processes over one store. os.WriteFile
// truncates and then writes, so a reader landing in that window gets a parse
// error rather than stale data — and a store whose token file will not parse is
// correctly treated as one nobody may write to, so the site refuses to start.
// Starting both together reproduced it; under load it would not be rare.
//
// A source check rather than a behavioural one, because the failure is a race
// and the next writer somebody adds will be correct by inspection or not at all.
func TestSharedStateIsWrittenAtomically(t *testing.T) {
	// Files both processes read. Anything here must go through atomicfile.
	shared := []string{
		"tokensPath", "policyPath", "configPath", "envsPath", "extPath",
		"menuPath", "listingPath", "vocabPath", "formsPath", "provPath",
		"storePath",
	}
	// Writes that are not shared state, each with the reason.
	exempt := map[string]string{
		"compliancecmd.go": "writes an SBOM to a path the operator named",
		"democmd.go":       "writes a template and a stylesheet, once, into a new directory",
		"main.go":          "renders a page to a file the operator named",
		"auditlog.go":      "the audit key and its directory marker, written once at setup",
		"timestamp.go":     "writes a token or a root to a path the operator named",
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body := readFile(t, e.Name())
		for _, line := range strings.Split(body, "\n") {
			if !strings.Contains(line, "os.WriteFile(") {
				continue
			}
			found++
			if _, ok := exempt[e.Name()]; ok {
				continue
			}
			for _, p := range shared {
				if strings.Contains(line, p+"(") {
					t.Errorf("%s writes %s with os.WriteFile, which truncates "+
						"before it writes. The other process reads this file, "+
						"and half a document is a parse error rather than old "+
						"data. Use atomicfile.Write.", e.Name(), p)
				}
			}
		}
	}
	if found == 0 {
		t.Fatal("no os.WriteFile calls were found at all; the pattern has " +
			"stopped matching and this test is checking nothing")
	}
}
