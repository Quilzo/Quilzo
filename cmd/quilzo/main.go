// Command quilzo is the whole CMS: the command line, the admin interface, the
// public site and the agent interface, in one binary.
//
// The command line came first and that ordering was deliberate. A CMS whose
// primitives only exist behind a web UI cannot be scripted, reviewed in a pull
// request, or driven by an assistant without pretending to be a browser.
// Building the interface on a complete command line keeps every action
// available to a person, a script and an agent on equal terms — which is now a
// property the test suite asserts rather than an intention, because the gap
// between the three had grown to twenty-six capabilities before anybody counted.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/ext"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/tmpl"
)

const defaultRoot = ".quilzo"

// Colours are resolved at startup from whether stdout is a terminal, so piping
// or capturing output yields clean text. They were unconditional constants
// before, which put escape codes into every captured demo in this project's
// own history.
var (
	bold, dim, green, yellow, red, reset string
	w                                    *out.Writer
)

func overrideNote(forced bool, reason string) string {
	if !forced {
		return ""
	}
	return reason
}

// errBlocked marks a refusal by a gate rather than a failure of the command.
type errBlocked struct{ error }

func (e errBlocked) Unwrap() error { return e.error }

var version = "dev"

func usage() {
	// The whole surface, because `--help` is how an agent discovers a CLI. The
	// measured advantage of a CLI over a tool-schema protocol is that nothing is
	// loaded until it is needed — which only works if asking is complete when it
	// happens. Half a help page is a schema with holes in it.
	fmt.Print(`quilzo — content is immutable, publishing moves a pointer, and
          templates cannot execute anything.

content
  quilzo init                              create a content store
  quilzo add NAME=FILE.json [...]          stage pages into a draft
  quilzo diff                              what differs between live and draft
  quilzo log [--ref draft|live]            commit history
  quilzo render PAGE TEMPLATE [-o FILE]    render a page
  quilzo verify                            re-hash every object

leaving (there is no lock-in here, and this is how it is proved)
  quilzo export markdown --to DIR          Hugo, Astro, Eleventy, Jekyll
  quilzo export wxr --to DIR               WordPress reads this natively
  quilzo export json --to DIR              lossless; this tool re-imports it
  quilzo siem ocsf|cef|jsonl --envelope F  the audit log, still verifiable
  quilzo siem verify FILE --envelope F     check an export was not altered

importing
  quilzo import FILE [--from wordpress]    bring in another CMS's export
  quilzo media add FILE --alt "..."        validate and accept an upload
  quilzo media get https://... --alt "..." fetch one, checked at connect time
  quilzo media formats                     what is accepted, and what is not
  quilzo form list | expire | erase VALUE  forms, retention and erasure
  quilzo listing list | run NAME           declared queries a page can show
  quilzo terms list | check                the controlled vocabularies
  quilzo menu list | check                 navigation, and whether it resolves
  quilzo ipfs id                           what the permanent web will call this site
  quilzo ipfs write -o site                render it for 'ipfs add -r'      
  quilzo ipfs verify CID                   check what a pinning service claimed

templates
  quilzo demo                              a whole example application, in one go
  quilzo template list | show NAME         ready-made starting points
  quilzo template use NAME [--dir DIR]     write it, its stylesheet and sample

languages
  quilzo lang init en | add fr             a site in more than one language
  quilzo lang check                        which translations are stale or missing
  quilzo lang translated PAGE LOCALE       record what it was translated from

content types
  quilzo ext list | add | pin | test        run your own code, sandboxed
  quilzo records collections               what data this application holds
  quilzo records list NAME [--where k=v]   query records
  quilzo records add NAME field=value      write one
  quilzo records import NAME rows.json     write many, in one commit
  quilzo type example > FILE.json          a definition you can edit
  quilzo type add FILE.json                define a type: flat fields, no regex
  quilzo type list | show NAME             what exists, and its address
  quilzo type bind PAGE TYPE               the page must satisfy the type
  quilzo type check                        validate every bound page

working together
  quilzo lock PAGE [--note "..."]          advisory claim, expires in 30 min
  quilzo lock list | release PAGE          who is working on what
  quilzo review status                     who has agreed to the current draft
  quilzo review approve [--note "..."]     agree to it; authors cannot

publishing
  quilzo env list                          what is where, and what is waiting
  quilzo env add staging --before production
  quilzo env promote staging production    a pointer move; the same bytes
  quilzo env diff staging production       what would change
  quilzo publish [COMMIT]                  move live to the draft
  quilzo schedule add 48h | list | run     publish later; gates run at publish
  quilzo rollback [--steps N]              move live back along its history
  quilzo a11y [--ref REF]                  accessibility check, blocking publish

the assistant
  quilzo assist "..." --author WHO         propose changes; marks what it writes
  quilzo provenance check [--ref REF]      who or what wrote each page
  quilzo provenance set PAGE --source T    record provenance by hand

access
  quilzo oidc configure --issuer ... --client-id ...   sign in with an IdP
  quilzo oidc check                        talk to the provider, report what it offers
  quilzo auth grant WHO ROLE [--on PATH]   reader | author | publisher | admin
  quilzo auth explain WHO [ACTION]         why someone can or cannot do a thing
  quilzo auth list | roles
  quilzo token issue NAME --principal WHO  an API credential, shown once
  quilzo token list | revoke ID | stale

encryption at rest
  quilzo vault status                      whether objects are sealed on disk
  quilzo vault enable                      seal new objects; prints the key once
  quilzo vault rotate                      new key, rewraps without re-encrypting
      QUILZO_KEY / _KEY_FILE / _KEY_COMMAND  where the key comes from

compliance evidence
  quilzo compliance summary                what a procurement questionnaire asks
  quilzo compliance sbom [FILE]            CycloneDX 1.6, derived from the build
  quilzo compliance crypto                 every algorithm, and its post-quantum
                                            status, checked against the source
  quilzo compliance controls               NIST 800-53 coverage, from the rules

agents and integrations
  quilzo agent templates                    the agent archetypes, and when to use each
  quilzo agent new NAME --kind KIND         declare what an agent may do
  quilzo agent list | show NAME | check     what is declared, and whether it still validates
  quilzo agents                            what models have been doing, and
                                            which are not accepting refusals
  quilzo webhook add https://...           tell another system when you publish
  quilzo webhook list | test               signed, timestamped, replay-proof

security posture
  quilzo config show | list                everything settable, and its default
  quilzo config explain KEY                what it is for, and what it costs
  quilzo config set KEY VALUE              --accept-risk "why" if it weakens
  quilzo posture scan [--min SEV]          continuous misconfiguration check
  quilzo posture rules | explain RULE      what is checked, and why it matters
  quilzo posture suppress ID --reason ...  accept a risk, for at most 90 days

interface
  quilzo serve [--addr HOST:PORT]          the admin, on loopback by default
      /playground                            try the API against your own store
  quilzo site  [--addr HOST:PORT]          the published site, PWA-installable
      --api                                 content API at /api/v1, read-only
      --api-writable                        allow PUT; every write needs If-Match
      --base-url https://example.com        needed for /sitemap.xml
      --redirects redirects.json            keep old URLs working after a move
  quilzo audit [DIR]                       templates that disable escaping
  quilzo scan [--fail-on SEV]              XSS, injection and leaked secrets
  quilzo scan --rules                      what is checked, and why
  quilzo csp                               the policy your content implies

log transparency
  quilzo logd                              the log writer, run as its own account
  quilzo logd status                       whether the separation is in force
  quilzo auditlog head --save              a commitment to every entry so far
  quilzo auditlog prove SEQ                one entry is in the log, in ~20 hashes
  quilzo auditlog consistency              nothing before a published head moved
  quilzo auditlog anchor                   put the head in Bitcoin, so rewriting
                                            history contradicts a block
  quilzo timestamp stamp | list | verify   RFC 3161 proof of when you published
  quilzo anchor submit | list | verify     one hash over a whole publication

  quilzo mcp [--list]                      the agent interface, over stdio
  quilzo __sandbox --allow DIR -- CMD       run CMD confined to DIR. Not a
                                            command you type: this program
                                            re-executes itself as this to put
                                            an extension in a Landlock sandbox,
                                            and it is listed because anything
                                            dispatched and undocumented ships
                                            for nobody
  quilzo version                           what this binary is

global
  --root DIR    store location (default .quilzo)
  --json        machine-readable output; stdout carries one document
  NO_COLOR      suppress colour (also off automatically when not a terminal)

exit codes
  0 success · 1 failed · 2 misused · 3 refused by a gate · 4 not found
  5 a required dependency was missing

A gate refusing (3) is not the command failing (1). Branch on the code rather
than on the wording, which is free to improve.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	// --json is global rather than per-command, because a caller scripting this
	// should not have to remember which subcommands happen to support it.
	args := os.Args[1:]
	jsonMode := false
	filtered := args[:0]
	for _, a := range args {
		if a == "--json" {
			jsonMode = true
			continue
		}
		filtered = append(filtered, a)
	}
	args = filtered

	w = out.New(jsonMode)
	bold, dim = w.Bold(), w.Dim()
	green, yellow, red, reset = w.Green(), w.Yellow(), w.Red(), w.Reset()

	root := defaultRoot
	// A tiny hand-rolled global flag pass, so `--root` works before the
	// subcommand as well as after it.
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--root" && i+1 < len(args) {
			root = args[i+1]
			i++
			continue
		}
		if v, ok := strings.CutPrefix(args[i], "--root="); ok {
			root = v
			continue
		}
		rest = append(rest, args[i])
	}
	if len(rest) == 0 {
		usage()
		os.Exit(2)
	}

	cmd, cmdArgs := rest[0], rest[1:]

	// Authorisation happens here, once, for every command. See privilege.go
	// for why it is a table rather than a call at the top of each one.
	if cmd != "help" && cmd != "-h" && cmd != "--help" {
		if err := authoriseCommand(root, cmd, cmdArgs); err != nil {
			w.Error(err)
			os.Exit(out.ExitFailure)
		}
	}

	var err error
	switch cmd {
	case "init":
		err = cmdInit(root)
	case "add":
		err = cmdAdd(root, cmdArgs)
	case "diff":
		err = cmdDiff(root)
	case "publish":
		err = cmdPublish(root, cmdArgs)
	case "rollback":
		err = cmdRollback(root, cmdArgs)
	case "log":
		err = cmdLog(root, cmdArgs)
	case "render":
		err = cmdRender(root, cmdArgs)
	case "audit":
		err = cmdAudit(cmdArgs)
	case "auditlog":
		err = cmdAuditLog(root, cmdArgs)
	case "assist":
		err = cmdAssist(root, cmdArgs)
	case "provenance", "prov":
		err = cmdProvenance(root, cmdArgs)
	case "compliance":
		err = cmdCompliance(root, cmdArgs)
	case "agents":
		err = cmdAgents(root, cmdArgs)
	case "agent":
		err = cmdAgent(root, cmdArgs)
	// The literal rather than sandboxCmd, because the test that keeps the
	// privilege table honest reads this switch from the source and cannot
	// resolve a constant.
	case "__sandbox":
		err = cmdSandbox(cmdArgs)
	case "webhook", "webhooks":
		err = cmdWebhook(root, cmdArgs)
	case "logd":
		if len(cmdArgs) > 0 && cmdArgs[0] == "status" {
			err = cmdLogdStatus(root)
		} else {
			err = cmdLogd(root, cmdArgs)
		}
	case "schedule":
		err = cmdSchedule(root, cmdArgs)
	case "lang", "locales":
		err = cmdLang(root, cmdArgs)
	case "anchor":
		err = cmdAnchor(root, cmdArgs)
	case "oidc":
		err = cmdOIDC(root, cmdArgs)
	case "vault":
		err = cmdVault(root, cmdArgs)
	case "lock", "locks":
		err = cmdLock(root, cmdArgs)
	case "review":
		err = cmdReview(root, cmdArgs)
	case "export":
		err = cmdExport(root, cmdArgs)
	case "siem":
		if len(cmdArgs) > 0 && cmdArgs[0] == "verify" {
			err = cmdSiemVerify(root, cmdArgs[1:])
		} else {
			err = cmdSiem(root, cmdArgs)
		}
	case "import":
		err = cmdImport(root, cmdArgs)
	case "media":
		err = cmdMedia(root, cmdArgs)
	case "form", "forms":
		err = cmdForms(root, cmdArgs)
	case "listing", "listings":
		err = cmdListings(root, cmdArgs)
	case "terms", "taxonomy":
		err = cmdTerms(root, cmdArgs)
	case "menu", "menus":
		err = cmdMenus(root, cmdArgs)
	case "ipfs":
		err = cmdIPFS(root, cmdArgs)
	case "demo":
		err = cmdDemo(root, cmdArgs)
	case "template", "templates":
		err = cmdTemplate(root, cmdArgs)
	case "posture":
		err = cmdPosture(root, cmdArgs)
	case "type", "types":
		err = cmdTypes(root, cmdArgs)
	case "mcp":
		err = cmdMCP(root, cmdArgs)
	case "timestamp", "stamp":
		err = cmdTimestamp(root, cmdArgs)
	case "site":
		err = cmdSite(root, cmdArgs)
	case "serve":
		err = cmdServe(root, cmdArgs)
	case "auth":
		err = cmdAuth(root, cmdArgs)
	case "token":
		err = cmdToken(root, cmdArgs)
	case "a11y":
		err = cmdA11y(root, cmdArgs)
	case "records", "record":
		err = cmdRecords(root, cmdArgs)
	case "env", "environments":
		err = cmdEnv(root, cmdArgs)
	case "ext", "extensions":
		err = cmdExt(root, cmdArgs)
	case "scan":
		err = cmdScan(root, cmdArgs)
	case "csp":
		err = cmdCSP(root, cmdArgs)
	case "config":
		err = cmdConfig(root, cmdArgs)
	case "verify":
		err = cmdVerify(root)
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		w.Error(err)
		// A gate refusing is a different outcome from the command breaking, and
		// a caller branching on exit status should be able to tell which.
		var blocked errBlocked
		if errors.As(err, &blocked) {
			os.Exit(out.ExitBlocked)
		}
		os.Exit(out.ExitFailure)
	}
}

// open is the one place any command gets a store, which is why encryption is
// wired here: every command inherits it, including the ones added next year by
// somebody who has not read this file.
func open(root string) (*store.Store, error) { return openEncrypted(root) }

// reorder moves flags ahead of positional arguments.
//
// Go's flag package stops parsing at the first non-flag argument, so
// `add index=home.json -m "msg"` treats -m as a filename. That is the natural
// order to type and the CLI has to accept it, so flags are lifted out first.
// `valued` names the flags that consume the following argument; a boolean flag
// must not swallow the token after it.
func reorder(args []string, valued map[string]bool) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if n, _, hasEq := strings.Cut(name, "="); hasEq {
			_ = n
			continue // --flag=value carries its own value
		}
		if valued[name] && i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return append(flags, positional...)
}

func cmdInit(root string) error {
	_, existed := os.Stat(root)
	s, err := open(root)
	if err != nil {
		return err
	}
	if existed != nil {
		fmt.Printf("created %s\n", s.Root())
		fmt.Printf("  %scontent is immutable and addressed by hash; publishing "+
			"moves a pointer%s\n", dim, reset)
	} else {
		fmt.Printf("reusing %s\n", s.Root())
	}
	return nil
}

func cmdAdd(root string, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	msg := fs.String("m", "edit", "commit message")
	// Empty by default, filled from the resolved caller below. The literal
	// "cli" was recorded as the author of every commit, which made a conflict
	// report that "cli" had changed the draft — true and useless.
	author := fs.String("author", "", "author; defaults to the caller")
	remove := fs.String("remove", "", "comma-separated page names to drop")
	basedOn := fs.String("based-on", "",
		"the draft commit this edit was made against; refuses if it has moved")
	if err := fs.Parse(reorder(args, map[string]bool{
		"m": true, "author": true, "remove": true, "based-on": true})); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	parent := s.GetRef(site.RefDraft)
	if parent == "" {
		parent = s.GetRef(site.RefLive)
	}
	pages := map[string]any{}
	if parent != "" {
		if pages, err = site.PagesAt(s, parent); err != nil {
			return err
		}
	}

	for _, spec := range fs.Args() {
		name, path, ok := strings.Cut(spec, "=")
		if !ok {
			return fmt.Errorf("expected NAME=FILE.json, got %q", spec)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("cannot read %s: %w", path, err)
		}
		var v any
		if err := json.Unmarshal(body, &v); err != nil {
			return fmt.Errorf("%s is not valid JSON: %w", path, err)
		}
		pages[name] = v
	}
	for _, name := range strings.Split(*remove, ",") {
		if name = strings.TrimSpace(name); name != "" {
			delete(pages, name)
		}
	}

	// Content types are checked before anything is stored. Refusing the write
	// is the point: the store is immutable, so an invalid page that lands in it
	// is in the history for good, and "fix it in the next commit" leaves the
	// broken one addressable forever.
	// Extensions run before the type gate, so a transform produces content
	// that is then validated like anything else. An extension whose output
	// skipped validation would be a way to store what an author cannot.
	for name := range pages {
		fields, ok := pages[name].(map[string]any)
		if !ok {
			continue
		}
		out, xerr := runExtensions(root, ext.OnTransform, name, fields)
		if xerr != nil {
			return xerr
		}
		if _, xerr = runExtensions(root, ext.OnValidate, name, out); xerr != nil {
			return xerr
		}
		pages[name] = out
	}

	types, err := gateWrite(root, pages)
	if err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	who := *author
	if who == "" {
		who = caller.Name
	}
	changed := changedNames(fs.Args())
	cid, err := site.SaveDraftFrom(s, pages, *msg, who, *basedOn)
	if err != nil {
		// A refused write is worth recording. Somebody tried to save over
		// somebody else's edit, and the fact that the store stopped them is
		// exactly the sort of thing a log exists to preserve.
		record(root, caller.auditRecord("content.add", "/", audit.Denied,
			map[string]string{
				"pages":  strings.Join(changed, ","),
				"reason": "conflict",
			}))
		return conflictError(err, changed)
	}
	// The validation record is written after the content, so a crash between
	// the two leaves a page with no record rather than a record for a page that
	// was never stored. Unrecorded reads as unvalidated, which is the safe way
	// round.
	if err := types.Save(); err != nil {
		return err
	}
	// The most ordinary write in the program, and it recorded nothing. AU-3
	// wants who did what; a log that holds every grant and no content change
	// answers a much narrower question than anyone reading it will assume.
	record(root, caller.auditRecord("content.add", "/", audit.Success,
		map[string]string{
			"commit": short(cid),
			"pages":  strings.Join(changed, ","),
			"author": who,
		}))
	w.Human("draft %s  %d page(s)\n", short(cid), len(pages))
	return nil
}

func cmdDiff(root string) error {
	s, err := open(root)
	if err != nil {
		return err
	}
	live, draft := s.GetRef(site.RefLive), s.GetRef(site.RefDraft)
	if draft == "" {
		fmt.Println("no draft")
		return nil
	}
	if live == draft {
		fmt.Println("draft matches live")
		return nil
	}
	changes, err := site.Diff(s, live, draft)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		fmt.Println("no content differences")
		return nil
	}
	colour := map[string]string{"added": green, "removed": red, "modified": yellow}
	for _, c := range changes {
		fmt.Printf("  %s%-9s%s %s\n", colour[c.Kind], c.Kind, reset, c.Path)
	}
	fmt.Printf("\n  %d change(s) between live and draft\n", len(changes))
	return nil
}

// checkAccessibility renders every page in a commit and reports what fails.
//
// Rendering is required rather than inspecting the content, because what a
// reader receives is the rendered page. Content that looks fine and a template
// that drops the alt attribute produce an inaccessible site, and only the output
// shows it.
func checkAccessibility(root string, s *store.Store, commitID, tplDir string) ([]*a11y.Report, error) {
	pages, err := site.PagesAt(s, commitID)
	if err != nil {
		return nil, err
	}
	tplPath := filepath.Join(tplDir, "page.html")
	raw, err := os.ReadFile(tplPath)
	if err != nil {
		// No template means nothing renders, so there is nothing to judge. Say
		// so rather than reporting a clean result over an empty check.
		return nil, fmt.Errorf("no template at %s to render against: %w", tplPath, err)
	}
	// Rendered the way the site serves them. Checking a page with its
	// navigation and its listings missing is checking a different document,
	// and it fails in both directions: a link that is only empty because the
	// name was not supplied blocks a publish, and a genuine failure inside a
	// menu is never seen.
	src := sourcesFor(root, s, commitID, siteName(root), pages)
	rendered := map[string]string{}
	for name, body := range pages {
		ctx, cerr := src.For(name, body, nil)
		if cerr != nil {
			return nil, fmt.Errorf("assembling %s: %w", name, cerr)
		}
		out, err := tmpl.Render(string(raw), ctx)
		if err != nil {
			return nil, fmt.Errorf("rendering %s: %w", name, err)
		}
		rendered[name] = out
	}
	return a11y.CheckAll(rendered), nil
}

func cmdPublish(root string, args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	force := fs.Bool("force-inaccessible", false,
		"publish despite blocking accessibility failures, and record that you did")
	reason := fs.String("reason", "", "why the override is justified (required with --force-inaccessible)")
	tplDir := fs.String("templates", "templates", "where page.html lives")
	skip := fs.Bool("no-a11y-check", false, "skip the check entirely")
	token := fs.String("token", "", "authenticate as the holder of this token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	args = fs.Args()

	caller := resolveCaller(root, *token)
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		record(root, caller.auditRecord("publish", "/", audit.Denied,
			map[string]string{"reason": "authorisation"}))
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	target := ""
	if len(args) > 0 {
		target = args[0]
	}
	// The gate runs before the pointer moves. ATAG Part B asks that the tool
	// help authors produce accessible content, and a report printed after
	// publishing helps nobody — the inaccessible page is already being served.
	if !*skip {
		candidate := target
		if candidate == "" {
			candidate = s.GetRef(site.RefDraft)
		}
		reports, cerr := checkAccessibility(root, s, candidate, *tplDir)
		if cerr != nil {
			// A gate that cannot run must not exit like a gate that passed.
			//
			// This printed "accessibility check skipped" and published, with
			// status zero. In a pipeline that is a green build: `quilzo
			// publish && deploy` deploys, and a typo in --templates means the
			// check never runs again and nothing ever says so. Absence read as
			// a claim, which is the failure this whole program is arranged to
			// avoid.
			//
			// Refusing here rather than guessing whether the template is
			// missing on purpose. A headless store that renders elsewhere is a
			// real case, and --no-a11y-check is how it says so — once, in the
			// pipeline, deliberately, and recorded in the audit log as a
			// choice somebody made.
			record(root, caller.auditRecord("publish", "/", audit.Denied,
				map[string]string{
					"reason": "accessibility check could not run",
					"detail": cerr.Error(),
				}))
			return errBlocked{fmt.Errorf(
				"the accessibility check could not run, so publishing would "+
					"claim a check that did not happen: %v\n"+
					"  create the template, point --templates at it, or pass "+
					"--no-a11y-check if this store is not what renders the "+
					"pages", cerr)}
		} else if n := a11y.BlockingCount(reports); n > 0 {
			printA11y(reports)
			if !*force {
				// A refusal is an audit event in its own right. AU-3 wants the
				// outcome, and "someone tried to publish inaccessible content"
				// is exactly the sort of attempt a log exists to preserve.
				record(root, caller.auditRecord("publish", "/", audit.Denied,
					map[string]string{
						"reason":   "accessibility",
						"blocking": fmt.Sprintf("%d", n),
					}))
				return fmt.Errorf(
					"%d blocking accessibility failure(s); this content is unusable "+
						"for someone.\nFix them, or publish with --force-inaccessible "+
						"--reason \"...\" to record the decision", n)
			}
			if strings.TrimSpace(*reason) == "" {
				return fmt.Errorf(
					"--force-inaccessible needs --reason. An override without a stated " +
						"justification is indistinguishable from not checking")
			}
			fmt.Printf("  %soverriding %d blocking failure(s): %s%s\n",
				yellow, n, *reason, reset)
		}
	}

	// Dual authorization, last of the gates, because it is the one about people
	// rather than about content. A change that fails the accessibility or
	// provenance checks should be told that first — asking two colleagues to
	// approve something the tool is going to refuse anyway wastes their time
	// and teaches them the approval is a formality.
	if pol, perr := loadApprovalPolicy(root); perr == nil {
		if pol.Required > 0 || pol.RequireHumanForAI {
			prop, _, cerr := currentProposal(root, s)
			if cerr == nil {
				d := pol.Evaluate(*prop, kindOfPrincipal(root), time.Now())
				if !d.Allowed {
					record(root, caller.auditRecord("publish", "/", audit.Denied,
						map[string]string{
							"reason":     "dual-authorization",
							"have":       fmt.Sprintf("%d", d.Have),
							"need":       fmt.Sprintf("%d", d.Need),
							"content":    prop.Content,
							"author":     prop.Author,
							"authorkind": prop.AuthorKind,
						}))
					return errBlocked{fmt.Errorf("%s\n  quilzo review status",
						d.Reason)}
				}
				fmt.Printf("  %s%s%s\n", green, d.Reason, reset)
			}
		}
	}

	pub, err := site.Publish(s, target)
	if err != nil {
		return err
	}
	if len(pub.Changes) == 0 && pub.Previous == pub.Published {
		fmt.Println("already live")
		return nil
	}
	record(root, caller.auditRecord("publish", "/", audit.Success,
		map[string]string{
			"commit":   short(pub.Published),
			"changes":  fmt.Sprintf("%d", len(pub.Changes)),
			"override": overrideNote(*force, *reason),
		}))

	// Told after the fact, never before, and a failure here never blocks. A
	// receiver being down is not a reason to stop publishing — making it one
	// hands anybody who can take an endpoint offline the ability to stop the
	// site being updated.
	var changed []string
	for _, c := range pub.Changes {
		changed = append(changed, c.Path)
	}
	notify(root, "published", pub.Published, changed)
	fmt.Printf("live is now %s  (%d change(s))\n", short(pub.Published), len(pub.Changes))
	if pub.Previous != "" {
		fmt.Printf("  %sprevious %s is still stored; `quilzo rollback` moves the "+
			"pointer back%s\n", dim, short(pub.Previous), reset)
	}
	// Said plainly because it is the one thing a pointer cannot fix.
	fmt.Printf("  %srolling back restores the content, not the fact that it was "+
		"published%s\n", dim, reset)
	return nil
}

func cmdRollback(root string, args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	steps := fs.Int("steps", 1, "how many commits to go back")
	if err := fs.Parse(reorder(args, map[string]bool{"steps": true})); err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	pub, err := site.Rollback(s, *steps)
	if err != nil {
		record(root, caller.auditRecord("rollback", "/", audit.Denied,
			map[string]string{"steps": fmt.Sprintf("%d", *steps),
				"reason": err.Error()}))
		return err
	}
	// Rollback changes what the public is served and recorded nothing, which
	// made it the quietest way to change the live site in the whole program.
	record(root, caller.auditRecord("rollback", "/", audit.Success,
		map[string]string{
			"from":  short(pub.Previous),
			"to":    short(pub.Published),
			"steps": fmt.Sprintf("%d", *steps),
		}))
	fmt.Printf("live is now %s  (%d change(s) reverted)\n",
		short(pub.Published), len(pub.Changes))
	fmt.Printf("  %srolled back from %s, which is still stored and can be "+
		"published again%s\n", dim, short(pub.Previous), reset)
	return nil
}

func cmdLog(root string, args []string) error {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	ref := fs.String("ref", site.RefDraft, "which ref to walk")
	limit := fs.Int("limit", 20, "how many commits")
	if err := fs.Parse(reorder(args, map[string]bool{
		"ref": true, "limit": true})); err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	head := s.GetRef(*ref)
	if head == "" {
		return fmt.Errorf("no ref %q", *ref)
	}
	live := s.GetRef(site.RefLive)
	hist, err := s.History(head, *limit)
	if err != nil {
		return err
	}
	for _, h := range hist {
		mark := ""
		if h.ID == live {
			mark = green + " ← live" + reset
		}
		fmt.Printf("  %s  %-10s %s%s\n", short(h.ID), h.Commit.Author, h.Commit.Message, mark)
	}
	return nil
}

func cmdRender(root string, args []string) error {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	ref := fs.String("ref", site.RefLive, "which ref to read")
	out := fs.String("o", "", "write here instead of stdout")
	if err := fs.Parse(reorder(args, map[string]bool{
		"ref": true, "o": true})); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("usage: quilzo render PAGE TEMPLATE")
	}
	pageName, templatePath := fs.Arg(0), fs.Arg(1)

	s, err := open(root)
	if err != nil {
		return err
	}
	pages, err := site.PagesAt(s, *ref)
	if err != nil {
		return err
	}
	page, ok := pages[pageName]
	if !ok {
		names := make([]string, 0, len(pages))
		for n := range pages {
			names = append(names, n)
		}
		sort.Strings(names)
		return fmt.Errorf("no page %q; have %s", pageName, strings.Join(names, ", "))
	}

	src, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}
	names := make([]any, 0, len(pages))
	for n := range pages {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return names[i].(string) < names[j].(string) })

	html, err := tmpl.Render(string(src), map[string]any{
		"page": page,
		"site": map[string]any{"pages": names},
	})
	if err != nil {
		return fmt.Errorf("template: %w", err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(html), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", *out)
		return nil
	}
	fmt.Print(html)
	return nil
}

func cmdAudit(args []string) error {
	dir := "templates"
	if len(args) > 0 {
		dir = args[0]
	}
	total := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".html" {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		sites := tmpl.RawSites(string(body))
		if len(sites) > 0 {
			fmt.Printf("  %s\n", path)
			for _, s := range sites {
				fmt.Printf("      %sraw%s %s\n", yellow, reset, s)
			}
			total += len(sites)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if total > 0 {
		fmt.Printf("\n  %d place(s) where escaping is switched off. Each one is a "+
			"decision to trust that content.\n", total)
	} else {
		fmt.Println("  no template opts out of escaping")
	}
	return nil
}

// printA11y renders a set of reports for a person, worst first.
func printA11y(reports []*a11y.Report) {
	for _, r := range reports {
		if len(r.Findings) == 0 {
			continue
		}
		fmt.Printf("\n  %s%s%s\n", bold, r.Page, reset)
		for _, f := range r.Findings {
			colour := yellow
			if f.Severity == a11y.Blocking {
				colour = red
			}
			fmt.Printf("    %s%s%s  %s (%s)\n      %s\n",
				colour, f.Severity, reset, f.Rule, f.Criterion, f.Detail)
			if f.Excerpt != "" {
				fmt.Printf("      %s%s%s\n", dim, f.Excerpt, reset)
			}
		}
	}
}

func cmdA11y(root string, args []string) error {
	fs := flag.NewFlagSet("a11y", flag.ContinueOnError)
	ref := fs.String("ref", site.RefDraft, "which ref to check")
	tplDir := fs.String("templates", "templates", "where page.html lives")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	target := s.GetRef(*ref)
	if target == "" {
		target = *ref
	}
	reports, err := checkAccessibility(root, s, target, *tplDir)
	if err != nil {
		return err
	}

	blocking := a11y.BlockingCount(reports)
	total := 0
	for _, r := range reports {
		total += len(r.Findings)
	}
	fmt.Printf("%d page(s) checked, %d finding(s), %d blocking\n",
		len(reports), total, blocking)
	printA11y(reports)

	// A clean result must never read as "this site is accessible".
	if len(reports) > 0 {
		fmt.Printf("\n  %schecked:%s\n", bold, reset)
		for _, c := range reports[0].Checked {
			fmt.Printf("    %s\n", c)
		}
		fmt.Printf("  %snot checked, and needs a person:%s\n", bold, reset)
		for _, c := range reports[0].NotCheck {
			fmt.Printf("    %s%s%s\n", dim, c, reset)
		}
	}
	if blocking > 0 {
		return fmt.Errorf("%d blocking failure(s)", blocking)
	}
	return nil
}

func cmdVerify(root string) error {
	s, err := open(root)
	if err != nil {
		return err
	}
	n, err := s.Verify()
	if err != nil {
		return fmt.Errorf("%s%v%s", red, err, reset)
	}
	fmt.Printf("  %d object(s) intact\n", n)
	fmt.Printf("  %severy object re-hashed to the id it is filed under%s\n", dim, reset)
	return nil
}

func short(oid string) string {
	if len(oid) > 12 {
		return oid[:12]
	}
	return oid
}
