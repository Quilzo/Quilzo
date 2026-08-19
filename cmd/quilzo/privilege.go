package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// What every command needs before it is allowed to run.
//
// This exists because the check was in one place and needed to be in twenty.
// `publish` called authorise and nothing else did, so with a policy configured
// and no token presented at all:
//
//	auth grant mallory admin              succeeded
//	auth revoke alice admin               succeeded
//	token issue evil --role admin         succeeded, and printed a live token
//	schedule add 1h                       succeeded, deferring a publish
//
// which is the entire access-control model bypassed by anyone able to run the
// binary. publish refused correctly the whole time, and that inconsistency is
// what shows it was an omission rather than a decision: if the reasoning had
// been "filesystem access to the store is already game over", publish would
// not have been checking either.
//
// It is not game over, and the rest of this program is built on that. The
// audit log is written by a separate account precisely so that code execution
// as the CMS is not enough to rewrite it, and a store on a shared volume is a
// normal deployment.
//
// So the table, rather than a call at the top of each command. A call has to
// be remembered; a table is a list somebody has to add a row to, and the test
// below refuses to pass until every dispatched command has one. This is the
// same shape as the content-type gate test, which is what caught the HTTP API
// writing content without validating it.
type need struct {
	// action is what the caller must be permitted to do. Empty means the
	// command needs no authority, and then why must say why that is safe.
	action auth.Action
	why    string
}

// commandNeeds is keyed by "command" or by "command subcommand" where the
// subcommand changes the answer. The more specific key wins, so `auth explain`
// can be readable while `auth grant` is not.
var commandNeeds = map[string]need{
	// -- reading. A reader role, so a store with access control does not leak
	// its contents to anybody with a shell on the box.
	"diff":   {action: auth.ActView},
	"log":    {action: auth.ActView},
	"render": {action: auth.ActView},
	"export": {action: auth.ActView},
	// Reading published content and hashing it. The identifier of a public
	// page is not a secret — anybody who can fetch the page can compute it —
	// but rendering the whole site is still a read of the store.
	"ipfs": {action: auth.ActView},
	// Reading the vocabularies, the menus, and the content they classify.
	// Editing either is done through the interface, where the existing terms
	// and their usage counts are visible — changing what everybody is allowed
	// to say about the content is a governance act, not a shell one-liner.
	// Retention and erasure change what is stored about members of the
	// public, so they need the permission to write rather than to read.
	"form":       {action: auth.ActEditDraft},
	"forms":      {action: auth.ActEditDraft},
	"listing":    {action: auth.ActView},
	"listings":   {action: auth.ActView},
	"terms":      {action: auth.ActView},
	"taxonomy":   {action: auth.ActView},
	"menu":       {action: auth.ActView},
	"menus":      {action: auth.ActView},
	"siem":       {action: auth.ActView},
	"a11y":       {action: auth.ActView},
	"verify":     {action: auth.ActView},
	"scan":       {action: auth.ActView},
	"csp":        {action: auth.ActView},
	"compliance": {action: auth.ActView},
	"agents":     {action: auth.ActView},
	// Declaring what a model may do is deciding a blast radius, which is an
	// administrative act rather than an editorial one. Reading the list and
	// the templates is not, so those step down from it.
	"agent": {action: auth.ActGrant},
	// Pairing with a peer, and adopting what it sent into the draft. ActGrant
	// rather than ActEditDraft: adding a peer decides which other store this
	// one will accept content from, which is a trust decision and outlives
	// the person who made it, whereas the draft it eventually writes is the
	// visible consequence rather than the thing being authorised.
	"peer": {action: auth.ActGrant},
	// Editing what the business may claim is editing a publish gate, so it
	// needs more than the right to publish through it. An author who can
	// remove the rule standing between their copy and the public has the
	// gate as a setting rather than as a gate.
	"brand": {action: auth.ActGrant},
	// Reading which image licences are about to lapse is reading the library,
	// not changing it. The gate that acts on the same answer lives inside
	// publish, which has its own privilege.
	"rights":          {action: auth.ActView},
	"agent templates": {action: auth.ActView},
	"agent list":      {action: auth.ActView},
	"agent show":      {action: auth.ActView},
	"agent check":     {action: auth.ActView},
	// Running one acts under the agent's manifest, and the least it can do is
	// read the store. Author rather than view: a run writes an audit record
	// attributed to the caller, and an entry somebody could create without
	// being able to change anything would be a way to write the log.
	"agent run":  {action: auth.ActEditDraft},
	"provenance": {action: auth.ActView},
	"prov":       {action: auth.ActView},
	// Strict parent, narrowing children — see the note on posture. Pointing
	// every reader at a different audit log is an operator act, so the parent
	// takes that answer and the seven reading subcommands step down from it.
	"auditlog":  {action: auth.ActGrant},
	"anchor":    {action: auth.ActView},
	"timestamp": {action: auth.ActView},
	"stamp":     {action: auth.ActView},

	// -- writing content
	"add": {action: auth.ActEditDraft},
	// Records are content: writing them is an author's act, reading them a
	// reader's.
	"records":             {action: auth.ActEditDraft},
	"record":              {action: auth.ActEditDraft},
	"records list":        {action: auth.ActView},
	"records get":         {action: auth.ActView},
	"records collections": {action: auth.ActView},
	"import":              {action: auth.ActEditDraft},
	"assist":              {action: auth.ActEditDraft},
	"media":               {action: auth.ActEditDraft},
	"lang":                {action: auth.ActEditDraft},
	"locales":             {action: auth.ActEditDraft},
	"lock":                {action: auth.ActEditDraft},
	"locks":               {action: auth.ActEditDraft},
	"review":              {action: auth.ActEditDraft},
	// Writes content, types, listings, menus and forms, and publishes. That is
	// the whole store, so it needs the permission that covers the whole store —
	// and it refuses outright on a store that already has anything in it.
	"demo":      {action: auth.ActPublish},
	"template":  {action: auth.ActEditDraft},
	"templates": {action: auth.ActEditDraft},

	// -- content types gate every write, so changing one is a change to what
	// every author may store. Publisher, not author.
	"type":  {action: auth.ActPublish},
	"types": {action: auth.ActPublish},

	// Listing and showing are reads. Splitting these is not politeness: a
	// reader who cannot list the types cannot tell why their content was
	// refused, and an authorisation model that makes the error message
	// unreachable gets turned off.
	"type list":       {action: auth.ActView},
	"type show":       {action: auth.ActView},
	"type check":      {action: auth.ActView},
	"type example":    {action: auth.ActView},
	"types example":   {action: auth.ActView},
	"types list":      {action: auth.ActView},
	"types show":      {action: auth.ActView},
	"template list":   {action: auth.ActView},
	"template show":   {action: auth.ActView},
	"templates list":  {action: auth.ActView},
	"templates show":  {action: auth.ActView},
	"lock list":       {action: auth.ActView},
	"locks list":      {action: auth.ActView},
	"review status":   {action: auth.ActView},
	"schedule list":   {action: auth.ActView},
	"media formats":   {action: auth.ActView},
	"lang check":      {action: auth.ActView},
	"locales check":   {action: auth.ActView},
	"posture scan":    {action: auth.ActView},
	"posture rules":   {action: auth.ActView},
	"posture explain": {action: auth.ActView},
	"webhook list":    {action: auth.ActView},
	"webhooks list":   {action: auth.ActView},
	"oidc check":      {action: auth.ActView},
	"logd status":     {action: auth.ActView},

	"auditlog verify":      {action: auth.ActView},
	"auditlog show":        {action: auth.ActView},
	"auditlog export":      {action: auth.ActView},
	"auditlog head":        {action: auth.ActView},
	"auditlog prove":       {action: auth.ActView},
	"auditlog consistency": {action: auth.ActView},
	"auditlog anchor":      {action: auth.ActView},

	// -- changing what the public sees
	"publish": {action: auth.ActPublish},
	// Promotion changes what an environment serves, which for production is
	// what the public sees. Configuring the set is an operator act.
	"env":               {action: auth.ActGrant},
	"environments":      {action: auth.ActGrant},
	"env list":          {action: auth.ActView},
	"env status":        {action: auth.ActView},
	"env diff":          {action: auth.ActView},
	"env promote":       {action: auth.ActPublish},
	"environments list": {action: auth.ActView},
	"rollback":          {action: auth.ActRollback},
	"schedule":          {action: auth.ActPublish},

	// -- changing who may do anything. Admin.
	"auth":  {action: auth.ActGrant},
	"token": {action: auth.ActToken},
	"oidc":  {action: auth.ActGrant},
	"vault": {action: auth.ActToken},

	// Suppressing a posture rule is accepting a risk on the organisation's
	// behalf, and scanning is not — so the parent takes the strict answer and
	// the reading subcommands narrow it.
	//
	// That direction is the whole convention here, and a test enforces it. A
	// permissive parent with a strict child looks equivalent and is not: the
	// next subcommand somebody adds inherits the parent, so getting it wrong
	// means new mutating subcommands arrive unguarded. Defaulting strict means
	// they arrive over-guarded, which is a bug report rather than a breach.
	"posture": {action: auth.ActGrant},

	// Configuration decides how every other control behaves, so changing it is
	// an admin act. Reading it is not: an author who cannot see the settings
	// cannot tell why a publish was refused.
	"config":         {action: auth.ActGrant},
	"config show":    {action: auth.ActView},
	"config list":    {action: auth.ActView},
	"config explain": {action: auth.ActView},

	// A webhook is an outbound credential and a data flow to somewhere else.
	// Registering an extension is registering code that runs beside the
	// content store. Admin, and the reading subcommands narrow it.
	"ext":        {action: auth.ActGrant},
	"extensions": {action: auth.ActGrant},
	"ext list":   {action: auth.ActView},
	"ext test":   {action: auth.ActView},

	"webhook":  {action: auth.ActGrant},
	"webhooks": {action: auth.ActGrant},

	// Serving is starting a process that enforces its own authorisation per
	// request, but deciding to expose the store at all is an operator act.
	"serve": {action: auth.ActPublish},
	"site":  {action: auth.ActPublish},
	"mcp":   {action: auth.ActEditDraft},

	// -- deliberately unauthenticated, each with the reason.
	"__sandbox": {why: "is the sandbox shim this program re-executes itself as: " +
		"it restricts its own thread and execve's the extension, and never " +
		"opens the store. Requiring authority here would mean resolving a " +
		"token inside the process that is about to be confined"},
	"init": {why: "creates the store; there is no policy to consult until one exists"},
	"logd": {why: "runs as its own account and derives its authority from the " +
		"socket peer's uid, not from a token in this store"},
	"audit":   {why: "reads template files given as arguments and never opens the store"},
	"version": {why: "prints a version"},
	"help":    {why: "prints usage"},
	"-h":      {why: "prints usage"},
	"--help":  {why: "prints usage"},

	// -- read-only subcommands of otherwise privileged commands, so that
	// somebody locked out can still find out why.
	"auth explain": {action: auth.ActView},
	// The break-glass. It cannot require authority: the situation it exists
	// for is that no credential remains to present. It checks for itself that
	// no usable admin token exists, refuses when one does, and records what it
	// did in a log this account cannot rewrite.
	"auth recover": {why: "recovers a store with no usable admin token, which " +
		"is the one situation where requiring a token is a contradiction"},
	"auth list":    {action: auth.ActView},
	"token list":   {action: auth.ActView},
	"vault status": {action: auth.ActView},
}

// commandResource is the resource a command acts on. Coarse by design: this is
// the outer gate, and the finer per-page checks stay where the page name is
// known. A gate that is correct about the command and coarse about the path is
// worth more than no gate.
func commandResource(cmd string, args []string) string { return "/" }

// unknownCommand explains a name nothing recognises.
//
// Suggestions come from the same table that decides privileges, so a command
// that exists is always offered — there is no second list to fall behind.
func unknownCommand(cmd string) error {
	// The threshold is relative to the shorter word, not to a constant.
	//
	// A fixed two edits is most of a four-letter word and a rounding error in
	// a twelve-letter one, which is how "prov" came back as the suggestion for
	// "aprove". Requiring the distance to be under half the shorter word keeps
	// short aliases from matching everything and still catches a transposition
	// in a five-letter name.
	var near []string
	for known := range commandNeeds {
		if strings.HasPrefix(known, cmd) || strings.HasPrefix(cmd, known) {
			near = append(near, known)
			continue
		}
		shorter := len(cmd)
		if len(known) < shorter {
			shorter = len(known)
		}
		if d := editDistance(cmd, known); d*2 < shorter {
			near = append(near, known)
		}
	}
	sort.Strings(near)
	if len(near) > 4 {
		near = near[:4]
	}
	if len(near) > 0 {
		return fmt.Errorf("there is no %q command. Did you mean %s?\n"+
			"  quilzo help — every command", cmd, strings.Join(near, ", "))
	}
	return fmt.Errorf("there is no %q command.\n  quilzo help — every command",
		cmd)
}

// editDistance is Levenshtein, bounded by the length of the shorter word.
//
// Two rows rather than a full matrix: the words are command names, so this is
// never the expensive part, and the small version is easier to be sure of.
func editDistance(a, b string) int {
	if len(a) > 24 || len(b) > 24 {
		return 99
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

// authoriseCommand is the single point every command passes through.
func authoriseCommand(root, cmd string, args []string) error {
	n, ok := lookupNeed(cmd, args)
	if !ok {
		// A command nobody declared. Refusing is the only safe answer: the
		// alternative is that adding a command silently adds an unguarded one,
		// which is exactly how this hole appeared.
		//
		// What it *says* depends on who is reading. A developer who added a
		// command and forgot the table needs the file name. A person who
		// mistyped needs to know they mistyped — and telling them to edit a Go
		// source file is the worst possible answer to a typo. Every unknown
		// command took the developer message for as long as this check has
		// existed, because the two cases were never distinguished.
		//
		// They are distinguishable: a command in the dispatch switch and
		// absent from the table is the developer's; anything else is a typo,
		// and a test walks the source to guarantee the first case never
		// reaches a user.
		return unknownCommand(cmd)
	}
	if n.action == "" {
		return nil
	}
	// The bootstrap, and the only way out of a chicken and egg that otherwise
	// bricks the store on the first grant.
	//
	// `auth grant alice admin` is permitted when no policy exists, and creates
	// one. From that moment `token issue` needs manage-tokens — which needs a
	// token, which cannot be issued. The store locks itself the instant access
	// control is switched on, and the operator's only recovery is editing JSON
	// by hand.
	//
	// So: issuing is allowed without a token while the token store is empty
	// and the principal being issued to already holds a binding. Both halves
	// matter. It escalates nothing, because when no token exists nobody holds
	// any authority to escalate from — the store is in exactly the state it
	// was in before the grant. And it closes permanently the moment any token
	// exists, rather than staying open as a mode somebody has to remember to
	// turn off.
	if n.action == auth.ActToken && bootstrapIssue(root, cmd, args) {
		return nil
	}
	// Asking a command for help must not require the authority to run it.
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "help" {
			return nil
		}
	}

	caller := resolveCaller(root, tokenFromArgs(args))
	resource := commandResource(cmd, args)
	if err := authorise(root, caller, n.action, resource); err != nil {
		sub := cmd
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			sub = cmd + " " + args[0]
		}
		record(root, caller.auditRecord(sub, resource, audit.Denied,
			map[string]string{"reason": "authorisation"}))
		return err
	}
	return nil
}

// bootstrapIssue reports whether this is the first token being issued to a
// principal the policy already knows.
func bootstrapIssue(root, cmd string, args []string) bool {
	if cmd != "token" || len(args) == 0 || args[0] != "issue" {
		return false
	}
	toks, err := loadTokens(root)
	if err != nil || len(toks.Tokens) > 0 {
		return false
	}
	principal := ""
	for i, a := range args {
		if a == "--principal" && i+1 < len(args) {
			principal = args[i+1]
		}
		if v, ok := strings.CutPrefix(a, "--principal="); ok {
			principal = v
		}
	}
	if principal == "" {
		return false
	}
	p, err := loadPolicy(root)
	if err != nil {
		return false
	}
	for _, b := range p.Bindings {
		if b.Principal == principal {
			return true
		}
	}
	return false
}

func lookupNeed(cmd string, args []string) (need, bool) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		if n, ok := commandNeeds[cmd+" "+args[0]]; ok {
			return n, true
		}
	}
	n, ok := commandNeeds[cmd]
	return n, ok
}

// tokenFromArgs finds --token before the subcommand's own flag parsing runs,
// because the authorisation decision happens before that.
func tokenFromArgs(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--token" && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(args[i], "--token="); ok {
			return v
		}
	}
	return ""
}
