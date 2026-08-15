package main

import (
	"fmt"
	"strings"

	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/auth"
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
	"diff":       {action: auth.ActView},
	"log":        {action: auth.ActView},
	"render":     {action: auth.ActView},
	"export":     {action: auth.ActView},
	"siem":       {action: auth.ActView},
	"a11y":       {action: auth.ActView},
	"verify":     {action: auth.ActView},
	"compliance": {action: auth.ActView},
	"agents":     {action: auth.ActView},
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
	"add":       {action: auth.ActEditDraft},
	"import":    {action: auth.ActEditDraft},
	"assist":    {action: auth.ActEditDraft},
	"media":     {action: auth.ActEditDraft},
	"lang":      {action: auth.ActEditDraft},
	"locales":   {action: auth.ActEditDraft},
	"lock":      {action: auth.ActEditDraft},
	"locks":     {action: auth.ActEditDraft},
	"review":    {action: auth.ActEditDraft},
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
	"publish":  {action: auth.ActPublish},
	"rollback": {action: auth.ActRollback},
	"schedule": {action: auth.ActPublish},

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
	"webhook":  {action: auth.ActGrant},
	"webhooks": {action: auth.ActGrant},

	// Serving is starting a process that enforces its own authorisation per
	// request, but deciding to expose the store at all is an operator act.
	"serve": {action: auth.ActPublish},
	"site":  {action: auth.ActPublish},
	"mcp":   {action: auth.ActEditDraft},

	// -- deliberately unauthenticated, each with the reason.
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
	"auth list":    {action: auth.ActView},
	"token list":   {action: auth.ActView},
	"vault status": {action: auth.ActView},
}

// commandResource is the resource a command acts on. Coarse by design: this is
// the outer gate, and the finer per-page checks stay where the page name is
// known. A gate that is correct about the command and coarse about the path is
// worth more than no gate.
func commandResource(cmd string, args []string) string { return "/" }

// authoriseCommand is the single point every command passes through.
func authoriseCommand(root, cmd string, args []string) error {
	n, ok := lookupNeed(cmd, args)
	if !ok {
		// A command nobody declared. Refusing is the only safe answer: the
		// alternative is that adding a command silently adds an unguarded one,
		// which is exactly how this hole appeared.
		return fmt.Errorf("%q has no declared privilege, so it will not run. "+
			"Add it to commandNeeds in cmd/scrivet/privilege.go", cmd)
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
