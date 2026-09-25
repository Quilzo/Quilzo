// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	stdpath "path"
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
	"form":     {action: auth.ActEditDraft},
	"forms":    {action: auth.ActEditDraft},
	"listing":  {action: auth.ActView},
	"listings": {action: auth.ActView},
	"terms":    {action: auth.ActView},
	"taxonomy": {action: auth.ActView},
	"menu":     {action: auth.ActView},
	"menus":    {action: auth.ActView},
	"siem":     {action: auth.ActView},
	"a11y":     {action: auth.ActView},
	"verify":   {action: auth.ActView},
	"scan":     {action: auth.ActView},
	"csp":      {action: auth.ActView},
	// Reading what this deployment may connect to is a view. Changing it is
	// `config set`, which is already privileged.
	"network":    {action: auth.ActView},
	"marking":    {action: auth.ActView},
	"transfer":   {action: auth.ActView},
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
	"rights": {action: auth.ActView},
	// Listing what this install may reach is reading configuration. Calling a
	// tool is checked inside the command against ActPublish, because only that
	// half leaves the machine — and a call into somebody else's system is the
	// one action here that nothing can roll back.
	"integrations":    {action: auth.ActView},
	"integration":     {action: auth.ActView},
	"agent templates": {action: auth.ActView},
	"agent list":      {action: auth.ActView},
	"agent show":      {action: auth.ActView},
	"agent check":     {action: auth.ActView},
	// Running one acts under the agent's manifest, and the least it can do is
	// read the store. Author rather than view: a run writes an audit record
	// attributed to the caller, and an entry somebody could create without
	// being able to change anything would be a way to write the log.
	"agent run": {action: auth.ActEditDraft},
	// Writing the signing key and reading the follower list are both
	// administrative: the key is the credential that speaks for the whole site
	// to everybody following it, and the follower list names people who read
	// this site, which is not public information.
	"fediverse":  {action: auth.ActGrant},
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
	// The theme is what every page is rendered against, so changing it changes
	// what every reader sees — the same authority as changing the template, and
	// for the same reason.
	// Reading a file somebody hands it and saying whether the events in it
	// are usable. Touches no store and writes nothing, so it is the authority
	// to look rather than the authority to change anything — and the person
	// most likely to run it is whoever is writing a connector, who may well
	// have been given nothing else.
	"telemetry": {action: auth.ActView},

	"theme": {action: auth.ActEditDraft},
	// Sections are content: adding, moving and removing one writes a draft
	// commit, so it is the authority an author already has over a page.
	"section":  {action: auth.ActEditDraft},
	"sections": {action: auth.ActEditDraft},
	// Runs a server that publishes on behalf of Telegram accounts. That is the
	// publish authority, delegated — so the operator starting it needs to hold
	// it, whatever the person in the chat holds.
	// Reading. The settings half asks for grant separately inside the command,
	// because a key's summary describes a control and the rest is content.
	"find": {action: auth.ActView},
	// Reading which pages name which is reading the content and the types.
	"links": {action: auth.ActView},
	// Moving a page rewrites content, so it is an author's act — and the
	// command checks both ends itself, because a move out of somebody's
	// subtree takes a page out of their reach and a move in puts one where
	// they may not have meant to.
	"move": {action: auth.ActEditDraft},
	// Editing a draft. A note is a remark about content, made by somebody who
	// is working on it — so it takes the same authority the draft does.
	// Saying a page is still right is a statement about the draft, made by
	// somebody who works on it.
	"checked":  {action: auth.ActEditDraft},
	"note":     {action: auth.ActEditDraft},
	"notes":    {action: auth.ActEditDraft},
	"telegram": {action: auth.ActPublish},
	// The same as telegram, and for the same reason: each starts a surface
	// that publishes on behalf of somebody else's account.
	"slack":   {action: auth.ActPublish},
	"discord": {action: auth.ActPublish},

	// -- content types gate every write, so changing one is a change to what
	// every author may store. Publisher, not author.
	"type":  {action: auth.ActPublish},
	"types": {action: auth.ActPublish},

	// Listing and showing are reads. Splitting these is not politeness: a
	// reader who cannot list the types cannot tell why their content was
	// refused, and an authorisation model that makes the error message
	// unreachable gets turned off.
	"type list":        {action: auth.ActView},
	"type show":        {action: auth.ActView},
	"type check":       {action: auth.ActView},
	"type example":     {action: auth.ActView},
	"type stub":        {action: auth.ActView},
	"types example":    {action: auth.ActView},
	"types list":       {action: auth.ActView},
	"types show":       {action: auth.ActView},
	"template list":    {action: auth.ActView},
	"template show":    {action: auth.ActView},
	"template layouts": {action: auth.ActView},
	"theme show":       {action: auth.ActView},
	"theme tokens":     {action: auth.ActView},
	"theme check":      {action: auth.ActView},
	"theme fonts":      {action: auth.ActView},
	"theme css":        {action: auth.ActView},
	// Exporting is `theme css` in another format: it reads what is set and
	// writes nothing here. The person most likely to ask is a designer who
	// was given view and nothing else, and shutting the export to exactly
	// them would make the answer "email me the hex values".
	"theme export":    {action: auth.ActView},
	"section list":    {action: auth.ActView},
	"section kinds":   {action: auth.ActView},
	"section fields":  {action: auth.ActView},
	"telegram check":  {action: auth.ActView},
	"telegram link":   {action: auth.ActPublish},
	"sections fields": {action: auth.ActView},
	"sections list":   {action: auth.ActView},
	"sections kinds":  {action: auth.ActView},
	"templates list":  {action: auth.ActView},
	"templates show":  {action: auth.ActView},
	"lock list":       {action: auth.ActView},
	"locks list":      {action: auth.ActView},
	"review status":   {action: auth.ActView},
	"schedule list":   {action: auth.ActView},
	"media formats":   {action: auth.ActView},
	"media list":      {action: auth.ActView},
	// Checking a manifest changes nothing, and the person most likely to ask
	// is an auditor who has been given view and nothing else. Inheriting the
	// parent's edit-draft would shut the check to exactly them.
	"media verify":     {action: auth.ActView},
	"media edit":       {action: auth.ActEditDraft},
	"media generate":   {action: auth.ActEditDraft},
	"media captions":   {action: auth.ActEditDraft},
	"agent probe":      {action: auth.ActView},
	"media remove":     {action: auth.ActEditDraft},
	"media renditions": {action: auth.ActEditDraft},
	"lang check":       {action: auth.ActView},
	"locales check":    {action: auth.ActView},
	"posture scan":     {action: auth.ActView},
	"posture rules":    {action: auth.ActView},
	"posture explain":  {action: auth.ActView},
	"webhook list":     {action: auth.ActView},
	"webhooks list":    {action: auth.ActView},
	"oidc check":       {action: auth.ActView},
	"logd status":      {action: auth.ActView},

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
	// The capture surface enforces edit-draft per request, and it runs a
	// script on a writable origin. Deciding to open that at all is the
	// operator act, so it is held to the same bar as opening the admin.
	"studio": {action: auth.ActPublish},
	"mcp":    {action: auth.ActEditDraft},

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
	// The option spellings as well as the subcommands. The GNU Coding
	// Standards ask for --version and --help, and the reason is not ceremony:
	// a packaging tool checking a program's version tries --version and
	// nothing else, so a `version` subcommand alone is unreachable to
	// everything that looks. These reach the same two branches.
	"--version": {why: "prints a version"},
	"-V":        {why: "prints a version"},
	"-h":        {why: "prints usage"},
	"--help":    {why: "prints usage"},

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

// Which page a command is about, so that a binding scoped to part of the site
// means something on the command line.
//
// # What was wrong
//
// This used to be one line returning "/" for everything, and its comment
// called that coarse by design: "the finer per-page checks stay where the page
// name is known". There were no finer per-page checks. Every authorise() call
// on this surface passes "/", so the coarse gate was the only gate, and being
// coarse had two consequences that are not the same shape.
//
// A grant narrowed with --on /blog stopped working altogether. covers("/blog",
// "/") is false, so an author scoped to part of the site could run no command
// at all, and the flag the help text calls "enforced" was a way to lock
// somebody out. That is the wrong answer, but it is the safe wrong answer.
//
// A deny narrowed the same way stopped working too, and that one is a hole. A
// publisher denied on /legal still holds publisher on "/"; the deny does not
// cover "/"; the target was always "/". So the deny never matched, and
// `quilzo section set legal/notice 0 body=…` was permitted by the very policy
// written to forbid it. The browser interface enforced it and the command line
// did not, which is worse than not having the feature at all: somebody reads
// the policy, sees the deny, and believes it.
//
// # Why a table, and why it is allowed to give up
//
// The page has to be identified before the command parses its own arguments,
// which is the awkward part — at this point `args` is just words. Most
// commands make that easy by taking their positional arguments first and
// finding them with leadingArgs, which stops at the first flag. Those get a
// row here naming which positional is the page, read with leadingArgs itself,
// so the gate and the command cannot disagree about which word they are
// looking at.
//
// Anything not in the table, and anything in it whose page argument is missing
// or is not a name this can be sure of, falls back to "/". That is the strict
// direction: "/" is covered only by a binding on the whole site, so a command
// this cannot read is authorised as though it touched everything. A new
// command therefore arrives over-guarded, which is a bug report, rather than
// under-guarded, which is a breach.
//
// The corollary is the one thing that must not be got wrong: a row here is a
// claim that the command touches *that page and nothing else*. A row for a
// command that also writes somewhere else would narrow the check away from the
// place it was needed.

// wholeStore is the page-argument index meaning "this one names no page".
//
// Spelled out rather than left absent, because absence falls through to the
// parent's row: without "lock list" saying so, `quilzo lock list` would read
// the word "list" as the name of a page.
const wholeStore = -1

// pageArgs names, for each command that takes one, which of its positional
// arguments is the page.
//
// Keyed like commandNeeds — "command" or "command subcommand", the more
// specific winning — and the index counts the positional arguments after
// whichever key matched.
//
// A bare command has a row only where its own dispatch treats an unrecognised
// first word as a page name, which is true of `lock` and of nothing else here;
// every subcommand it recognises is then listed too.
var pageArgs = map[string]int{
	// Saying a page is still right, and withdrawing that.
	"checked set":    0,
	"checked clear":  0,
	"checked own":    0,
	"checked disown": 0,
	"checked list":   wholeStore,
	"checked due":    wholeStore,

	// Remarks about a page. `note list` takes an optional page and surveys
	// everything without one, which the missing-argument fallback handles.
	"note add":      0,
	"note list":     0,
	"note resolve":  0,
	"note remove":   0,
	"note rm":       0,
	"notes add":     0,
	"notes list":    0,
	"notes resolve": 0,
	"notes remove":  0,
	"notes rm":      0,

	// lock's dispatch sends anything that is not list or release to
	// lockClaim, so the bare row is right by construction and the two it
	// recognises are named. A subcommand added to that switch needs a row.
	"lock":          0,
	"lock list":     wholeStore,
	"lock release":  0,
	"locks":         0,
	"locks list":    wholeStore,
	"locks release": 0,

	// Sections are parts of one page. `section item` puts the verb first, so
	// the page is the second positional after it.
	"section add":     0,
	"section remove":  0,
	"section rm":      0,
	"section move":    0,
	"section mv":      0,
	"section fields":  0,
	"section set":     0,
	"section list":    0,
	"section item":    1,
	"section kinds":   wholeStore,
	"sections add":    0,
	"sections remove": 0,
	"sections rm":     0,
	"sections move":   0,
	"sections mv":     0,
	"sections fields": 0,
	"sections set":    0,
	"sections list":   0,
	"sections item":   1,
	"sections kinds":  wholeStore,

	// Binding a page to a content type, and saying where its bytes came from.
	"type bind":      0,
	"types bind":     0,
	"provenance set": 0,
	"prov set":       0,

	// Recording that one page was translated from its source.
	"lang translated":    0,
	"locales translated": 0,
}

// pageResolvers is for the commands whose page arguments cannot be found by
// position, because their flags may appear anywhere.
//
// One entry, and it should stay a short list: every one of these is a second
// reading of arguments the command reads for itself, which is the shape of
// thing that drifts. `add` earns it because it is the command people actually
// write content with, and leaving it at "/" would mean the flag that scopes an
// author to part of the site still did nothing for the one thing authors do.
var pageResolvers = map[string]func(args []string) []string{
	"add": addResources,
}

// addResources is the pages `add` writes: the name on the left of each
// NAME=FILE argument, and the names --remove deletes.
//
// It reads the arguments with splitFlags and the same flag table cmdAdd
// parses with, so the two cannot disagree about which words are positional.
// Anything it cannot account for — a spec with no "=", a --remove it cannot
// read — returns nothing, and nothing means the whole store.
func addResources(args []string) []string {
	flags, positional := splitFlags(args, addValued)
	var pages []string
	for _, spec := range positional {
		name, _, ok := strings.Cut(spec, "=")
		if !ok {
			// cmdAdd refuses this too. Until it does, the honest answer about
			// what is being written is "something I cannot name".
			return nil
		}
		pages = append(pages, name)
	}
	for i := 0; i < len(flags); i++ {
		list, present, readable := removeFlag(flags, i)
		if !present {
			continue
		}
		if !readable {
			// The flag is there and its value is not, so which pages this
			// deletes is unknown.
			return nil
		}
		for _, name := range strings.Split(list, ",") {
			if name = strings.TrimSpace(name); name != "" {
				pages = append(pages, name)
			}
		}
	}
	return pages
}

// removeFlag reads --remove at flags[i], in either spelling and either form.
//
// Three answers rather than two, because "this is not --remove" and "this is
// --remove and I cannot see its value" must not both be the empty string:
// the first means carry on, the second means give up on the whole command.
func removeFlag(flags []string, i int) (list string, present, readable bool) {
	f := flags[i]
	for _, prefix := range []string{"--remove=", "-remove="} {
		if v, ok := strings.CutPrefix(f, prefix); ok {
			return v, true, true
		}
	}
	if f == "--remove" || f == "-remove" {
		if i+1 < len(flags) {
			return flags[i+1], true, true
		}
		return "", true, false
	}
	return "", false, false
}

// commandResources is every resource a command acts on. Permission is needed
// on all of them.
func commandResources(cmd string, args []string) []string {
	if resolve, ok := pageResolvers[cmd]; ok {
		return resourcesFor(resolve(args))
	}
	idx, rest, ok := pageArgOf(cmd, args)
	if !ok {
		return []string{"/"}
	}
	pos, _ := leadingArgs(rest, idx+1)
	if len(pos) <= idx {
		// The argument is not there. The command will say so in its own words;
		// until then the strict answer is the whole store rather than a guess.
		return []string{"/"}
	}
	return resourcesFor([]string{pos[idx]})
}

// pageArgOf finds the row for a command, resolved the way lookupNeed resolves
// its own: the subcommand key first, the bare command second.
func pageArgOf(cmd string, args []string) (idx int, rest []string, ok bool) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		if n, found := pageArgs[cmd+" "+args[0]]; found {
			// A subcommand that names no page stops here rather than falling
			// through to the parent's row, which would read its own name as a
			// page.
			return n, args[1:], n >= 0
		}
	}
	if n, found := pageArgs[cmd]; found {
		return n, args, n >= 0
	}
	return 0, nil, false
}

// resourcesFor turns page names into resource paths, in order and without
// repeats, and gives up as a whole if any name is one it cannot vouch for.
//
// All or nothing on purpose. Dropping the name it could not read and checking
// the rest would authorise a write against the pages it understood and let the
// one it did not through unexamined.
func resourcesFor(pages []string) []string {
	if len(pages) == 0 {
		return []string{"/"}
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range pages {
		r := pageResource(p)
		if r == "/" {
			return []string{"/"}
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// pageResource is the resource path for a page name, or "/" when the name is
// not one this can be sure of.
//
// Refused rather than repaired, the same rule the admin's back-links follow: a
// name that does not survive path.Clean is not a page this store holds, and
// cleaning it quietly would authorise one path and act on another.
func pageResource(page string) string {
	page = strings.TrimSpace(page)
	if page == "" || strings.HasPrefix(page, "-") {
		return "/"
	}
	r := "/" + strings.TrimPrefix(page, "/")
	if stdpath.Clean(r) != r {
		return "/"
	}
	return r
}

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
	// Every resource, not the first one. A command that writes two pages needs
	// the authority for both, and stopping at the first would let a deny on
	// the second page be worked around by naming a permitted page alongside it.
	for _, resource := range commandResources(cmd, args) {
		if err := authorise(root, caller, n.action, resource); err != nil {
			sub := cmd
			if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
				sub = cmd + " " + args[0]
			}
			record(root, caller.auditRecord(sub, resource, audit.Denied,
				map[string]string{"reason": "authorisation"}))
			return err
		}
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
	// The global pass in main has already taken it out of the arguments, so
	// there is nothing left here to scan for. Kept as a function because the
	// alternative is the authorisation path reading a package variable
	// directly, and this way the one call site says what it is asking for.
	return flagToken
}
