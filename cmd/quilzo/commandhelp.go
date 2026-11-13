// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Asking a command for help, as `quilzo CMD --help` or `quilzo CMD SUB -h`.
//
// The flag was left to each command, and most did not read it. A command
// that does not parse its arguments, or reads the first one as a name, ran:
// `quilzo init --help` in an empty directory created a store there, `quilzo
// fediverse init --help` wrote a signing key, `quilzo browser install --help`
// started a 118 MB download, `quilzo fediverse block --help` refused an
// instance called "--help", and `quilzo token keygen --help` wrote a key to a
// file of that name. Others answered with an error about the word: `quilzo
// oidc --help` was "unknown oidc command", `quilzo saml add --help` one usage
// line and exit 1. A command whose flag set did read it listed its flags and
// then failed, "flag: help requested", exit 1, so a script asking whether a
// command exists was told it does not.
//
// So the question is answered here, before any command runs and before
// anything is moved or opened: the lines of the help about the command, and
// exit 0. A command that answers it itself (helpGoesToTheCommand) is let
// through after those lines so that its flag set lists its flags, and main
// treats the flag.ErrHelp that comes back as the answer it is. A test asks
// every command and subcommand, in an empty directory and in a fresh store,
// and fails on anything written.

// helpAsked reports whether the arguments ask for help. Everything after
// "--" belongs to a program the command runs, whose own -h is not ours.
func helpAsked(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if isHelpFlag(a) {
			return true
		}
	}
	return false
}

// isHelpFlag reports whether a is a spelling a flag set answers as help: -h
// or -help, with one dash or two, with or without a value after "=". Only
// three of the eight were taken, and a flag set answered the rest itself,
// after the command had acted: `quilzo init --h` created a store and then
// failed, and `quilzo token keygen --help=true` wrote a key to a file of that
// name.
func isHelpFlag(a string) bool {
	name, ok := strings.CutPrefix(a, "-")
	if !ok {
		return false
	}
	name, _, _ = strings.Cut(strings.TrimPrefix(name, "-"), "=")
	return name == "h" || name == "help"
}

// helpGoesToTheCommand reports whether the command answers the help itself:
// it parses its flags before anything else, and the help flag is the first
// thing after its name. A flag set stops at the first argument that is not a
// flag, so `quilzo booking list x -h` never reached the -h and listed the
// bookings; with anything before the flag, the help's lines are the answer.
func helpGoesToTheCommand(cmd string, args []string) bool {
	key := helpKey(cmd, args)
	if !answersOwnHelp[key] {
		return false
	}
	if strings.Contains(key, " ") {
		args = args[1:]
	}
	return len(args) > 0 && isHelpFlag(args[0])
}

// helpAfter reports whether `quilzo CMD help` asks for CMD's help, as
// `quilzo help CMD` does: CMD takes a subcommand, so "help" where one goes
// is a question and not a page's or an assistant's name. `quilzo decide
// help` answered "unknown decide command "help"", which tells somebody
// typing the natural thing that the command does not exist, and other
// commands took the word as one more argument and ran.
//
// Read from the help, which a test holds to the code's own switches. Left
// to the command where its help names a subcommand called help (`quilzo geo
// help` is its own answer), and where a page or a name may go in the same
// place (`quilzo lock PAGE`), since there "help" is somebody's page.
//
// And where CMD takes nothing but flags, since there "help" can be nothing
// else. Such a command ran with the word left over: `quilzo rollback help`
// put the live site back a version, `quilzo init help` made a store, and
// `quilzo serve help` started the admin.
func helpAfter(cmd string, args []string) bool {
	if len(args) == 0 || args[0] != "help" {
		return false
	}
	if primary, ok := helpAliases[cmd]; ok {
		cmd = primary
	}
	subs, lines, onlyFlags := false, 0, true
	for _, line := range strings.Split(usageText, "\n") {
		rest, ok := strings.CutPrefix(line, "  quilzo "+cmd)
		if !ok || rest == "" || rest[0] != ' ' {
			continue
		}
		lines++
		// What comes before the description. A line whose description
		// follows the command's name has none, and its first word is not
		// a subcommand.
		synopsis := rest[1:]
		if i := helpDescription.FindStringIndex(synopsis); i != nil {
			synopsis = synopsis[:i[0]]
		}
		for _, b := range helpBracketed.FindAllString(synopsis, -1) {
			onlyFlags = onlyFlags && strings.HasPrefix(b, "[-")
		}
		synopsis = helpBracketed.ReplaceAllString(synopsis, " ")
		for _, f := range strings.Fields(synopsis) {
			onlyFlags = onlyFlags && strings.HasPrefix(f, "-")
		}
		for i, alt := range strings.Split(synopsis, " | ") {
			fields := strings.Fields(alt)
			if len(fields) == 0 {
				continue
			}
			for _, w := range strings.Split(fields[0], "|") {
				switch {
				case w == "help":
					return false
				case helpSubcommand.MatchString(w):
					subs = true
				case i == 0 && helpName.MatchString(w):
					// Read in the first alternative only: after a spaced
					// pipe a value may stand alone, as "tool:T" does.
					return false
				}
			}
		}
	}
	return subs || lines > 0 && onlyFlags
}

// helpAfterSub reports whether `quilzo CMD SUB help` asks for the help of
// CMD SUB: everywhere the help names SUB, it takes nothing after it but
// flags and their values, so "help" there can be nothing but a question.
// Such a subcommand ran with the word left over, as `quilzo rollback help`
// did a level up: `quilzo vault enable help` sealed the store and printed
// its key, `quilzo memory forget help` made every agent forget the
// operator, `quilzo fediverse init help` wrote a signing key, and `quilzo
// review approve help` approved the draft for anybody but its author.
//
// Where SUB takes a name, "help" is left to be one: `quilzo decide ask
// help` asks the decider called help.
func helpAfterSub(cmd string, args []string) bool {
	if len(args) < 2 || args[1] != "help" || !helpSubcommand.MatchString(args[0]) {
		return false
	}
	if primary, ok := helpAliases[cmd]; ok {
		cmd = primary
	}
	named := false
	for _, line := range strings.Split(usageText, "\n") {
		rest, ok := strings.CutPrefix(line, "  quilzo "+cmd)
		if !ok || rest == "" || rest[0] != ' ' {
			continue
		}
		synopsis := rest[1:]
		if i := helpDescription.FindStringIndex(synopsis); i != nil {
			synopsis = synopsis[:i[0]]
		}
		for _, alt := range strings.Split(synopsis, " | ") {
			fields := strings.Fields(alt)
			if len(fields) == 0 || !slices.Contains(strings.Split(fields[0], "|"), args[0]) {
				continue
			}
			named = true
			after := strings.Join(fields[1:], " ")
			for _, b := range helpBracketed.FindAllString(after, -1) {
				if !strings.HasPrefix(b, "[-") {
					return false
				}
			}
			// A flag's value follows it, written as a name: the FILE of
			// `auditlog export -o FILE`.
			prev := ""
			for _, f := range strings.Fields(helpBracketed.ReplaceAllString(after, " ")) {
				if !strings.HasPrefix(f, "-") && !(strings.HasPrefix(prev, "-") && helpName.MatchString(f)) {
					return false
				}
				prev = f
			}
		}
	}
	return named
}

// helpSubcommand is how a subcommand is written in the help, a lowercase
// word, and helpName how a name a command takes is: in capitals, or quoted.
var (
	helpSubcommand = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	helpName       = regexp.MustCompile(`^["A-Z]`)
)

// helpOrVersion are the spellings that print the help or the version, which
// main answers itself.
var helpOrVersion = map[string]bool{"help": true, "-h": true, "--help": true,
	"version": true, "--version": true, "-V": true}

// helpAliases maps a second spelling of a command to the one the help uses,
// so that `quilzo forms --help` finds the lines about `quilzo form`.
var helpAliases = map[string]string{
	"environments": "env", "extensions": "ext", "forms": "form",
	"integration": "integrations", "listings": "listing", "locales": "lang",
	"locks": "lock", "menus": "menu", "notes": "note", "prov": "provenance",
	"record": "records", "sections": "section", "stamp": "timestamp",
	"taxonomy": "terms", "templates": "template", "types": "type",
	"webhooks": "webhook",
}

// helpKey is the command and subcommand help was asked of, under the
// spelling the help uses: "token issue" for `quilzo token issue --help`, and
// "serve" for `quilzo serve --help`.
func helpKey(cmd string, args []string) string {
	if primary, ok := helpAliases[cmd]; ok {
		cmd = primary
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return cmd + " " + args[0]
	}
	return cmd
}

// answersOwnHelp is every command that parses its flags before it does
// anything else, so that --help reaches its flag set first and nothing runs.
// The flag set's list says what each flag is for, which the help's one line
// cannot, and it was the answer these commands gave before.
//
// Listed rather than assumed: a command left out answers with the help's
// lines alone, which is safe, and a command listed that starts doing
// something before it parses is caught by the test that asks them all.
var answersOwnHelp = map[string]bool{}

func init() {
	for _, key := range []string{
		"a11y", "add", "agent cost", "agent could", "agent declare", "agent draft",
		"agent export", "agent import", "agent probe", "agent run", "agent workspace",
		"analytics", "anchor export", "anchor submit", "annotate follow", "apps could",
		"assist", "assistant action", "assistant add", "assurance record",
		"assurance report", "assurance show", "auditlog consistency", "auditlog head",
		"auditlog show", "auth deny", "auth explain", "auth grant", "auth revoke",
		"backup create", "backup restore", "booking cancel", "booking feed",
		"booking list", "brand check", "call cost", "call demo", "cell warm",
		"checked due", "checked list", "checked set", "compliance accessibility",
		"compliance ai-act", "compliance component", "compliance ksi",
		"compliance site", "compliance ssp", "connect revoke", "csp", "demo",
		"engagement check", "engagement issue", "engagement open", "entity relies",
		"entity report", "env promote", "errand demo", "experiment add",
		"experiment report", "export", "feature approve", "feature capture",
		"feature check", "feature decline", "feature draft", "feature export",
		"feature from", "feature install", "feature proposals", "feature remove",
		"feature rollback", "find", "fleet", "fleet add", "fleet shadow", "flow demo",
		"form erase", "framework adopt", "framework map", "framework status",
		"gateway budget", "huddle demo", "import", "inbox reply", "integrations call",
		"integrations gateway", "integrations import", "integrations template",
		"ipfs id", "ipfs verify", "ipfs write", "lang translated", "links",
		"listing run", "lock", "log", "logd", "mcp", "media add", "media captions",
		"media edit", "media film", "media focus", "media generate", "media get",
		"media list", "media origin", "media remove", "media renditions",
		"media replace", "media speak", "media transcribe", "memory forget",
		"memory history", "memory list", "memory receipt", "menu add", "menu remove",
		"move", "note add", "note list", "oidc check", "oidc configure", "pay enable",
		"pay orders", "personalise add", "personalise test", "policy export",
		"policy import", "policy propose", "posture frameworks", "posture scan",
		"posture suppress", "provenance backfill", "provenance check",
		"provenance set", "publish", "records add", "records export", "records import",
		"records list", "redirect add", "render", "research add", "research cite",
		"research claim", "research ideas", "research new", "research plan",
		"research report", "research run", "research search", "review approve",
		"review require", "rollback", "room open", "room react", "room read",
		"room remove", "room say", "scan", "schedule add", "schedule run",
		"scim token", "screen cost", "scribe demo", "section add", "section block",
		"section backdrop", "section blocks", "section fields", "section kinds", "section list",
		"section move", "section reuse", "serve", "sframe check", "sframe suites",
		"share", "shield block", "shield dry-run", "shield hold", "shield lift",
		"shield list", "shield release", "siem", "site", "site fill", "site import",
		"site new", "spend grant", "studio", "template adopt", "template use",
		"theme apply", "theme check", "theme css", "theme export", "theme fonts",
		"theme generate", "theme import", "theme layer", "theme set", "theme show", "theme tokens",
		"theme unset", "timestamp export", "timestamp stamp", "token exchange",
		"token issue", "token proof", "token stale", "transfer record", "trust add",
		"type bind", "type bind-collection", "vault enable", "vault rewrap",
		"vault rotate", "webhook add",
	} {
		answersOwnHelp[key] = true
	}
}

// commandHelp prints the lines of the help about the command, and the
// subcommand when the help has lines for it. The whole help when it has none,
// which is a command it does not describe.
func commandHelp(cmd string, args []string) {
	text := helpFor(cmd, args)
	if text == "" {
		usage()
		return
	}
	fmt.Print(text)
	fmt.Printf("\n  %severy command, and the exit codes: quilzo help%s\n", dim, reset)
}

// helpFor is the entries of usageText about the command: each line that
// names it, with the lines indented under it that go on to describe it.
func helpFor(cmd string, args []string) string {
	if primary, ok := helpAliases[cmd]; ok {
		cmd = primary
	}
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
	}
	var all, ofSub []string
	lines := strings.Split(usageText, "\n")
	for i := 0; i < len(lines); i++ {
		rest, ok := strings.CutPrefix(lines[i], "  quilzo "+cmd)
		if !ok || (rest != "" && rest[0] != ' ') {
			continue
		}
		entry := lines[i]
		for i+1 < len(lines) && strings.HasPrefix(lines[i+1], "    ") {
			i++
			entry += "\n" + lines[i]
		}
		all = append(all, entry)
		if sub != "" && helpNames(rest, sub) {
			ofSub = append(ofSub, entry)
		}
	}
	if len(ofSub) > 0 {
		all = ofSub
	}
	if len(all) == 0 {
		return ""
	}
	return strings.Join(all, "\n") + "\n"
}

var (
	helpDescription = regexp.MustCompile(`\s{2,}`)
	helpBracketed   = regexp.MustCompile(`\[[^\]]*\]`)
)

// helpNames reports whether an entry's synopsis offers sub where a
// subcommand goes: "list | show NAME | remove NAME" offers list, show and
// remove, and "ocsf|cef|jsonl --envelope F" each of the three. The same
// reading as the test that checks the help against the code.
func helpNames(synopsis, sub string) bool {
	synopsis = strings.TrimLeft(synopsis, " ")
	if i := helpDescription.FindStringIndex(synopsis); i != nil {
		synopsis = synopsis[:i[0]]
	}
	synopsis = helpBracketed.ReplaceAllString(synopsis, " ")
	for _, alt := range strings.Split(synopsis, " | ") {
		fields := strings.Fields(alt)
		if len(fields) == 0 {
			continue
		}
		for _, w := range strings.Split(fields[0], "|") {
			if w == sub {
				return true
			}
		}
	}
	return false
}
