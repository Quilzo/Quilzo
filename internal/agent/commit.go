// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"regexp"
	"strings"
)

// Batchable says whether actions of a commit class may be approved
// together: only those that read or merely act. Anything that writes,
// sends, pays, deletes or publishes is decided one at a time, and so is
// every question.
func Batchable(class string) bool { return class == "reads" || class == "acts" }

var (
	rePays    = regexp.MustCompile(`(?i)\b(pay|payment|purchase|buy|order|checkout|check out|donate|transfer|withdraw|subscribe|book|reserve|renew|upgrade)\b`)
	reDeletes = regexp.MustCompile(`(?i)\b(delete|remove|erase|cancel|deactivate|destroys|unsubscribe)\b`)
	reSends   = regexp.MustCompile(`(?i)\b(send|submit|post|publish|share|invite|sign in|reaches the network|network)\b`)
)

// CommitOf says what letting an action go ahead commits to, from the
// action and the reason it waits: reads, acts, writes, sends, pays,
// deletes, publishes, or answers for a question. writes says a tool is
// declared as one that changes something.
func CommitOf(a Action, why, kind string, writes bool) string {
	if kind == WaitQuestion {
		return "answers"
	}
	if a.Delegate != "" {
		return "acts"
	}
	if a.Tool != "" {
		// A tool call that pays says so in why (internal/spend): paying is
		// what it commits to, whatever else it changes, and paying is never
		// earned away.
		if strings.HasPrefix(why, PaysPrefix) {
			return "pays"
		}
		// A triggered run's write to another system waits because it goes
		// out, so it is a send: decided one at a time, by somebody other
		// than the starter where there is one, and never earned away. As a
		// write it was earnable, so a kind of call approved often enough by
		// hand in runs a person started would have gone out unasked from
		// one nobody started.
		if strings.HasPrefix(why, UnattendedPrefix) {
			return "sends"
		}
		// So is a write that says what the brand rules refuse: it carries a
		// claim to another system's readers, and a person reads what the
		// rules found each time. As a write it was earnable, so a kind of
		// call approved often enough for any other reason would have
		// carried the claim out with nobody shown it.
		if strings.HasPrefix(why, ClaimsPrefix) {
			return "sends"
		}
		if writes {
			return "writes"
		}
		return "reads"
	}
	op := a.Op
	switch {
	case strings.HasPrefix(op, "publish"):
		return "publishes"
	case op == "browser_open" || op == "browser_type" || op == "desktop_type" || op == "browser_sign_in" ||
		op == "web_fetch" || op == "web_search":
		// What waits of these carries the model's words to a host: an
		// address, typing, a query.
		return "sends"
	case op == "file_delete":
		// Into the bin is a write a person can take back; out of the bin
		// is not.
		if strings.Contains(why, "nothing brings back") {
			return "deletes"
		}
		return "writes"
	case op == "shell_run" || op == "code_run":
		// A command that would reach the network from a run nobody
		// started waits because it goes out, as a tool's write from such a
		// run does, and so is a send unless it deletes as well: as a write
		// it was earnable, so a kind of command approved often enough by
		// hand in runs a person started would have reached out unasked
		// from one nobody started.
		switch {
		case reDeletes.MatchString(why):
			return "deletes"
		case reSends.MatchString(why) || strings.HasPrefix(why, UnattendedPrefix):
			return "sends"
		}
		return "writes"
	case op == "write_page" || op == "file_write" || op == "file_edit" || op == "file_move" || op == "browser_save" ||
		op == "remember" || op == "forget" ||
		strings.HasPrefix(op, "write_") || strings.HasPrefix(op, "create_") || strings.HasPrefix(op, "update_") ||
		strings.HasPrefix(op, "delete_"):
		if strings.HasPrefix(op, "delete_") || op == "forget" {
			return "deletes"
		}
		return "writes"
	case strings.HasPrefix(op, "read_") || strings.HasPrefix(op, "list_") || strings.HasPrefix(op, "search") ||
		op == "recall" || op == "browser_read" || op == "browser_look" || op == "desktop_read" ||
		op == "browser_scroll" || op == "browser_wait" || op == "browser_hover" || op == "browser_console" ||
		op == "browser_check" || op == "browser_emulate" || op == "browser_navigate" ||
		op == "desktop_look" || op == "file_read" || op == "file_list" || op == "file_search" || op == "decide":
		return "reads"
	}
	switch {
	case rePays.MatchString(why):
		return "pays"
	case reDeletes.MatchString(why):
		return "deletes"
	case reSends.MatchString(why) || strings.HasPrefix(why, UnattendedPrefix):
		// What a hand carries out of a run nobody started is a send
		// whatever else its reason says: a file put into a page, for one.
		return "sends"
	}
	return "acts"
}

// PaysPrefix begins the reason a paying tool call waits for a person.
const PaysPrefix = "it pays "

// UnattendedPrefix begins the reason a triggered run's write to another
// system, or its hands' reach out to one, waits for a person: what goes
// out from a run nobody started is a person's decision, unless
// administrators granted the agent that tool's or that hand's unattended
// sends (cmd/quilzo agentsends.go).
const UnattendedPrefix = "it goes out from a run nobody started"

// ClaimsPrefix begins the reason a tool's write waits for a person when
// what it would say breaks the brand rules the site is published under, or
// those rules could not be read (cmd/quilzo brandcmd.go).
const ClaimsPrefix = "the brand rules hold it"
