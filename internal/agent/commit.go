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

// What a reason says an action does. A reason is written in the third
// person ("it submits a form", "a form that sends", "it deletes"), and a
// control's name, which a reason quotes, as a command ("Pay now",
// "Delete"), so each verb is matched in both forms. Other forms are not:
// "booking", "shared" and "sent" name hosts, files and folders far more
// often than they say what pressing something does, and no reason is
// written with them. Nor are "orders" and "books", which are lists and
// shop departments, and hosts (books.google.com), as often as not.
var (
	rePays = regexp.MustCompile(`(?i)\b(pays?|payment|purchases?|buys?|order|checkout|check out|checks out|` +
		`donates?|transfers?|withdraws?|subscribes?|book|reserves?|renews?|upgrades?)\b`)
	reDeletes = regexp.MustCompile(`(?i)\b(deletes?|removes?|erases?|cancels?|deactivates?|destroys?|unsubscribes?)\b`)
	reSends   = regexp.MustCompile(`(?i)\b(sends?|submits?|posts?|publish|publishes|shares?|invites?|signs? in|reaches the network|network)\b`)
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
		switch {
		case reDeletes.MatchString(why):
			return "deletes"
		case reSends.MatchString(why):
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
	case reSends.MatchString(why):
		return "sends"
	}
	return "acts"
}

// PaysPrefix begins the reason a paying tool call waits for a person.
const PaysPrefix = "it pays "
