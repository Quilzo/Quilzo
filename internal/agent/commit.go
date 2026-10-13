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
		if writes {
			return "writes"
		}
		return "reads"
	}
	op := a.Op
	switch {
	case strings.HasPrefix(op, "publish"):
		return "publishes"
	case op == "browser_open" || op == "browser_type" || op == "desktop_type" || op == "browser_sign_in":
		return "sends"
	case op == "shell_run":
		switch {
		case reDeletes.MatchString(why):
			return "deletes"
		case reSends.MatchString(why):
			return "sends"
		}
		return "writes"
	case op == "write_page" || op == "file_write" || op == "remember" || op == "forget" ||
		strings.HasPrefix(op, "write_") || strings.HasPrefix(op, "create_") || strings.HasPrefix(op, "update_") ||
		strings.HasPrefix(op, "delete_"):
		if strings.HasPrefix(op, "delete_") || op == "forget" {
			return "deletes"
		}
		return "writes"
	case strings.HasPrefix(op, "read_") || strings.HasPrefix(op, "list_") || strings.HasPrefix(op, "search") ||
		op == "recall" || op == "browser_read" || op == "browser_look" || op == "desktop_read" ||
		op == "desktop_look" || op == "file_read" || op == "file_list" || op == "decide":
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
