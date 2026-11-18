// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// count added a bare s to every noun, and two of its callers handed it a
// word that does not take one: moving a page two menus link to said "2 menu
// entrys would be retargeted", and `memory forget` said "0 memorys removed".
func TestCountSpellsThePluralOfEveryWordItIsGiven(t *testing.T) {
	for _, c := range []struct {
		n    int
		noun string
		want string
	}{
		{1, "menu entry", "1 menu entry"},
		{2, "menu entry", "2 menu entries"},
		{0, "memory", "0 memories"},
		{1, "memory", "1 memory"},
		{3, "memory", "3 memories"},
		{2, "submission", "2 submissions"},
		{2, "day", "2 days"},
		{2, "key", "2 keys"},
		{2, "address", "2 addresses"},
		{2, "box", "2 boxes"},
		{2, "match", "2 matches"},
		{2, "time", "2 times"},
	} {
		if got := count(c.n, c.noun); got != c.want {
			t.Errorf("count(%d, %q) = %q, want %q", c.n, c.noun, got, c.want)
		}
	}
}

// The help said `quilzo webhook list | remove ID | test`, but an endpoint has
// no id: neither the list nor its JSON shows one, and `webhook remove` takes
// the address it was added with. An administrator following the help looked
// for an id that is not there.
func TestWebhookRemoveIsHelpedByTheAddressItTakes(t *testing.T) {
	help := helpFor("webhook", []string{"remove"})
	if !strings.Contains(help, "remove URL") || strings.Contains(help, "remove ID") {
		t.Errorf("the help for webhook remove does not name the address it takes:\n%s", help)
	}
	err := hookRemove(t.TempDir(), nil)
	if err == nil || !strings.Contains(err.Error(), "webhook remove URL") {
		t.Errorf("webhook remove's own usage does not agree with the help: %v", err)
	}
}

// `records list` showed each record by the first twelve characters of its
// id, which `records get` and `records delete` then refused as "not a
// record id: 32 hexadecimal characters". The help's own journey (list,
// then get or delete what it showed) could not be followed without --json.
func TestARecordIsListedByAnIDItsSiblingsTake(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	if _, e, code := cliRun(t, root, "", "records", "add", "products", "name=pen"); code != 0 {
		t.Fatalf("records add: %s", e)
	}
	o, e, code := cliRun(t, root, "", "records", "list", "products")
	if code != 0 {
		t.Fatalf("records list: %s", e)
	}
	shown := strings.Fields(o)[0]
	for _, verb := range []string{"get", "delete"} {
		if _, e, code := cliRun(t, root, "", "records", verb, "products", shown); code != 0 {
			t.Errorf("`records %s products %s`, the id the list showed, exited %d: %s", verb, shown, code, e)
		}
	}
}

// A token issued for an hour said "expires 2026-11-12", and `token list`
// showed the same day alone, so it could not be told from one that lasts
// the month. Under a day, the hour and the zone are shown as well.
func TestAShortTokenSaysTheHourItEnds(t *testing.T) {
	root, token := accessStore(t)
	o, e, code := cliRun(t, root, token, "token", "issue", "ci-hour", "--principal", "owner", "--role", "reader", "--ttl", "1h")
	if code != 0 {
		t.Fatalf("token issue: %s", e)
	}
	ends := time.Now().UTC().Add(time.Hour)
	at := regexp.MustCompile(`expires (\S+ \d\d:\d\d UTC)`).FindStringSubmatch(o)
	if at == nil || !strings.HasPrefix(at[1], ends.Format("2006-01-02")) {
		t.Errorf("an hour's token does not say the hour it ends:\n%s", o)
	}
	o, e, code = cliRun(t, root, token, "token", "list")
	if code != 0 {
		t.Fatalf("token list: %s", e)
	}
	for _, line := range strings.Split(o, "\n") {
		switch {
		case strings.Contains(line, "ci-hour") && !regexp.MustCompile(`\d\d:\d\d UTC`).MatchString(line):
			t.Errorf("token list shows an hour's token by its day alone:\n%s", line)
		case strings.Contains(line, " boot ") && strings.Contains(line, "UTC"):
			t.Errorf("token list shows a week's token by the hour:\n%s", line)
		}
	}
}

// `auth grant --for 30d`, as the help writes it, was taken, and every other
// length of time on the command line refused a day: `token issue --ttl 1d`
// was "invalid value "1d" for flag -ttl: parse error", `agent sponsor --for
// 90d` the same, and `schedule add 2d` "neither a time nor a duration". One
// syntax now reads them all: Go's, and a whole number of days or weeks.
func TestEveryLengthOfTimeTakesDays(t *testing.T) {
	root, token := accessStore(t)
	if _, e, code := cliRun(t, root, token, "add", "about="+fileOf(t, "about.json", `{"title":"About"}`), "-m", "a draft to schedule"); code != 0 {
		t.Fatalf("add: %s", e)
	}
	refused := regexp.MustCompile(`invalid value|parse error|neither a time|not a number of days|is a length of time|not a length of time`)
	for _, line := range [][]string{
		{"token", "issue", "y", "--principal", "owner", "--ttl", "1d"},
		{"token", "stale", "--idle", "4w"},
		{"auth", "enrol", "ann", "--for", "1d"},
		{"auth", "grant", "ann", "author", "--for", "2w"},
		{"agent", "sponsor", "x", "owner", "--for", "90d"},
		{"agent", "renew", "x", "--for", "90d"},
		{"agent", "cost", "--since", "7d"},
		{"agent", "credential", "issue", "x", "--for", "1d"},
		{"shield", "pause", "x", "--for", "1d", "--reason", "r"},
		{"trust", "add", "x", "--for", "1d"},
		{"schedule", "add", "2d"},
		{"checked", "set", "about", "--every", "1w"},
	} {
		o, e, _ := cliRun(t, root, token, line...)
		if m := refused.FindString(o + e); m != "" {
			t.Errorf("`quilzo %s` refused its length of time (%s):\n%s", strings.Join(line, " "), m, firstLines(o+e, 4))
		}
	}
}
