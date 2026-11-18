// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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

// The top level disagreed with its own help. `-V`, "the same, shorter",
// printed the same four lines as --version; `help zzz` printed every
// command and exited 0, as though zzz were one; `-help` was "no such
// command" though `quilzo log -help` is help; `--root` with no directory
// after it was "there is no "--root" command"; and the global section
// named --root but none of the three places a token is read from.
func TestTheTopLevelDoesWhatItsHelpSays(t *testing.T) {
	o, _, code := cliRun(t, "", "", "-V")
	if code != 0 || strings.TrimSpace(o) != "quilzo "+version {
		t.Errorf("-V, the same as --version but shorter, exited %d with:\n%s", code, o)
	}
	if o, _, _ := cliRun(t, "", "", "--version"); !strings.Contains(o, "Copyright") {
		t.Errorf("--version no longer says the copyright:\n%s", o)
	}
	o, e, code := cliRun(t, "", "", "help", "zzz")
	if code != 2 || !strings.Contains(e, `there is no "zzz" command`) || strings.Contains(o, "global") {
		t.Errorf("`help zzz` exited %d:\n%s%s", code, firstLines(o, 3), firstLines(e, 3))
	}
	if o, e, code := cliRun(t, "", "", "help", "token"); code != 0 || !strings.Contains(o, "quilzo token issue") {
		t.Errorf("`help token` exited %d:\n%s%s", code, firstLines(o, 3), e)
	}
	for _, spelling := range []string{"-help", "--h"} {
		if o, e, code := cliRun(t, "", "", spelling); code != 0 || !strings.Contains(o, "\nglobal\n") {
			t.Errorf("`quilzo %s` exited %d, not the help:\n%s", spelling, code, firstLines(e, 3))
		}
	}
	for _, line := range [][]string{{"--root"}, {"log", "--root"}, {"--root="}, {"--token"}} {
		_, e, code := cliRun(t, "", "", line...)
		if code != 2 || !strings.Contains(e, strings.TrimSuffix(line[len(line)-1], "=")+" needs") || strings.Contains(e, "there is no") {
			t.Errorf("`quilzo %s` exited %d: %s", strings.Join(line, " "), code, firstLines(e, 2))
		}
	}
	o, _, _ = cliRun(t, "", "", "help")
	_, global, _ := strings.Cut(o, "\nglobal\n")
	global, _, _ = strings.Cut(global, "\n\n")
	for _, want := range []string{"--token", "~/.quilzo/token", "QUILZO_TOKEN"} {
		if !strings.Contains(global, want) {
			t.Errorf("the global section does not name %s:\n%s", want, global)
		}
	}
}

// A token file any account can read was used without a word, though the
// file is preferred to QUILZO_TOKEN for being 0600 (tokenFile). It is still
// used, and the command says, once, that it can be read by others and how
// to close it, as ssh does of a key.
func TestATokenFileOthersCanReadIsSaidToBe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a Windows file's mode does not say who may read it")
	}
	root, token := accessStore(t)
	run := func(mode os.FileMode) (string, int) {
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, ".quilzo"), 0o700); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(home, ".quilzo", "token")
		if err := os.WriteFile(file, []byte(token+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "quilzo-main", "--root", root, "token", "list")
		cmd.Dir = t.TempDir()
		cmd.Env = append(os.Environ(), "HOME="+home, "QUILZO_TOKEN=", "NO_COLOR=1")
		var o, e bytes.Buffer
		cmd.Stdout, cmd.Stderr = &o, &e
		err := cmd.Run()
		if err != nil {
			t.Errorf("token list with the file at %o: %v\n%s", mode, err, firstLines(e.String(), 3))
		}
		return e.String(), strings.Count(e.String(), file+" can be read")
	}
	if said, n := run(0o644); n != 1 || !strings.Contains(said, "chmod 600") {
		t.Errorf("a token file others can read was used without a word, or said more than once:\n%s", said)
	}
	if said, n := run(0o600); n != 0 {
		t.Errorf("a token file only its owner can read was warned about:\n%s", said)
	}
}

// A mistyped command is offered the nearest one, at every level. Only the
// top level did it, and it offered rows of the privilege table as commands:
// `schedul` was "Did you mean schedule, schedule list?". `token lsit` was
// "unknown token command" and nothing else, `auth grnat` the whole usage
// and no nearer word, a mistyped flag Go's own list of every flag, written
// with one dash, and `config set site.nmae` a pointer to all 129 settings.
func TestAMistypedWordIsOfferedTheNearestOne(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	if _, e, code := cliRun(t, root, "", "add", "about="+fileOf(t, "about.json", `{"title":"About"}`), "-m", "a page to move"); code != 0 {
		t.Fatalf("add: %s", e)
	}
	for _, c := range []struct {
		line []string
		want string
	}{
		{[]string{"token", "lsit"}, "did you mean quilzo token list?"},
		{[]string{"token", "isue", "x"}, "did you mean quilzo token issue?"},
		{[]string{"auth", "grnat", "a", "b"}, "did you mean quilzo auth grant?"},
		{[]string{"records", "lsit"}, "did you mean quilzo records list?"},
		{[]string{"agent", "template", "lsit"}, "did you mean quilzo agent template list?"},
		{[]string{"publish", "--no-a11y-chek"}, "did you mean --no-a11y-check?"},
		{[]string{"move", "about", "x", "--dryrun"}, "did you mean --dry-run?"},
		{[]string{"token", "issue", "z", "--principl", "owner"}, "did you mean --principal?"},
		{[]string{"config", "set", "site.nmae", "Hello"}, "did you mean site.name?"},
	} {
		o, e, code := cliRun(t, root, "", c.line...)
		line := strings.Join(c.line, " ")
		if code == 0 || !strings.Contains(e, c.want) {
			t.Errorf("`quilzo %s` exited %d without %q:\n%s", line, code, c.want, firstLines(o+e, 4))
		}
		// Go's own list of the flags, under a heading nobody wrote, with a
		// dash the help does not use.
		if strings.Contains(o+e, "Usage of ") {
			t.Errorf("`quilzo %s` answered with the flag package's list:\n%s", line, firstLines(o+e, 4))
		}
	}
	_, e, _ := cliRun(t, root, "", "schedul")
	if !strings.Contains(e, "Did you mean schedule?") {
		t.Errorf("`quilzo schedul` was not offered schedule, or was offered a row of the privilege table:\n%s", e)
	}
}

// "-" is standard input where a command reads a file and standard output
// where it writes one, as on every other command line. It was a file name:
// `add fromstdin=-` was "open -: no such file", and `records export -o -`,
// `auditlog export -o -`, `siem jsonl --envelope -` and `compliance sbom -`
// each wrote a file called "-", nothing on standard output, while `export
// json --to -` made a directory of that name. Where a directory goes, "-"
// is refused.
func TestADashIsStandardInputOrOutput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	run := func(stdin string, args ...string) (string, string, int, string) {
		t.Helper()
		dir := t.TempDir()
		cmd := exec.Command(os.Args[0], append([]string{"quilzo-main", "--root", root}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "QUILZO_TOKEN=", "NO_COLOR=1")
		cmd.Stdin = strings.NewReader(stdin)
		var o, e bytes.Buffer
		cmd.Stdout, cmd.Stderr = &o, &e
		code := 0
		if err := cmd.Run(); err != nil {
			code = -1
			if exit, ok := err.(*exec.ExitError); ok {
				code = exit.ExitCode()
			}
		}
		if _, err := os.Lstat(filepath.Join(dir, "-")); err == nil {
			t.Errorf("`quilzo %s` made a file or directory called -", strings.Join(args, " "))
		}
		return o.String(), e.String(), code, dir
	}
	if _, e, code, _ := run(`{"title":"From stdin","blocks":[]}`, "add", "fromstdin=-", "-m", "piped in"); code != 0 {
		t.Fatalf("`add fromstdin=-` exited %d: %s", code, firstLines(e, 3))
	}
	if o, e, code, _ := run("name,price\npen,2\n", "records", "import", "products", "-"); code != 0 {
		t.Errorf("`records import products -` exited %d: %s%s", code, firstLines(o, 3), firstLines(e, 3))
	}
	for _, c := range []struct {
		line []string
		want string
	}{
		{[]string{"records", "export", "products", "-o", "-"}, "name"},
		{[]string{"auditlog", "export", "-o", "-"}, `"seq":`},
		{[]string{"siem", "jsonl", "-o", filepath.Join(t.TempDir(), "log.jsonl"), "--envelope", "-"}, `"first_seq"`},
		{[]string{"compliance", "sbom", "-"}, "CycloneDX"},
		{[]string{"compliance", "aibom", "-"}, "CycloneDX"},
		{[]string{"newsletter", "export", "-"}, "email"},
	} {
		o, e, code, _ := run("", c.line...)
		if code != 0 || !strings.Contains(o, c.want) {
			t.Errorf("`quilzo %s` exited %d without %s on standard output:\n%s%s", strings.Join(c.line, " "), code, c.want, firstLines(o, 3), firstLines(e, 3))
		}
	}
	for _, line := range [][]string{
		{"export", "json", "--to", "-"},
		// The export and its envelope cannot both be the one stream.
		{"siem", "jsonl", "--envelope", "-"},
	} {
		if o, e, code, _ := run("", line...); code == 0 {
			t.Errorf("`quilzo %s` was not refused:\n%s%s", strings.Join(line, " "), firstLines(o, 3), firstLines(e, 3))
		}
	}
}
