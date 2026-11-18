// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The first things anybody does with Quilzo, run as they are written.
//
// README's Quickstart, INSTALL's "A first site", CONTRIBUTING's two-minute
// path, the sign-in page's own instructions and the container recipes are
// the first thing somebody does with this program, and each of them stopped
// short of what it promised. The Quickstart made nobody an administrator,
// and `serve --open` opened http://127.0.0.1:8080, where a browser refuses
// every passkey; the first site was refused at `quilzo publish`, because
// nothing said who had written its page, and `template use` printed the
// same steps as what to do next; CONTRIBUTING's token, and the sign-in
// page's, signed in to "Confirm it's you" with no passkey to confirm with;
// and the reference's container served a volume nobody had made a store in.
// Every command in them worked on its own and every test passed, because no
// test followed a document from its first line to its last.
//
// So these do. Each takes a document's own code, runs every line of it
// against this binary in a directory of its own, and then does what the
// prose around it says comes next: opens what `--open` opened, opens the
// link that adds a passkey, adds one as the enrolment page's script does,
// signs in with it, and asks the site for its home page. A line this does
// not know how to run fails it, naming the line, rather than being skipped:
// a step skipped is the step a reader is stuck on.

// walk is somebody following a document, in a shell and a home of their own.
type walk struct {
	t *testing.T
	// fs stands for /, for the absolute paths a document names, and dir is
	// where cd has left them.
	fs, dir, home string
	env           map[string]string
	// keepToken does what the prose after a `token issue` says, where the
	// code does not: keeps the token it printed for the commands after it.
	keepToken bool
	token     string
	// links is every enrolment link the commands printed.
	links []string
	// ports is each port a document names and the one it is served on here,
	// since the documented ones may be in use on the machine running this.
	ports map[string]string
	// serving is where each surface listens: "admin" and "site".
	serving map[string]string
	// opened is where the browser this walk has writes what it was asked
	// to open.
	opened string
	log    strings.Builder
	umask  os.FileMode

	// The container's image, read from the Dockerfile, and its volumes.
	entrypoint, cmd []string
	workdir         string
	seeded          []string
	volumes         map[string]string
}

func newWalk(t *testing.T) *walk {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the browser this stands in is a shell script")
	}
	fs := t.TempDir()
	f := &walk{t: t, fs: fs, home: filepath.Join(fs, "home", "you"), env: map[string]string{},
		ports: map[string]string{}, serving: map[string]string{}, volumes: map[string]string{},
		opened: filepath.Join(fs, "opened"), umask: 0o022}
	f.dir = f.home
	bin := filepath.Join(fs, "bin")
	for _, d := range []string{f.home, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// What `serve --open` starts: xdg-open on Linux, open on macOS. It
	// writes down what it was asked to open, as a browser would go there.
	script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> '" + f.opened + "'\n"
	for _, name := range []string{"xdg-open", "open"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.env["PATH"] = bin + string(os.PathListSeparator) + os.Getenv("PATH")
	return f
}

// path is a path a document names, on this walk's machine.
func (f *walk) path(p string) string {
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		return filepath.Join(f.home, strings.TrimPrefix(p, "~"))
	case filepath.IsAbs(p):
		return filepath.Join(f.fs, p)
	}
	return filepath.Join(f.dir, p)
}

// fill puts what a document leaves for its reader to supply: the token a
// `token issue` printed, where it writes qz_….
func (f *walk) fill(s string) string {
	if f.token != "" {
		s = strings.ReplaceAll(s, "qz_…", f.token)
	}
	return s
}

// shellWords splits a line as a shell would, for the lines these documents
// hold: quotes, a comment from an unquoted #, and && and ; and > as words of
// their own.
func shellWords(line string) []string {
	var out []string
	var cur strings.Builder
	in, quoted := rune(0), false
	flush := func() {
		if cur.Len() > 0 || quoted {
			out = append(out, cur.String())
		}
		cur.Reset()
		quoted = false
	}
	for i, r := range line {
		switch {
		case in != 0 && r == in:
			in = 0
		case in != 0:
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			in, quoted = r, true
		case r == ' ' || r == '\t':
			flush()
		case r == '#' && cur.Len() == 0 && !quoted:
			flush()
			return out
		case r == ';' || r == '>':
			flush()
			out = append(out, string(r))
		case r == '&' && strings.HasPrefix(line[i:], "&&"):
			flush()
			out = append(out, "&&")
		case r == '&':
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// mdBlocks is the code in a Markdown document under a heading, block by
// block and line by line, up to the next heading as high, with each
// continued line joined to the one it continues.
func mdBlocks(t *testing.T, doc, heading string) [][]string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	level, start := 0, -1
	for i, l := range lines {
		if strings.TrimLeft(l, "#") != l && strings.TrimSpace(strings.TrimLeft(l, "#")) == heading {
			level, start = len(l)-len(strings.TrimLeft(l, "#")), i+1
			break
		}
	}
	if start < 0 {
		t.Fatalf("no heading %q", heading)
	}
	var blocks [][]string
	var cur []string
	in := false
	for _, l := range lines[start:] {
		if !in && strings.HasPrefix(l, "#") {
			if n := len(l) - len(strings.TrimLeft(l, "#")); n <= level && strings.HasPrefix(l[n:], " ") {
				break
			}
		}
		if strings.HasPrefix(l, "```") {
			if in {
				blocks = append(blocks, joinContinued(cur))
				cur = nil
			}
			in = !in
			continue
		}
		if in {
			cur = append(cur, l)
		}
	}
	return blocks
}

// textBlocks is the code under a heading of INSTALL, a Texinfo-style text:
// the lines indented five spaces, from the heading to the next heading.
func textBlocks(t *testing.T, doc, heading string) [][]string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	start := -1
	for i := 0; i+1 < len(lines); i++ {
		if lines[i] == heading && strings.Trim(lines[i+1], "=-*") == "" && lines[i+1] != "" {
			start = i + 2
			break
		}
	}
	if start < 0 {
		t.Fatalf("no heading %q", heading)
	}
	var blocks [][]string
	var cur []string
	for i := start; i < len(lines); i++ {
		l := lines[i]
		if i+1 < len(lines) && l != "" && lines[i+1] != "" && strings.Trim(lines[i+1], "=-*") == "" {
			break
		}
		if strings.HasPrefix(l, "     ") {
			cur = append(cur, strings.TrimSpace(l))
			continue
		}
		if len(cur) > 0 {
			blocks = append(blocks, joinContinued(cur))
			cur = nil
		}
	}
	if len(cur) > 0 {
		blocks = append(blocks, joinContinued(cur))
	}
	return blocks
}

func joinContinued(lines []string) []string {
	var out []string
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		for strings.HasSuffix(strings.TrimRight(l, " "), "\\") && i+1 < len(lines) {
			i++
			l = strings.TrimSuffix(strings.TrimRight(l, " "), "\\") + " " + strings.TrimSpace(lines[i])
		}
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func readDoc(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// run is one line of a document.
func (f *walk) run(line string) {
	f.t.Helper()
	fmt.Fprintf(&f.log, "$ %s\n", line)
	words := shellWords(line)
	for len(words) > 0 {
		one, rest := words, []string(nil)
		for i, w := range words {
			if w == "&&" || w == ";" {
				one, rest = words[:i], words[i+1:]
				break
			}
		}
		if len(one) > 0 {
			f.one(line, one)
		}
		words = rest
	}
}

func (f *walk) runAll(blocks [][]string) {
	f.t.Helper()
	for _, b := range blocks {
		for _, line := range b {
			f.run(line)
		}
	}
}

func (f *walk) one(line string, words []string) {
	f.t.Helper()
	name := words[0]
	switch {
	case name == "git" && len(words) > 2 && words[1] == "clone":
		// The checkout is the one this test was built from; what a reader
		// has next is a directory named after it.
		if err := os.MkdirAll(f.path(path.Base(words[len(words)-1])), 0o755); err != nil {
			f.t.Fatal(err)
		}
	case name == "go" && len(words) > 1 && words[1] == "build":
		// The binary is this test's own.
	case name == "cd":
		to := f.path(words[1])
		if fi, err := os.Stat(to); err != nil || !fi.IsDir() {
			f.t.Fatalf("`%s`: there is no %s to go to\n%s", line, words[1], f.log.String())
		}
		f.dir = to
	case name == "mkdir":
		for _, d := range words[1:] {
			if !strings.HasPrefix(d, "-") {
				if err := os.MkdirAll(f.path(d), 0o755); err != nil {
					f.t.Fatal(err)
				}
			}
		}
	case name == "umask" && len(words) == 2 && words[1] == "077":
		f.umask = 0o077
	case name == "printf":
		args, to := redirect(words[1:])
		if to == "" || len(args) == 0 {
			f.t.Fatalf("this test runs printf only into a file: %q", line)
		}
		text := strings.ReplaceAll(args[0], `\n`, "\n")
		for _, a := range args[1:] {
			text = strings.Replace(text, "%s", f.fill(a), 1)
		}
		if err := os.WriteFile(f.path(to), []byte(text), 0o666&^f.umask); err != nil {
			f.t.Fatal(err)
		}
	case name == "export":
		k, v, _ := strings.Cut(words[1], "=")
		f.env[k] = f.fill(v)
	case name == "docker":
		f.docker(line, words[1:])
	case name == "quilzo" || strings.HasSuffix(name, "/quilzo"):
		args, to := redirect(words[1:])
		for i := range args {
			args[i] = f.fill(args[i])
		}
		f.quilzo(line, f.dir, args, to)
	default:
		f.t.Fatalf("this test does not know how to run %q, from `%s`: teach it to, "+
			"or the document asks its reader for something this test cannot check", name, line)
	}
}

// redirect takes a > FILE off the end of a command.
func redirect(words []string) ([]string, string) {
	for i, w := range words {
		if w == ">" && i+1 < len(words) {
			return append([]string(nil), words[:i]...), words[i+1]
		}
	}
	return append([]string(nil), words...), ""
}

// subcommand is the command a line of quilzo runs, past its global flags,
// and where it is.
func subcommand(args []string) (string, int) {
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--root" || a == "--token":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			return a, i
		}
	}
	return "", -1
}

func (f *walk) environ() []string {
	env := append(os.Environ(), "HOME="+f.home, "NO_COLOR=1", "QUILZO_TOKEN=")
	for k, v := range f.env {
		env = append(env, k+"="+v)
	}
	return env
}

// freePort is a port nothing on this machine is listening on now.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port
}

// served moves a documented address to a free port on the same host, an
// address of every interface to loopback, and remembers the move.
func (f *walk) served(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		f.t.Fatalf("%q is not an address", addr)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if _, ok := f.ports[port]; !ok {
		f.ports[port] = freePort(f.t)
	}
	return net.JoinHostPort(host, f.ports[port])
}

var enrolLink = regexp.MustCompile(`https?://\S+/enrol/qzenrol_[A-Za-z0-9_-]+`)

// quilzo runs one command line, in dir; the two that serve are left
// running, once they say where.
func (f *walk) quilzo(line, dir string, args []string, to string) {
	f.t.Helper()
	sub, at := subcommand(args)
	serves := sub == "serve" || (sub == "site" && (at+1 == len(args) || strings.HasPrefix(args[at+1], "-")))
	if serves {
		f.serve(line, dir, args, sub, at)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"quilzo-main"}, args...)...)
	cmd.Dir, cmd.Env = dir, f.environ()
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	fmt.Fprintf(&f.log, "%s%s", o.String(), e.String())
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		f.t.Fatal(err)
	}
	if err != nil {
		f.t.Fatalf("`%s` exited %d, and the document goes on as though it had worked:\n%s",
			line, exit.ExitCode(), f.log.String())
	}
	if to != "" {
		if err := os.WriteFile(f.path(to), o.Bytes(), 0o666&^f.umask); err != nil {
			f.t.Fatal(err)
		}
	}
	f.links = append(f.links, enrolLink.FindAllString(o.String(), -1)...)
	if sub == "token" && at+1 < len(args) && args[at+1] == "issue" {
		f.token = strings.TrimSpace(firstLines(o.String(), 1))
		if !strings.HasPrefix(f.token, "qz_") {
			f.t.Fatalf("`%s` printed no token first:\n%s", line, o.String())
		}
		if f.keepToken {
			f.env["QUILZO_TOKEN"] = f.token
		}
	}
}

// serve starts `quilzo serve` or `quilzo site` on a free port in place of
// the documented one, and waits for it to say where it listens.
func (f *walk) serve(line, dir string, args []string, sub string, at int) {
	f.t.Helper()
	addr := ""
	for i := at + 1; i < len(args); i++ {
		if args[i] == "--addr" && i+1 < len(args) {
			args[i+1] = f.served(args[i+1])
			addr = args[i+1]
		} else if v, ok := strings.CutPrefix(args[i], "--addr="); ok {
			addr = f.served(v)
			args[i] = "--addr=" + addr
		}
	}
	if addr == "" {
		def := map[string]string{"serve": "127.0.0.1:8080", "site": "127.0.0.1:8081"}[sub]
		addr = f.served(def)
		args = append(args, "--addr", addr)
	}
	cmd := exec.Command(os.Args[0], append([]string{"quilzo-main"}, args...)...)
	cmd.Dir, cmd.Env = dir, f.environ()
	out, err := cmd.StdoutPipe()
	if err != nil {
		f.t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	surface := map[string]string{"serve": "admin", "site": "site"}[sub]
	lines := bufio.NewScanner(out)
	up := false
	deadline := time.Now().Add(time.Minute)
	for !up && time.Now().Before(deadline) && lines.Scan() {
		fmt.Fprintf(&f.log, "%s\n", lines.Text())
		up = strings.HasPrefix(lines.Text(), surface+" on http://")
	}
	if !up {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		f.t.Fatalf("`%s` did not start:\n%s%s", line, f.log.String(), stderr.String())
	}
	go func() {
		for lines.Scan() {
		}
	}()
	f.serving[surface] = addr
	// Announced as it starts to listen, so asked until it answers.
	for try := 0; try < 100; try++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	f.t.Fatalf("`%s` said it was listening on %s and is not", line, addr)
}

// moved is a documented address at the port this walk serves it on.
func (f *walk) moved(raw string) *url.URL {
	f.t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		f.t.Fatal(err)
	}
	if port, ok := f.ports[u.Port()]; ok {
		u.Host = net.JoinHostPort(u.Hostname(), port)
	}
	return u
}

// browsed is everything the fake browser was asked to open.
func (f *walk) browsed() []string {
	b, _ := os.ReadFile(f.opened)
	return strings.Fields(string(b))
}

// passkey is an authenticator, doing what a browser's does for the
// enrolment page's script and the sign-in page's.
type passkey struct {
	key   *ecdsa.PrivateKey
	id    []byte
	count uint32
}

func newPasskey(t *testing.T) *passkey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &passkey{key: k, id: []byte("first-run-key"), count: 1}
}

func (k *passkey) authData(rpID string) []byte {
	sum := sha256.Sum256([]byte(rpID))
	// Present and verified, as a passkey is.
	out := append(append([]byte{}, sum[:]...), 0x01|0x04)
	return binary.BigEndian.AppendUint32(out, k.count)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// tab is somebody at the admin in a browser: a cookie jar, and the
// headers a browser sends with a page's own requests.
type tab struct {
	t      *testing.T
	origin string
	client *http.Client
}

func newTab(t *testing.T, origin string) *tab {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &tab{t: t, origin: origin, client: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
}

func (b *tab) get(p string) (int, string, string) {
	b.t.Helper()
	res, err := b.client.Get(b.origin + p)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Request.URL.Path, string(body)
}

func (b *tab) post(p string, body any) map[string]any {
	b.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, b.origin+p, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.origin)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err := b.client.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	got, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		b.t.Fatalf("%s answered %d: %s", p, res.StatusCode, got)
	}
	var out map[string]any
	_ = json.Unmarshal(got, &out)
	return out
}

// enrolAndSignIn opens an enrolment link as the person it is for: the page,
// the passkey it adds, and then signing in with that passkey alone. It
// returns Get started as they see it.
func (f *walk) enrolAndSignIn(link string) string {
	f.t.Helper()
	u := f.moved(link)
	if net.ParseIP(u.Hostname()) != nil {
		f.t.Fatalf("the link is at %s, an address, where a browser refuses a passkey", u.Host)
	}
	b := newTab(f.t, u.Scheme+"://"+u.Host)
	if code, _, body := b.get(u.Path); code != http.StatusOK {
		f.t.Fatalf("the enrolment link answered %d: %.300s", code, body)
	}
	secret := path.Base(u.Path)
	k := newPasskey(f.t)
	der, err := x509.MarshalPKIXPublicKey(k.key.Public())
	if err != nil {
		f.t.Fatal(err)
	}
	clientData := func(kind, challenge string) []byte {
		raw, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge,
			"origin": b.origin, "crossOrigin": false})
		return raw
	}
	challenge, _ := b.post("/enrol/challenge", map[string]any{"secret": secret})["challenge"].(string)
	b.post("/enrol/register", map[string]any{
		"secret": secret, "id": b64(k.id), "challenge": challenge, "label": "a first run",
		"clientDataJSON":    b64(clientData("webauthn.create", challenge)),
		"authenticatorData": b64(k.authData(u.Hostname())),
		"publicKey":         b64(der), "algorithm": -7,
	})
	k.count++
	challenge, _ = b.post("/signin/passkey/challenge", map[string]any{})["challenge"].(string)
	cd, ad := clientData("webauthn.get", challenge), k.authData(u.Hostname())
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		f.t.Fatal(err)
	}
	b.post("/signin/passkey/verify", map[string]any{"id": b64(k.id), "challenge": challenge,
		"clientDataJSON": b64(cd), "authenticatorData": b64(ad), "signature": b64(sig)})
	code, at, body := b.get("/start")
	if code != http.StatusOK || at != "/start" {
		f.t.Fatalf("signed in with the passkey, Get started answered %d at %s: %.300s", code, at, body)
	}
	return body
}

// siteHome is the site's home page, which has to be there.
func (f *walk) siteHome() string {
	f.t.Helper()
	addr, ok := f.serving["site"]
	if !ok {
		f.t.Fatalf("nothing in it started the site\n%s", f.log.String())
	}
	res, err := http.Get("http://" + addr + "/")
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		f.t.Fatalf("the site's home page answered %d: %.300s\n%s", res.StatusCode, body, f.log.String())
	}
	return string(body)
}

// The README's Quickstart ends at an admin its reader is signed in to.
//
// It made nobody an administrator, so `quilzo auth enrol` refused the
// person it was run for and nobody could be given a passkey; and `serve
// --open` opened http://127.0.0.1:8080, which serve itself says to open as
// localhost, because a browser refuses an address as the name a passkey
// belongs to.
func TestTheReadmeQuickstartReachesASignedInAdmin(t *testing.T) {
	f := newWalk(t)
	f.keepToken = true
	for _, b := range mdBlocks(t, readDoc(t, "README.md"), "Quickstart") {
		// Pointing it at a model needs a model, which a test does not have.
		if strings.Contains(strings.Join(b, "\n"), "QUILZO_MODEL_URL") {
			continue
		}
		f.runAll([][]string{b})
	}
	admin, ok := f.serving["admin"]
	if !ok {
		t.Fatalf("the Quickstart never starts the admin\n%s", f.log.String())
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		opened := f.browsed()
		if len(opened) == 0 {
			t.Fatalf("serve --open opened nothing\n%s", f.log.String())
		}
		u := f.moved(opened[0])
		if net.ParseIP(u.Hostname()) != nil {
			t.Errorf("serve --open opened %s: an address, where every passkey is refused", opened[0])
		}
		if _, port, _ := net.SplitHostPort(admin); u.Port() != port {
			t.Errorf("serve --open opened %s, and the admin is on %s", opened[0], admin)
		}
	}
	if len(f.links) == 0 {
		t.Fatalf("nothing in the Quickstart gives its reader a passkey\n%s", f.log.String())
	}
	if body := f.enrolAndSignIn(f.links[len(f.links)-1]); !strings.Contains(body, "Get started") {
		t.Errorf("signed in, the first screen is not Get started: %.300s", body)
	}
	// And the command line still answers to its reader, with the token the
	// Quickstart had them keep.
	f.run("./quilzo agent runs")
}

// image reads what a container of the image starts as from the Dockerfile:
// the entrypoint, the command, the working directory, and the directories
// it is seeded with.
func (f *walk) image() {
	f.t.Helper()
	df := readDoc(f.t, "Dockerfile")
	// The directories the build stage makes to seed the image with, which
	// are what a volume mounted over them starts as.
	made := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^RUN mkdir -p ([^&\n]+)`).FindAllStringSubmatch(df, -1) {
		for _, d := range strings.Fields(m[1]) {
			made[d] = true
		}
	}
	run := strings.Split(df, "\nFROM ")
	final := run[len(run)-1]
	for _, l := range strings.Split(final, "\n") {
		switch {
		case strings.HasPrefix(l, "ENTRYPOINT "):
			if err := json.Unmarshal([]byte(strings.TrimPrefix(l, "ENTRYPOINT ")), &f.entrypoint); err != nil {
				f.t.Fatal(err)
			}
		case strings.HasPrefix(l, "CMD "):
			if err := json.Unmarshal([]byte(strings.TrimPrefix(l, "CMD ")), &f.cmd); err != nil {
				f.t.Fatal(err)
			}
		case strings.HasPrefix(l, "WORKDIR "):
			f.workdir = strings.TrimSpace(strings.TrimPrefix(l, "WORKDIR "))
		case strings.HasPrefix(l, "COPY --from=build"):
			if fields := strings.Fields(l); made[fields[len(fields)-2]] {
				f.seeded = append(f.seeded, fields[len(fields)-1])
			}
		}
	}
	if len(f.entrypoint) == 0 || f.workdir == "" {
		f.t.Fatalf("the Dockerfile's last stage names no entrypoint or working directory")
	}
}

// docker is the docker commands the recipes use.
func (f *walk) docker(line string, words []string) {
	f.t.Helper()
	switch {
	case len(words) > 0 && words[0] == "build":
		// The image is this test's binary and the Dockerfile's entrypoint.
		return
	case len(words) > 2 && words[0] == "volume" && words[1] == "create":
		f.volume(words[2])
		return
	case len(words) == 0 || words[0] != "run":
		f.t.Fatalf("this test does not know how to run `%s`", line)
	}
	var mounts [][2]string
	publish := map[string]string{}
	i := 1
	for ; i < len(words) && strings.HasPrefix(words[i], "-"); i++ {
		switch words[i] {
		case "--rm", "-d", "-it", "-i", "-t":
		case "-v", "--volume":
			i++
			name, at, _ := strings.Cut(words[i], ":")
			mounts = append(mounts, [2]string{at, f.volume(name)})
		case "-p", "--publish":
			i++
			host, port, _ := strings.Cut(words[i], ":")
			publish[port] = host
		default:
			f.t.Fatalf("this test does not know docker run's %s, in `%s`", words[i], line)
		}
	}
	if i >= len(words) {
		f.t.Fatalf("`%s` names no image", line)
	}
	args := words[i+1:]
	if len(args) == 0 {
		args = f.cmd
	}
	// A filesystem of its own, as the image has it, and each volume on its
	// mount point, seeded with what the image has there if it is empty.
	box := f.t.TempDir()
	for _, d := range f.seeded {
		if err := os.MkdirAll(filepath.Join(box, d), 0o755); err != nil {
			f.t.Fatal(err)
		}
	}
	for _, m := range mounts {
		if entries, _ := os.ReadDir(m[1]); len(entries) == 0 {
			for _, d := range f.seeded {
				if rest, ok := strings.CutPrefix(d, m[0]+"/"); ok {
					if err := os.MkdirAll(filepath.Join(m[1], rest), 0o755); err != nil {
						f.t.Fatal(err)
					}
				}
			}
		}
	}
	inside := func(p string) string {
		best, dir := "", ""
		for _, m := range mounts {
			if (p == m[0] || strings.HasPrefix(p, m[0]+"/")) && len(m[0]) > len(best) {
				best, dir = m[0], m[1]
			}
		}
		if best == "" {
			return filepath.Join(box, p)
		}
		return filepath.Join(dir, strings.TrimPrefix(p, best))
	}
	full := append(append([]string{}, f.entrypoint[1:]...), args...)
	for j := range full {
		switch {
		case strings.HasPrefix(full[j], "/"):
			full[j] = inside(full[j])
		case j > 0 && full[j-1] == "--addr":
			// The port is moved to a free one by its number inside the
			// container, and a reader is sent to the number -p publishes it
			// on, so the two have to be the same for the move to follow.
			_, port, _ := net.SplitHostPort(full[j])
			if host, ok := publish[port]; ok && host != port {
				f.t.Fatalf("this test follows a port published on its own number only: `%s`", line)
			}
		}
	}
	f.quilzo(line, inside(f.workdir), full, "")
}

// volume is a named volume's directory, made the first time it is named.
func (f *walk) volume(name string) string {
	if d, ok := f.volumes[name]; ok {
		return d
	}
	d := filepath.Join(f.fs, "volumes", name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		f.t.Fatal(err)
	}
	f.volumes[name] = d
	return d
}

// `serve --open` opens the admin where a passkey works: by name, for an
// admin on loopback or on every interface, and as it was given otherwise.
func TestServeOpensTheAdminWhereAPasskeyWorks(t *testing.T) {
	for addr, want := range map[string]string{
		"127.0.0.1:8080":         "http://localhost:8080",
		"[::1]:8080":             "http://localhost:8080",
		"127.0.0.2:9000":         "http://localhost:9000",
		"0.0.0.0:8080":           "http://localhost:8080",
		":8080":                  "http://localhost:8080",
		"admin.example.org:8443": "http://admin.example.org:8443",
	} {
		got, renamed := adminAddress(addr)
		if got != want || renamed != (want != "http://"+addr) {
			t.Errorf("an admin on %s is opened at %s (renamed %v), want %s", addr, got, renamed, want)
		}
	}
}
