// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auditstream"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/httpsig"
	"github.com/quilzo/quilzo/internal/logd"
	"github.com/quilzo/quilzo/internal/out"
)

// The accounts the reference compose runs the log writer and the CMS as
// (deploy/compose.yaml).
const (
	writerAccount = 65533
	cmsAccount    = 65532
)

// startWriter points the store at a log directory of its own and serves the
// writer over it in this process, as cmdLogd builds it.
func startWriter(t *testing.T, root string) (dir, sock string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := setAuditDir(root, dir); err != nil {
		t.Fatal(err)
	}
	srv, err := newLogWriter(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	sock = logSocketPath(root)
	ln, err := logd.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return dir, sock
}

// giveTheLogAway hands the log directory to the writer's account, so the
// separation is in force for this process: the log is owned by an account
// it is not. Only root can give a file away.
func giveTheLogAway(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("giving the log to another account needs root")
	}
	chownTree(t, dir, writerAccount, cmsAccount)
}

func chownTree(t *testing.T, dir string, uid, gid int) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// publishedKeysAt is the key file a verifier outside is given.
func publishedKeysAt(t *testing.T, path string) *publishedKeys {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var k publishedKeys
	if err := json.Unmarshal(b, &k); err != nil {
		t.Fatal(err)
	}
	return &k
}

// logdStatusJSON is `quilzo logd status --json`, read back.
func logdStatusJSON(t *testing.T, root string) map[string]any {
	t.Helper()
	old := w
	t.Cleanup(func() { w = old })
	w = out.New(true)
	var buf bytes.Buffer
	w.Out = &buf
	if err := cmdLogdStatus(root); err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(buf.Bytes(), &st); err != nil {
		t.Fatalf("%v: %s", err, buf.String())
	}
	w = old
	return st
}

// The writer makes the key and its public half when it first starts, in
// the directory it owns: head.key for itself alone, head.pub.json for
// everybody, and the log file, so the separation shows before the first
// record. Started again, it keeps the key it made.
func TestTheLogWriterMakesItsKeyWhenItFirstStarts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	dir, _ := startWriter(t, root)
	for name, mode := range map[string]os.FileMode{"head.key": 0o600, "head.pub.json": 0o644} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("the writer did not make %s: %v", name, err)
		}
		if fi.Mode().Perm() != mode {
			t.Errorf("%s is %v, not %v", name, fi.Mode().Perm(), mode)
		}
	}
	if !fileExists(filepath.Join(dir, "audit.jsonl")) {
		t.Error("the writer started without a log file, so nothing could tell it owns the log")
	}
	if fileExists(filepath.Join(root, "head.key")) {
		t.Error("a head key was made in the store")
	}
	first, err := publishedVerifier(headKeysPath(root))
	if err != nil {
		t.Fatal(err)
	}
	again, err := newLogWriter(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.Heads == nil || again.Heads.Verifier().KeyID() != first.KeyID() {
		t.Error("the writer made a new key when it started again")
	}
}

// What the writer hands back is checked before anybody uses it: a head over
// another root than the one this account read is refused, and so is a
// signature the published keys do not check.
func TestAHeadFromTheWriterIsCheckedAgainstWhatThisAccountRead(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	_, sock := startWriter(t, root)
	record(root, audit.Record{Action: "test.written", Resource: "/", Outcome: audit.Success,
		Principal: "dana", Kind: audit.KindHuman, Verified: true})
	s, err := newWriterSigner(root, sock)
	if err != nil {
		t.Fatal(err)
	}
	events, err := audit.Read(auditPath(root))
	if err != nil || len(events) == 0 {
		t.Fatalf("%d entries, %v", len(events), err)
	}
	head, _ := audit.TreeHead(events, time.Now())
	sh, err := s.Sign(head)
	if err != nil {
		t.Fatal(err)
	}
	if sh.Root != head.Root || sh.Size != head.Size {
		t.Errorf("the writer signed %d/%s for %d/%s", sh.Size, sh.Root, head.Size, head.Root)
	}
	if err := s.Verifier().Verify(sh); err != nil {
		t.Errorf("the writer's head does not verify against what it publishes: %v", err)
	}
	forged := head
	forged.Root = strings.Repeat("0", 64)
	if _, err := s.Sign(forged); err == nil || !strings.Contains(err.Error(), "not the one the writer keeps") {
		t.Errorf("a head over another root was handed on: %v", err)
	}
	st, err := s.SignStatement(featureContext, []byte("sha256:0123"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verifier().VerifyStatement(featureContext, []byte("sha256:0123"), st); err != nil {
		t.Errorf("the writer's statement does not verify: %v", err)
	}
	if _, err := s.SignStatement("quilzo/other/v1", []byte("x")); err == nil {
		t.Error("the writer signed a statement nothing in this program makes")
	}

	// Published keys that are not the writer's: every head it signs is
	// caught by the first caller, not by an auditor later.
	ed, ml, _ := audit.GenerateHeadSeeds()
	other, _ := audit.NewHeadSigner(ed, ml)
	if err := writePublishedKeys(root, other); err != nil {
		t.Fatal(err)
	}
	s, err = newWriterSigner(root, sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(head); err == nil || !strings.Contains(err.Error(), "does not verify against") {
		t.Errorf("a head the published keys do not check was handed on: %v", err)
	}
}

// Where the log is this account's own the key is loaded here, as it always
// was: in the store, or beside a writer running as this same account, where
// the key the writer made is the one loaded.
func TestWithoutTheSeparationTheKeyIsLoadedHereAsBefore(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	s, err := headSigner(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(*audit.HeadSigner); !ok {
		t.Fatalf("a store keeping its own log signed through %T", s)
	}
	if !fileExists(filepath.Join(root, "head.key")) || !fileExists(filepath.Join(root, "head.pub.json")) {
		t.Error("the key and its public half are not in the store")
	}
	if got := logdStatusJSON(t, root)["heads_signed_by"]; got != "this account" {
		t.Errorf("logd status says heads are signed by %v", got)
	}

	beside := demoStore(t)
	startWriter(t, beside)
	s, err = headSigner(beside)
	if err != nil {
		t.Fatal(err)
	}
	local, ok := s.(*audit.HeadSigner)
	if !ok {
		t.Fatalf("a writer running as this account signed through %T", s)
	}
	pub, err := publishedVerifier(headKeysPath(beside))
	if err != nil {
		t.Fatal(err)
	}
	if local.Verifier().KeyID() != pub.KeyID() {
		t.Error("the key loaded here is not the one the writer made and publishes")
	}
}

// With the separation in force, `auditlog head --save`, an agent's receipt
// and an app's receipt are signed by the writer and check out against the
// keys it publishes; the store keeps the head it saved, and holds no key.
func TestAHeadAndEveryReceiptAreSignedByTheWriter(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, _ := identityStore(t)
	dir, _ := startWriter(t, root)
	giveTheLogAway(t, dir)
	s, err := headSigner(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(*writerSigner); !ok {
		t.Fatalf("with the separation in force, heads are signed through %T", s)
	}
	key, _ := os.ReadFile(filepath.Join(dir, "head.key"))
	pub := publishedKeysAt(t, filepath.Join(dir, "head.pub.json"))

	if err := auditHead(root, []string{"--save"}); err != nil {
		t.Fatalf("auditlog head --save: %v", err)
	}
	var saved headFile
	if err := loadJSON(headsPath(root), &saved); err != nil || len(saved.Heads) != 1 {
		t.Fatalf("the store saved %d heads: %v", len(saved.Heads), err)
	}

	m := asker("tidy")
	m.AskFirst = nil
	if err := declareAgent(root, m, false, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, _, err := runAgentKept(context.Background(), root, "tidy", "tidy the about page", false, asAdmin("dana"))
	if err != nil && id == "" {
		t.Fatal(err)
	}
	rf, err := buildReceipt(root, id, time.Now())
	if err != nil {
		t.Fatalf("agent receipt: %v", err)
	}
	if c := checkReceipt(rf, pub); len(c.Problems) != 0 || c.OwnKeys {
		t.Errorf("the agent's receipt against the writer's keys: %+v", c)
	}

	const grant = "gr_0123456789abcdef"
	if err := recordE(root, audit.Record{Action: "mcp.call", Resource: "/mcp", Outcome: audit.Success,
		Principal: "dana", Kind: audit.KindAI, Model: "example-app", Verified: true,
		Detail: map[string]string{"grant": grant, "op": "list_pages"}}); err != nil {
		t.Fatal(err)
	}
	app, err := buildAppReceipt(root, grant, time.Now())
	if err != nil {
		t.Fatalf("apps receipt: %v", err)
	}
	if c := checkReceipt(app, pub); len(c.Problems) != 0 {
		t.Errorf("the app's receipt against the writer's keys: %+v", c)
	}

	st := logdStatusJSON(t, root)
	if st["heads_signed_by"] != "the log writer" || st["head_key_id"] != pub.KeyID {
		t.Errorf("logd status: %v", st)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "head.key")); !bytes.Equal(after, key) {
		t.Error("the writer's key was replaced")
	}
	if fileExists(filepath.Join(root, "head.key")) {
		t.Error("a head key was made in the store")
	}
}

// One round of the audit stream, signed by the writer: the receiver given
// the writer's published keys takes every record.
func TestTheAuditStreamsRoundsAreSignedByTheWriter(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	dir, _ := startWriter(t, root)
	giveTheLogAway(t, dir)
	record(root, audit.Record{Action: "test.written", Resource: "/", Outcome: audit.Success,
		Principal: "dana", Kind: audit.KindHuman, Verified: true})
	key, err := streamKey(root)
	if err != nil {
		t.Fatal(err)
	}
	heads, err := publishedVerifier(filepath.Join(dir, "head.pub.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv, recv := streamReceiver(t, heads, key.Public().(ed25519.PublicKey))
	if err := cmdConfig(root, []string{"set", "siem.stream.url", srv.URL + "/quilzo"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSiemStream(root, []string{"send"}); err != nil {
		t.Fatalf("a round of the stream: %v", err)
	}
	s, _ := streamSender(root)
	c, _ := s.Status()
	if c.Sent == 0 || recv.holds() != c.Sent || c.Error != "" {
		t.Fatalf("sent %d, the receiver holds %d: %s", c.Sent, recv.holds(), c.Error)
	}
}

type lockedReceiver struct {
	mu sync.Mutex
	rc *auditstream.Receiver
}

func (l *lockedReceiver) holds() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rc.Holds()
}

// streamReceiver is a SIEM on this machine that takes batches checked
// against heads and the stream key.
func streamReceiver(t *testing.T, heads *audit.HeadVerifier, pub ed25519.PublicKey) (*httptest.Server, *lockedReceiver) {
	t.Helper()
	recv := &lockedReceiver{rc: &auditstream.Receiver{Heads: heads,
		Keys: []httpsig.PublicKey{{ID: auditstream.KeyID(pub), Alg: httpsig.Ed25519, Ed: pub}}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		recv.mu.Lock()
		defer recv.mu.Unlock()
		if _, err := recv.rc.Accept(r, body, time.Now()); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, recv
}

// The statements the log's keys make, signed by the writer: an exported
// feature package, a registered research plan, and an engagement package's
// head, each checked against the writer's published keys.
func TestFeatureResearchAndEngagementSigningGoThroughTheWriter(t *testing.T) {
	root := featureSite(t)
	dir, _ := startWriter(t, root)
	giveTheLogAway(t, dir)
	keys := filepath.Join(dir, "head.pub.json")
	dana := asAdmin("dana")

	if err := installFeatureFile(root, writePackage(t, withoutAddress), "", "", dana); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "signed.json")
	if err := featureExport(root, []string{"lab-samples", "-o", pkg, "--sign"}); err != nil {
		t.Fatalf("feature export --sign: %v", err)
	}
	if _, _, err := readFeature(root, pkg, keys); err != nil {
		t.Errorf("the exported package against the writer's keys: %v", err)
	}

	if err := researchNew(root, "fever", "Does aspirin lower fever in adults?", dana); err != nil {
		t.Fatal(err)
	}
	if _, err := researchSetPlan(root, "fever", "Compare mean temperature between arms.", "", dana); err != nil {
		t.Fatal(err)
	}
	p, err := researchRegister(root, "fever", dana)
	if err != nil || p.Plan.Signature == nil {
		t.Fatalf("research register: %+v %v", p.Plan, err)
	}
	if err := researchPlanChecks(root, p); err != nil {
		t.Errorf("the registered plan against the writer's keys: %v", err)
	}

	asOnly(t, root, "dana")
	if err := cmdEngagement(root, []string{"open", "annual", "--firm", "Example LLP", "--auditor", "lee",
		"--scope", "example", "--from", "2026-01-01", "--to", "2026-06-30",
		"--until", time.Now().AddDate(0, 0, 90).Format("2006-01-02"),
		"--because", "the annual audit"}); err != nil {
		t.Fatal(err)
	}
	eng := filepath.Join(t.TempDir(), "engagement.json")
	if err := cmdEngagement(root, []string{"issue", "annual", "-o", eng}); err != nil {
		t.Fatalf("engagement issue: %v", err)
	}
	if err := cmdEngagement(root, []string{"check", eng, "--keys", keys}); err != nil {
		t.Errorf("the engagement package against the writer's keys: %v", err)
	}
}

// sharedTempDir is a directory other accounts can reach: every directory
// above it lets them through, which t.TempDir's do not.
func sharedTempDir(t *testing.T) string {
	t.Helper()
	for _, parent := range []string{os.TempDir(), "/tmp"} {
		reachable := true
		for p := parent; ; p = filepath.Dir(p) {
			fi, err := os.Stat(p)
			if err != nil || fi.Mode().Perm()&0o001 == 0 {
				reachable = false
				break
			}
			if p == filepath.Dir(p) {
				break
			}
		}
		if !reachable {
			continue
		}
		dir, err := os.MkdirTemp(parent, "quilzo-logd-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	t.Skip("no temporary directory here that another account can reach")
	return ""
}

// The reference compose, in the shape that broke: the writer runs as its
// own account and owns the audit directory, mode 0750; the CMS is another
// account, in its group, for which that directory is read-only. Before the
// writer held the key every command below exited 1 with "read-only file
// system", trying to make head.key where it could not write.
//
// Run as root, which can start the two as the accounts compose gives them;
// skipped elsewhere.
func TestUnderTheComposeLayoutTheCMSHasItsHeadsSignedByTheWriter(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root on Linux, to run the writer and the CMS as two accounts")
	}
	t.Setenv("HOME", t.TempDir())
	base := sharedTempDir(t)
	bin := filepath.Join(base, "quilzo")
	copyExecutable(t, os.Args[0], bin)

	// The store, made here and then handed to the CMS's account.
	if w == nil {
		w = out.New(false)
	}
	root := filepath.Join(base, "store")
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(root, []string{"-publish=false", "-templates", filepath.Join(base, "tpl")}); err != nil {
		t.Fatal(err)
	}
	seedPolicy(t, root, [2]string{"dana", "admin"})
	toks, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := toks.Issue("dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), toks); err != nil {
		t.Fatal(err)
	}

	// The audit volume: the writer's, readable by its group, as the image
	// seeds it.
	dir := filepath.Join(base, "audit")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, writerAccount, cmsAccount); err != nil {
		t.Fatal(err)
	}
	if err := setAuditDir(root, dir); err != nil {
		t.Fatal(err)
	}

	// The writer, as compose runs it. Its --root is a directory that is not
	// its own, as /srv/store is in its container. It also takes records from
	// this test's own account, for the setup below.
	writerStore := filepath.Join(base, "writer-root")
	if err := os.Mkdir(writerStore, 0o755); err != nil {
		t.Fatal(err)
	}
	logdErr, err := os.Create(filepath.Join(base, "logd.stderr"))
	if err != nil {
		t.Fatal(err)
	}
	writer := exec.Command(bin, "quilzo-main", "--root", writerStore, "logd", "--log-dir", dir,
		"--allow-uid", "65532,0")
	writer.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: writerAccount, Gid: cmsAccount}}
	writer.Stdout, writer.Stderr = logdErr, logdErr
	if err := writer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = writer.Process.Signal(syscall.SIGTERM)
		_ = writer.Wait()
	})
	said := func() string { b, _ := os.ReadFile(logdErr.Name()); return string(b) }
	deadline := time.Now().Add(60 * time.Second)
	for !fileExists(filepath.Join(dir, "log.sock")) || !fileExists(filepath.Join(dir, "head.pub.json")) {
		if time.Now().After(deadline) {
			t.Fatalf("the writer did not start:\n%s", said())
		}
		time.Sleep(50 * time.Millisecond)
	}
	for name, mode := range map[string]os.FileMode{"head.key": 0o600, "head.pub.json": 0o644} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != writerAccount || fi.Mode().Perm() != mode {
			t.Errorf("%s is uid %d, %v: it should be the writer's, %v", name, st.Uid, fi.Mode().Perm(), mode)
		}
	}

	// A kept agent run, recorded through the writer, and the stream set up,
	// before the store is handed over.
	m := asker("tidy")
	m.AskFirst = nil
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	run, _, err := runAgentKept(context.Background(), root, "tidy", "tidy the about page", false, asAdmin("dana"))
	if err != nil && run == "" {
		t.Fatalf("%v\n%s", err, said())
	}
	key, err := streamKey(root)
	if err != nil {
		t.Fatal(err)
	}
	heads, err := publishedVerifier(filepath.Join(dir, "head.pub.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv, recv := streamReceiver(t, heads, key.Public().(ed25519.PublicKey))
	if err := cmdConfig(root, []string{"set", "siem.stream.url", srv.URL + "/quilzo"}); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(base, "out")
	home := filepath.Join(base, "home")
	for _, d := range []string{outDir, home} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{root, filepath.Join(base, "tpl"), outDir, home} {
		chownTree(t, d, cmsAccount, cmsAccount)
	}

	// From here on the commands run as the CMS.
	asCMS := func(args ...string) (string, string, error) {
		cmd := exec.Command(bin, append([]string{"quilzo-main", "--root", root}, args...)...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: cmsAccount, Gid: cmsAccount}}
		cmd.Env = append(os.Environ(), "HOME="+home, "QUILZO_TOKEN="+secret, "NO_COLOR=1")
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}
	cms := func(args ...string) string {
		t.Helper()
		stdout, stderr, err := asCMS(args...)
		if err != nil {
			t.Fatalf("quilzo %s, as the CMS: %v\n%s%s\nthe writer said:\n%s",
				strings.Join(args, " "), err, stdout, stderr, said())
		}
		return stdout
	}

	var head audit.SignedHead
	if err := json.Unmarshal([]byte(cms("--json", "auditlog", "head", "--save")), &head); err != nil {
		t.Fatal(err)
	}
	if err := heads.Verify(head); err != nil {
		t.Errorf("the saved head does not verify against the writer's keys: %v", err)
	}
	var saved headFile
	if err := loadJSON(headsPath(root), &saved); err != nil || len(saved.Heads) != 1 || saved.Heads[0].Root != head.Root {
		t.Errorf("the store saved %+v: %v", saved.Heads, err)
	}

	receipt := filepath.Join(outDir, "receipt.json")
	cms("agent", "receipt", run, "-o", receipt)
	if got := cms("agent", "verify-receipt", receipt, "--keys", filepath.Join(dir, "head.pub.json")); !strings.Contains(got, "verified") {
		t.Errorf("verify-receipt --keys AUDITDIR/head.pub.json said:\n%s", got)
	}

	cms("siem", "stream", "send")
	if recv.holds() == 0 {
		t.Error("a round of the audit stream sent nothing")
	}

	var status map[string]any
	if err := json.Unmarshal([]byte(cms("--json", "logd", "status")), &status); err != nil {
		t.Fatal(err)
	}
	if status["separated"] != true || status["heads_signed_by"] != "the log writer" {
		t.Errorf("logd status, as the CMS: %v", status)
	}

	// A client that sends a root of its own is given a head over the true
	// one, from the writer's file.
	events, err := audit.Read(filepath.Join(dir, "audit.jsonl"))
	if err != nil || len(events) == 0 {
		t.Fatalf("%d entries: %v", len(events), err)
	}
	conn, err := net.Dial("unix", filepath.Join(dir, "log.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	forged := strings.Repeat("f", 64)
	body, _ := json.Marshal(map[string]any{"sign_head": map[string]any{"size": len(events), "root": forged}, "root": forged})
	if _, err := conn.Write(append(body, '\n')); err != nil {
		t.Fatal(err)
	}
	var resp logd.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil || resp.Head == nil {
		t.Fatalf("%+v %v", resp, err)
	}
	truth, _ := audit.TreeHead(events, time.Now())
	if resp.Head.Root != truth.Root || resp.Head.Root == forged {
		t.Errorf("a forged root got a head over %s; the log's is %s", resp.Head.Root, truth.Root)
	}
	if err := heads.Verify(*resp.Head); err != nil {
		t.Error(err)
	}

	// The writer stopped: the key is still its own, and asking for a head
	// says to start it rather than suggesting this account take the key.
	_ = writer.Process.Signal(syscall.SIGTERM)
	_ = writer.Wait()
	stdout, stderr, err := asCMS("auditlog", "head")
	if err == nil || !strings.Contains(stdout+stderr, "start quilzo logd") {
		t.Errorf("a head with the writer stopped: %v\n%s%s", err, stdout, stderr)
	}
}

func copyExecutable(t *testing.T, from, to string) {
	t.Helper()
	src, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
}
