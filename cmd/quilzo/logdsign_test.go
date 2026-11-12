// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auditstream"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/httpsig"
	"github.com/quilzo/quilzo/internal/logd"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/render"
)

// The accounts the reference compose runs the log writer and the CMS as
// (deploy/compose.yaml).
const (
	writerAccount = 65533
	cmsAccount    = 65532
	// siteGroup is the group the site connects to the writer as, so the
	// writer can tell it from the admin, which is the same uid.
	siteGroup = 65531
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

// The writer signs only with a key no other account could have read.
//
// A key the CMS made, before the writer held one, is a key the CMS may have
// kept, and a key its group can read is one the CMS can copy: either way
// the CMS can sign a head over any root it likes, which is the thing the
// writer holding the key exists to stop. The writer took any key it could
// read, and the advice for one it could not was to chown it over, which
// hands the writer a key somebody else has held.
func TestTheWriterSignsWithNoKeyAnotherAccountCouldHaveHeld(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := setAuditDir(root, dir); err != nil {
		t.Fatal(err)
	}
	// A key made beside the log before the writer started, as a CMS that
	// could still write there made one.
	if _, err := localHeadSigner(root); err != nil {
		t.Fatal(err)
	}
	key := headKeyPath(root)

	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	srv, err := newLogWriter(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Heads != nil {
		t.Error("the writer signs with a key its group can read")
	}
	if !strings.Contains(srv.HeadsWhy, "0640") || !strings.Contains(srv.HeadsWhy, "aside") {
		t.Errorf("the writer did not say why, or what to do: %q", srv.HeadsWhy)
	}

	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	if srv, err = newLogWriter(root, nil); err != nil || srv.Heads == nil {
		t.Fatalf("the writer does not sign with a key that is its own alone: %v %q", err, srv.HeadsWhy)
	}

	if os.Geteuid() != 0 {
		t.Skip("giving the key to another account needs root")
	}
	if err := os.Chown(key, cmsAccount, cmsAccount); err != nil {
		t.Fatal(err)
	}
	if srv, err = newLogWriter(root, nil); err != nil {
		t.Fatal(err)
	}
	if srv.Heads != nil {
		t.Error("the writer signs with a key another account made")
	}
	if !strings.Contains(srv.HeadsWhy, "uid 65532") || !strings.Contains(srv.HeadsWhy, "aside") ||
		strings.Contains(srv.HeadsWhy, "chown") {
		t.Errorf("the writer did not say to replace a key another account has held: %q", srv.HeadsWhy)
	}
}

// `logd status` asks the writer whether it signs rather than assuming so.
//
// A writer that cannot use its key still writes the log, and says why on
// its own stderr, which nobody running the CMS reads. Status read the
// published keys, found a key id, and said in green that the writer signs
// its heads with that key: true of no head at all, while every receipt and
// every round of the stream failed.
func TestLogdStatusSaysWhenTheWriterDoesNotSign(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := setAuditDir(root, dir); err != nil {
		t.Fatal(err)
	}
	srv, err := newLogWriter(root, nil)
	if err != nil || srv.Heads == nil {
		t.Fatalf("%v %q", err, srv.HeadsWhy)
	}
	// The key it made, and then could not use.
	srv.Heads, srv.HeadsWhy = nil, "head.key is not readable"
	ln, err := logd.Listen(logSocketPath(root))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	giveTheLogAway(t, dir)

	st := logdStatusJSON(t, root)
	if st["heads_signed_by"] != "the log writer" {
		t.Fatalf("status says heads are signed by %v", st["heads_signed_by"])
	}
	if st["writer_signs"] != false || !strings.Contains(statusText(st["writer_refuses"]), "head.key is not readable") {
		t.Errorf("status did not say the writer refuses, and why: %v %v", st["writer_signs"], st["writer_refuses"])
	}
	human := logdStatusHuman(t, root)
	if strings.Contains(human, "the writer signs its heads with key") {
		t.Errorf("status says the writer signs:\n%s", human)
	}
	if !strings.Contains(human, "head.key is not readable") {
		t.Errorf("status does not say why the writer signs nothing:\n%s", human)
	}
}

func statusText(v any) string { s, _ := v.(string); return s }

// logdStatusHuman is `quilzo logd status` as a person reads it.
func logdStatusHuman(t *testing.T, root string) string {
	t.Helper()
	old := w
	t.Cleanup(func() { w = old })
	w = out.New(false)
	var buf bytes.Buffer
	w.Out = &buf
	if err := cmdLogdStatus(root); err != nil {
		t.Fatal(err)
	}
	w = old
	return buf.String()
}

// A writer that publishes no keys signs nothing anybody can check, so every
// head it is asked for is refused here. Status said in yellow that "the
// writer signs its heads", and its JSON gave writer_refuses as empty: a
// script reading the field was told nothing was refused while every
// receipt and every round of the stream failed.
func TestLogdStatusSaysNoHeadCanBeMadeWhenTheWriterPublishesNoKeys(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	dir, _ := startWriter(t, root)
	giveTheLogAway(t, dir)
	if err := os.Remove(filepath.Join(dir, "head.pub.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := headSigner(root); err == nil {
		t.Fatal("a head was to be signed with no published keys to check it against")
	}

	st := logdStatusJSON(t, root)
	if st["heads_signed_by"] != "the log writer" || st["writer_signs"] != false {
		t.Errorf("status: %v", st)
	}
	if !strings.Contains(statusText(st["writer_refuses"]), "public keys cannot be read") {
		t.Errorf("status did not say why no head can be made: %q", st["writer_refuses"])
	}
	human := logdStatusHuman(t, root)
	if strings.Contains(human, "the writer signs its heads") {
		t.Errorf("status says the writer signs:\n%s", human)
	}
	if !strings.Contains(human, "publishes no keys") || !strings.Contains(human, "none can be made") {
		t.Errorf("status does not say no head can be made, and why:\n%s", human)
	}
}

// The audit log screen says who signs the log's heads as the writer is
// now, not as it was when the server started.
//
// It read both once: a writer that could not use its key went on writing
// the log, and the page said its heads were signed by the writer while the
// receipt button on the apps screen failed; a writer started after the
// server, which compose can do, was never mentioned at all.
func TestTheAuditLogScreenSaysWhetherTheWriterSignsNow(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const signs = "signed by\n    the writer too"

	// A writer with no key it may use.
	root := demoStore(t)
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := setAuditDir(root, dir); err != nil {
		t.Fatal(err)
	}
	refusing, err := newLogWriter(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	refusing.Heads, refusing.HeadsWhy = nil, "head.key is not readable"
	ln, err := logd.Listen(logSocketPath(root))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = refusing.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	giveTheLogAway(t, dir)
	srv, tok := logScreen(t, root)
	body := adminGet(t, srv, "/logs", tok)
	if strings.Contains(body, signs) {
		t.Errorf("the screen says the writer signs heads it refuses:\n%s", body)
	}
	if !strings.Contains(body, "it signs\n    none") || !strings.Contains(body, "head.key is not readable") {
		t.Errorf("the screen does not say the writer signs none, and why:\n%s", body)
	}

	// A writer started after the screen was built, that signs.
	root = demoStore(t)
	srv, tok = logScreen(t, root)
	if body := adminGet(t, srv, "/logs", tok); strings.Contains(body, signs) || strings.Contains(body, "signs\n    none") {
		t.Errorf("with the log in the store the screen names a writer:\n%s", body)
	}
	dir, _ = startWriter(t, root)
	giveTheLogAway(t, dir)
	body = adminGet(t, srv, "/logs", tok)
	if !strings.Contains(body, signs) || !strings.Contains(body, filepath.Join(dir, "head.pub.json")) {
		t.Errorf("the screen does not say the writer started since signs, or where its keys are:\n%s", body)
	}
}

// logScreen is the admin as `quilzo serve` builds it for the audit log
// screen, and an administrator's session.
func logScreen(t *testing.T, root string) (*admin.Server, string) {
	t.Helper()
	seedPolicy(t, root, [2]string{"dana", "admin"})
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	toks, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(s, pol, toks, render.Layouts{})
	if err != nil {
		t.Fatal(err)
	}
	srv.LoadAudit = func() ([]audit.Event, error) { return audit.Read(auditPath(root)) }
	logHeadsHook(srv, root)
	tok := tokenFor(t, toks, waitingSession{name: "dana", actor: admin.Actor{Name: "dana", Role: auth.RoleAdmin, Scope: "/"}})
	return srv, tok
}
