// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package logd

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
)

const testContext = "quilzo/test-statement/v1"

// signingWriter is a writer holding a head key, with n records already in
// its log. configure, when given, changes the writer before it serves.
func signingWriter(t *testing.T, n int, configure ...func(*Server)) (sock string, s *Server,
	signer *audit.HeadSigner, path string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "audit.jsonl")
	l, err := audit.New(audit.Options{Path: path, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ed, ml, err := audit.GenerateHeadSeeds()
	if err != nil {
		t.Fatal(err)
	}
	if signer, err = audit.NewHeadSigner(ed, ml); err != nil {
		t.Fatal(err)
	}
	sock = filepath.Join(dir, "log.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	s = &Server{Log: l, Heads: signer, Statements: []string{testContext}}
	for _, c := range configure {
		c(s)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	for i := 0; i < n; i++ {
		if _, err := Submit(sock, Submission{Action: "publish", Resource: "/", Outcome: "success",
			Principal: "dana", Kind: "human", Verified: true}); err != nil {
			t.Fatal(err)
		}
	}
	return sock, s, signer, path
}

// The root a head carries is the writer's, computed over its own file.
func trueHead(t *testing.T, path string, size int) audit.Head {
	t.Helper()
	events, err := audit.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := audit.TreeHead(events[:size], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestTheWriterSignsAHeadOverTheFirstEntriesOfItsOwnLog(t *testing.T) {
	sock, _, signer, path := signingWriter(t, 4)
	for _, size := range []int{0, 2, 4} {
		sh, err := SignHead(sock, size)
		if err != nil {
			t.Fatalf("a head over %d: %v", size, err)
		}
		if want := trueHead(t, path, size); sh.Size != size || sh.Root != want.Root {
			t.Errorf("a head over %d carries %d entries and root %s; the log's is %s", size, sh.Size, sh.Root, want.Root)
		}
		if err := signer.Verifier().Verify(*sh); err != nil {
			t.Errorf("the writer's head does not verify: %v", err)
		}
		if len(sh.Algorithms) != 2 {
			t.Errorf("the head was signed by %v, not both algorithms", sh.Algorithms)
		}
	}
}

// The heart of it, for heads. A client that could name the root would have
// the writer sign whatever it was told, which is the CMS holding the key by
// another route; and one that could name the time could backdate a
// commitment to entries that did not exist yet.
func TestAClientThatSendsAForgedRootGetsAHeadOverTheTrueOne(t *testing.T) {
	sock, _, signer, path := signingWriter(t, 3)
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	forged := strings.Repeat("f", 64)
	body, _ := json.Marshal(map[string]any{
		"sign_head": map[string]any{"size": 3, "root": forged, "at": "1999-01-01T00:00:00Z"},
		"root":      forged, "at": "1999-01-01T00:00:00Z",
	})
	if _, err := conn.Write(append(body, '\n')); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != "" || resp.Head == nil {
		t.Fatalf("the writer answered %+v", resp)
	}
	if resp.Head.Root == forged {
		t.Fatal("the writer signed the root the client sent")
	}
	if want := trueHead(t, path, 3); resp.Head.Root != want.Root || resp.Head.Size != 3 {
		t.Errorf("the head is over %d entries with root %s; the log's is %s", resp.Head.Size, resp.Head.Root, want.Root)
	}
	if strings.HasPrefix(resp.Head.At, "1999") {
		t.Error("the client backdated the head")
	}
	if err := signer.Verifier().Verify(*resp.Head); err != nil {
		t.Errorf("the head does not verify: %v", err)
	}
}

// Asking for a signature is never a record: the log holds what was
// submitted and nothing for each head or statement asked of it.
func TestAskingForASignatureWritesNothingToTheLog(t *testing.T) {
	sock, _, _, path := signingWriter(t, 2)
	for i := 0; i < 3; i++ {
		if _, err := SignHead(sock, 2); err != nil {
			t.Fatal(err)
		}
		if _, err := SignStatement(sock, testContext, []byte("sha256:abc")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SignHead(sock, 9); err == nil {
		t.Error("a head past the end of the log was signed")
	}
	events, err := audit.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("the log holds %d entries after two records and six signatures", len(events))
	}
}

func TestAHeadThatIsNotOverTheLogIsRefused(t *testing.T) {
	sock, _, _, _ := signingWriter(t, 2)
	if _, err := SignHead(sock, 3); err == nil || !strings.Contains(err.Error(), "holds 2 entries") {
		t.Errorf("a head over more entries than the log holds: %v", err)
	}
	if _, err := SignHead(sock, -1); err == nil {
		t.Error("a head over a negative number of entries was signed")
	}
}

// A statement is signed under a context the writer was given and no other,
// and never under the head's own: a signing oracle over arbitrary contexts
// would sign the next kind of statement before anybody decided the CMS
// should be able to ask for one.
func TestAStatementIsSignedOnlyUnderANamedContext(t *testing.T) {
	sock, _, signer, _ := signingWriter(t, 1)
	msg := []byte("sha256:0123")
	st, err := SignStatement(sock, testContext, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Verifier().VerifyStatement(testContext, msg, *st); err != nil {
		t.Errorf("the statement does not verify: %v", err)
	}
	for _, ctx := range []string{"quilzo/other/v1", "quilzo/audit-head/v1", ""} {
		if _, err := SignStatement(sock, ctx, msg); err == nil {
			t.Errorf("a statement under %q was signed", ctx)
		}
	}
	if _, err := SignStatement(sock, testContext, make([]byte, MaxStatementBytes+1)); err == nil {
		t.Error("a statement over more than a digest was signed")
	}
	if _, err := SignStatement(sock, testContext, nil); err == nil {
		t.Error("a statement over nothing was signed")
	}
}

// A writer that could not load its key still writes the log, and says why
// it signs nothing rather than answering with nothing.
func TestAWriterWithoutAKeyWritesRecordsAndSaysWhyItSignsNothing(t *testing.T) {
	sock, _, _, path := signingWriter(t, 1, func(s *Server) {
		s.Heads, s.HeadsWhy = nil, "head.key is not readable"
	})
	if _, err := SignHead(sock, 1); err == nil || !strings.Contains(err.Error(), "head.key is not readable") {
		t.Errorf("a writer without a key answered: %v", err)
	}
	if _, err := SignStatement(sock, testContext, []byte("x")); err == nil {
		t.Error("a writer without a key signed a statement")
	}
	if _, err := Submit(sock, Submission{Action: "publish", Resource: "/", Outcome: "success",
		Principal: "dana", Kind: "human", Verified: true}); err != nil {
		t.Fatalf("a writer without a key stopped writing the log: %v", err)
	}
	if events, _ := audit.Read(path); len(events) != 2 {
		t.Errorf("the log holds %d entries", len(events))
	}
}

// The same accounts may ask for a signature as may submit a record.
func TestAnAccountThatMayNotSubmitMayNotAskForAHead(t *testing.T) {
	refused := make(chan string, 1)
	sock, _, _, _ := signingWriter(t, 0, func(s *Server) {
		s.AllowUID = []int{os.Geteuid() + 1}
		s.OnRefusal = func(reason string, uid int) { refused <- reason }
	})
	if _, err := SignHead(sock, 0); err == nil {
		t.Fatal("an account the writer does not take records from was given a head")
	}
	if why := <-refused; !strings.Contains(why, "not permitted") {
		t.Errorf("the refusal was not reported: %q", why)
	}
}

// Heads are read under the locks appends take, so a head asked for while
// records arrive is never refused over a half-written line.
func TestAHeadAskedForWhileRecordsArriveIsAlwaysSigned(t *testing.T) {
	sock, _, signer, _ := signingWriter(t, 1)
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 20; i++ {
			if _, err := Submit(sock, Submission{Action: "publish", Resource: "/", Outcome: "success",
				Principal: "dana", Kind: "human", Verified: true}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 10; i++ {
		sh, err := SignHead(sock, 1)
		if err != nil {
			t.Fatalf("a head asked for while records arrived: %v", err)
		}
		if err := signer.Verifier().Verify(*sh); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// lengthen makes the writer's log n entries long by copying its first line:
// a long file to read and hash, not a chain, which nothing here verifies.
// Appending that many records one at a time, each synced, would take
// minutes.
func lengthen(t *testing.T, path string, n int) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := body[:bytes.IndexByte(body, '\n')+1]
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(bytes.Repeat(line, n-1)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// A head is computed over the whole log, and a record does not wait for one.
//
// The writer read its log back under the locks every append takes, which
// for a log of a year or two is over a second, and the stream, a receipt
// and `auditlog head` each ask for one. A record submitted meanwhile waited
// for all of them: with eight clients asking, most records ran past the
// writer's five seconds and were not written, and a record not written is
// an agent refused until one is (auditReady). Any account that may submit
// may ask for a head, the public site's included.
//
// What is measured is the wait for the lock an append takes, not a
// record's whole round trip: its own fsync varies on a shared disk by more
// than the wait is long.
func TestARecordIsWrittenWhileHeadsAreComputedOverALongLog(t *testing.T) {
	sock, _, _, path := signingWriter(t, 0)
	rec := Submission{Action: "publish", Resource: "/about", Outcome: "success",
		Principal: "dana", Kind: "human", Verified: true,
		Detail: map[string]string{"why": "a reason of the length people give for a change", "path": "/content/about.md"}}
	if _, err := Submit(sock, rec); err != nil {
		t.Fatal(err)
	}
	const n = 30000
	lengthen(t, path, n)

	start := time.Now()
	if _, err := SignHead(sock, n); err != nil {
		t.Fatal(err)
	}
	alone := time.Since(start)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = SignHead(sock, n)
			}
		}()
	}
	var worst time.Duration
	for end := time.Now().Add(alone); time.Now().Before(end); {
		asked := time.Now()
		unlock, err := atomicfile.Lock(path + ".lock")
		if err != nil {
			t.Fatal(err)
		}
		worst = max(worst, time.Since(asked))
		unlock()
		time.Sleep(time.Millisecond)
	}
	if _, err := Submit(sock, rec); err != nil {
		t.Errorf("a record submitted while heads were computed was not written: %v", err)
	}
	close(stop)
	wg.Wait()
	if worst > alone/4 {
		t.Errorf("an append waited %v for its lock while heads were computed, and one head over the log takes %v",
			worst, alone)
	}
}

// One head at a time. A head holds every entry of the log in memory while
// it is computed, and once reading the log stopped holding up records,
// heads asked for at once each held a copy of their own: enough of them
// and the writer is killed for its memory, and then nothing is written.
func TestHeadsAreComputedOneAtATime(t *testing.T) {
	sock, s, signer, _ := signingWriter(t, 2)
	release, ok := s.oneHead(time.Now().Add(time.Second))
	if !ok {
		t.Fatal("no head is being computed, and one could not start")
	}
	got := make(chan error, 1)
	go func() {
		sh, err := SignHead(sock, 2)
		if err == nil {
			err = signer.Verifier().Verify(*sh)
		}
		got <- err
	}()
	select {
	case err := <-got:
		t.Fatalf("a head was computed while another was: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	// A head over no entries reads none, so it waits for nothing: it is
	// what `logd status` asks to learn whether the writer signs at all.
	asked := time.Now()
	if _, err := SignHead(sock, 0); err != nil {
		t.Fatalf("a head over no entries while another was computed: %v", err)
	}
	if waited := time.Since(asked); waited > 200*time.Millisecond {
		t.Errorf("a head over no entries waited %v for one over the log", waited)
	}
	release()
	if err := <-got; err != nil {
		t.Fatalf("the head waiting its turn: %v", err)
	}

	// A head that cannot start by its deadline is refused rather than
	// computed for a client that has stopped waiting.
	release, _ = s.oneHead(time.Now().Add(time.Second))
	defer release()
	if _, ok := s.oneHead(time.Now().Add(50 * time.Millisecond)); ok {
		t.Error("a second head started while one was being computed")
	}
}

// An account the writer cannot name is refused where only some accounts
// may submit or ask for a signature.
//
// Where the kernel cannot say who connected (any platform but Linux), the
// writer skipped the check and took the record, and now the request for a
// head or a statement, from whoever connected: --allow-uid was a list
// nobody was checked against, while the writer said it accepted
// submissions from those accounts only. Without a list any account that
// can reach the socket may submit, as it always could, so that stays.
func TestAnAccountTheWriterCannotNameIsRefusedWhereOnlySomeMay(t *testing.T) {
	askPeer = func(net.Conn) (int, int, error) { return -1, -1, errors.New("no peer credentials on this platform") }
	t.Cleanup(func() { askPeer = peerCreds })
	rec := Submission{Action: "publish", Resource: "/", Outcome: "success",
		Principal: "dana", Kind: "human", Verified: true}

	sock, _, _, path := signingWriter(t, 0, func(s *Server) { s.AllowUID = []int{os.Geteuid()} })
	if _, err := Submit(sock, rec); err == nil {
		t.Error("a record from an account nobody could name was written past --allow-uid")
	}
	if _, err := SignHead(sock, 0); err == nil {
		t.Error("a head was signed for an account nobody could name, past --allow-uid")
	}
	if _, err := SignStatement(sock, testContext, []byte("sha256:0123")); err == nil {
		t.Error("a statement was signed for an account nobody could name, past --allow-uid")
	}
	if events, _ := audit.Read(path); len(events) != 0 {
		t.Errorf("the log holds %d entries", len(events))
	}

	open, _, _, _ := signingWriter(t, 0)
	if _, err := Submit(open, rec); err != nil {
		t.Errorf("a writer with no list refused an account it could not name: %v", err)
	}
}

// The writer takes records from every account that may submit, and signs
// only for those named to ask for a signature: by uid, and by the group the
// account connected as.
//
// It signed for every account that could submit. In the reference compose
// the public site and the admin are one uid, so anything that could run
// code as the public site could have the writer sign a feature package or
// a research plan with the log's key.
func TestOnlyTheAccountsNamedMayAskForASignature(t *testing.T) {
	const account, admins, site = 65532, 65532, 65531
	// Who connects is changed between connections, never askPeer itself,
	// which the writers' goroutines read: set once, before any is started.
	type peer struct {
		uid, gid int
		err      error
	}
	var who atomic.Pointer[peer]
	who.Store(&peer{uid: account, gid: site})
	askPeer = func(net.Conn) (int, int, error) { p := who.Load(); return p.uid, p.gid, p.err }
	t.Cleanup(func() { askPeer = peerCreds })
	as := func(uid, gid int) { who.Store(&peer{uid: uid, gid: gid}) }
	rec := Submission{Action: "publish", Resource: "/", Outcome: "success",
		Principal: "dana", Kind: "human", Verified: true}
	msg := []byte("sha256:0123")

	refused := make(chan string, 8)
	sock, _, signer, path := signingWriter(t, 0, func(s *Server) {
		s.AllowUID, s.SignGID = []int{account}, []int{admins}
		s.OnRefusal = func(reason string, uid int) { refused <- reason }
	})

	// The site: the admin's uid, a group of its own. Its records are
	// written; it is given no signature.
	as(account, site)
	if _, err := Submit(sock, rec); err != nil {
		t.Fatalf("the site's record was refused: %v", err)
	}
	if _, err := SignStatement(sock, testContext, msg); err == nil {
		t.Error("the site had the writer sign a statement")
	} else {
		select {
		case why := <-refused:
			if !strings.Contains(why, "may not ask for a signature") {
				t.Errorf("the refusal says %q", why)
			}
		case <-time.After(5 * time.Second):
			t.Error("the refusal was not reported")
		}
	}
	if _, err := SignHead(sock, 1); err == nil {
		t.Error("the site had the writer sign a head")
	}

	// The admin: the same uid, the group named.
	as(account, admins)
	st, err := SignStatement(sock, testContext, msg)
	if err != nil {
		t.Fatalf("the admin was refused a statement: %v", err)
	}
	if err := signer.Verifier().VerifyStatement(testContext, msg, *st); err != nil {
		t.Error(err)
	}
	if _, err := SignHead(sock, 1); err != nil {
		t.Errorf("the admin was refused a head: %v", err)
	}
	if events, _ := audit.Read(path); len(events) != 1 {
		t.Errorf("the log holds %d entries, not the site's one record", len(events))
	}

	// By uid as well: an account that may submit, not named to sign.
	byUID, _, _, _ := signingWriter(t, 0, func(s *Server) { s.AllowUID, s.SignUID = []int{account, 1000}, []int{1000} })
	if _, err := SignStatement(byUID, testContext, msg); err == nil {
		t.Error("an account --sign-uid does not name had a statement signed")
	}
	as(1000, 1000)
	if _, err := SignStatement(byUID, testContext, msg); err != nil {
		t.Errorf("the account --sign-uid names was refused: %v", err)
	}

	// With neither named, every account that may submit may ask, as before.
	as(account, site)
	open, _, _, _ := signingWriter(t, 0, func(s *Server) { s.AllowUID = []int{account} })
	if _, err := SignStatement(open, testContext, msg); err != nil {
		t.Errorf("with no list, an account that may submit was refused a statement: %v", err)
	}

	// And an account nobody can name is refused a signature where only some
	// may ask, though any account may submit.
	who.Store(&peer{uid: -1, gid: -1, err: errors.New("no peer credentials on this platform")})
	unnamed, _, _, _ := signingWriter(t, 0, func(s *Server) { s.SignGID = []int{admins} })
	if _, err := Submit(unnamed, rec); err != nil {
		t.Errorf("with no --allow-uid, a record from an account nobody could name was refused: %v", err)
	}
	if _, err := SignStatement(unnamed, testContext, msg); err == nil {
		t.Error("an account nobody could name had a statement signed past --sign-gid")
	}
}

// The group is the kernel's answer, as the uid is: this process, connecting
// as its own group, is signed for where that group is named and refused
// where another is.
func TestTheGroupAskingIsTheOneTheKernelNames(t *testing.T) {
	if _, _, err := peerCreds(nil); err != nil && strings.Contains(err.Error(), "only be read from the kernel on Linux") {
		t.Skip(err)
	}
	msg := []byte("sha256:0123")
	mine, _, _, _ := signingWriter(t, 0, func(s *Server) { s.SignGID = []int{os.Getegid()} })
	if _, err := SignStatement(mine, testContext, msg); err != nil {
		t.Errorf("connecting as group %d, named, was refused: %v", os.Getegid(), err)
	}
	other, _, _, _ := signingWriter(t, 0, func(s *Server) { s.SignGID = []int{os.Getegid() + 1} })
	if _, err := SignStatement(other, testContext, msg); err == nil {
		t.Errorf("connecting as group %d, with only %d named, had a statement signed", os.Getegid(), os.Getegid()+1)
	}
	if _, err := Submit(other, Submission{Action: "publish", Resource: "/", Outcome: "success",
		Principal: "dana", Kind: "human", Verified: true}); err != nil {
		t.Errorf("an account that may not ask for a signature could not submit a record: %v", err)
	}
}
