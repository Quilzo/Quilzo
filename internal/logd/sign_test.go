// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package logd

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
