package logd

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lithoform/lithoform/internal/audit"
)

func writer(t *testing.T) (string, *audit.Log, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	l, err := audit.New(audit.Options{Path: logPath, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "log.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Log: l}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	// The listener is ready before Listen returns, so no sleep is needed; this
	// only guards against a scheduler that has not run the goroutine yet.
	time.Sleep(20 * time.Millisecond)
	return sock, l, logPath
}

func TestASubmittedRecordIsAppended(t *testing.T) {
	sock, _, path := writer(t)

	resp, err := Submit(sock, Submission{
		Action: "publish", Resource: "/", Outcome: "success",
		Principal: "dana", Kind: "human", Verified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Seq != 1 || resp.Hash == "" {
		t.Errorf("the writer answered %#v", resp)
	}

	events, err := audit.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "publish" {
		t.Fatalf("got %#v", events)
	}
	if ok, problems := audit.Verify(events); !ok {
		t.Errorf("the chain does not verify: %v", problems)
	}
}

// The heart of it. If the submitting process could choose the sequence number,
// the previous hash or the entry hash, a compromised CMS could submit a
// self-consistent run of forged entries and the log would verify perfectly.
func TestAClientCannotChooseItsOwnSequenceOrHash(t *testing.T) {
	sock, _, path := writer(t)

	// Send a payload carrying every field a forger would want. The Submission
	// type has nowhere to put them, so they are not merely rejected — there is
	// nothing to reject.
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	forged := map[string]any{
		"action": "publish", "resource": "/", "outcome": "success",
		"principal": "dana", "kind": "human", "verified": true,
		"seq": 9999, "prev": strings.Repeat("a", 64),
		"hash": strings.Repeat("b", 64), "at": "1999-01-01T00:00:00Z",
	}
	body, _ := json.Marshal(forged)
	_, _ = conn.Write(append(body, '\n'))
	var resp Response
	_ = json.NewDecoder(conn).Decode(&resp)
	conn.Close()

	events, err := audit.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d entries", len(events))
	}
	e := events[0]
	if e.Seq != 1 {
		t.Errorf("the client chose sequence %d", e.Seq)
	}
	if e.Hash == strings.Repeat("b", 64) {
		t.Error("the client chose its own entry hash")
	}
	if e.Prev != "" {
		t.Error("the client chose a predecessor for the first entry")
	}
	if strings.HasPrefix(e.At, "1999") {
		t.Error("the client backdated its own record")
	}
	if ok, _ := audit.Verify(events); !ok {
		t.Error("the resulting chain does not verify")
	}
}

// A run of submissions must produce a chain, not a set of unrelated entries.
func TestConcurrentSubmissionsProduceOneOrderedChain(t *testing.T) {
	sock, _, path := writer(t)

	done := make(chan error, 20)
	for i := range 20 {
		go func(i int) {
			_, err := Submit(sock, Submission{
				Action: "publish", Resource: "/", Outcome: "success",
				Principal: "dana", Kind: "human", Verified: true,
				Detail: map[string]string{"n": string(rune('a' + i))},
			})
			done <- err
		}(i)
	}
	for range 20 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}

	events, err := audit.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 20 {
		t.Fatalf("got %d entries from 20 submissions", len(events))
	}
	// Two goroutines computing "the previous hash" at once would produce two
	// entries claiming the same predecessor, and the chain would not verify.
	if ok, problems := audit.Verify(events); !ok {
		t.Errorf("concurrent writes broke the chain: %v", problems)
	}
}

// The writer is the trust boundary now, so a record it would refuse must be
// refused here rather than written and discovered later.
func TestTheWriterEnforcesTheSameRulesTheLogDoes(t *testing.T) {
	sock, _, path := writer(t)

	for _, bad := range []Submission{
		{Action: "", Resource: "/", Outcome: "success", Principal: "d", Kind: "human"},
		{Action: "x", Resource: "/", Outcome: "nonsense", Principal: "d", Kind: "human"},
		{Action: "x", Resource: "/", Outcome: "success", Principal: "d",
			Kind: "service", Verified: false},
		{Action: "x", Resource: "/", Outcome: "success", Principal: "d",
			Kind: "human", Detail: map[string]string{"password": "hunter2"}},
	} {
		if _, err := Submit(sock, bad); err == nil {
			t.Errorf("the writer accepted %#v", bad)
		}
	}
	events, _ := audit.Read(path)
	if len(events) != 0 {
		t.Errorf("%d refused records were written anyway", len(events))
	}
}

// A client that connects and sends nothing would otherwise occupy the writer
// indefinitely, and a log that stops recording is the precondition for
// everything else.
func TestASilentClientDoesNotHoldTheWriter(t *testing.T) {
	sock, _, _ := writer(t)

	silent, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	// Another client must still be served while the first says nothing.
	done := make(chan error, 1)
	go func() {
		_, err := Submit(sock, Submission{
			Action: "publish", Resource: "/", Outcome: "success",
			Principal: "dana", Kind: "human", Verified: true,
		})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a second client was refused: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("one silent client blocked the writer")
	}
}

func TestAnOversizedSubmissionIsRefused(t *testing.T) {
	sock, _, path := writer(t)

	huge := map[string]string{}
	for i := range 5000 {
		huge[string(rune('a'+i%26))+string(rune(i))] = strings.Repeat("x", 100)
	}
	if _, err := Submit(sock, Submission{
		Action: "publish", Resource: "/", Outcome: "success",
		Principal: "dana", Kind: "human", Verified: true, Detail: huge,
	}); err == nil {
		t.Error("an oversized record was accepted")
	}
	events, _ := audit.Read(path)
	if len(events) != 0 {
		t.Error("an oversized record was written")
	}
}

// The socket path is configuration. Deleting whatever happens to be there is
// how a writer overwrites something it should not.
func TestListenRefusesToRemoveSomethingThatIsNotASocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(path, []byte("important"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path); err == nil {
		t.Fatal("Listen removed a regular file")
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("the file was deleted anyway")
	}
}

// A stale socket from an unclean shutdown must not stop the writer starting,
// because a writer that will not start is a writer somebody disables.
func TestAStaleSocketIsReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.sock")

	// A crash leaves the socket file behind: SetUnlinkOnClose(false) is what
	// makes closing the listener not tidy up, which is what a killed process
	// does.
	first, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	if ul, ok := first.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	_ = first.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the fixture did not leave a stale socket: %v", err)
	}

	second, err := Listen(path)
	if err != nil {
		t.Fatalf("a stale socket stopped the writer starting: %v", err)
	}
	_ = second.Close()
}

// The socket's mode is the access control, and it must not be world-writable —
// otherwise any account on the machine can submit audit records.
func TestTheSocketIsNotWorldWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o002 != 0 {
		t.Errorf("the socket is mode %04o, so any account can submit records",
			info.Mode().Perm())
	}
}

// Configuration that is not in effect is worse than none, because somebody
// believes it.
func TestOwnershipIsCheckedRatherThanAssumed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// The file is owned by whoever runs the test, so claiming that account is
	// the CMS must report the separation as absent.
	ok, why := CheckOwnership(path, os.Getuid())
	if ok {
		t.Error("separation was reported in force while the CMS account owns " +
			"the log")
	}
	if !strings.Contains(why, "formality") {
		t.Errorf("the explanation does not say why it matters: %s", why)
	}

	// A different uid means the CMS cannot open it.
	ok, why = CheckOwnership(path, os.Getuid()+1)
	if !ok {
		t.Errorf("separation was reported absent when it holds: %s", why)
	}
}
