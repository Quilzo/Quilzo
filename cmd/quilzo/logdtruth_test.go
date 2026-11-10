// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
)

// With no log writer running and the log another account's, `logd status`
// says that nothing can write the log, not that this account writes it.
//
// It said "this process writes the audit log itself, so anything that can
// execute code as this account can rewrite the record", which is the
// opposite of the truth there: the separation is in force, this account
// cannot open the log at all, and what it does goes unrecorded, an agent's
// actions refused, until the writer runs. That is the moment somebody is
// diagnosing the audit log, under the reference compose with logd stopped.
func TestLogdStatusSaysNothingWritesALogThatIsAnotherAccounts(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root on Linux, to give the log to another account and ask as the CMS")
	}
	t.Setenv("HOME", t.TempDir())
	base := sharedTempDir(t)
	bin := filepath.Join(base, "quilzo")
	copyExecutable(t, os.Args[0], bin)
	if w == nil {
		w = out.New(false)
	}
	root := filepath.Join(base, "store")
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "audit")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := setAuditDir(root, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "audit.jsonl"), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	chownTree(t, dir, writerAccount, cmsAccount)
	chownTree(t, root, cmsAccount, cmsAccount)
	chownTree(t, home, cmsAccount, cmsAccount)

	status := exec.Command(bin, "quilzo-main", "--root", root, "logd", "status")
	status.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: cmsAccount, Gid: cmsAccount}}
	status.Env = append(os.Environ(), "HOME="+home, "NO_COLOR=1")
	got, err := status.CombinedOutput()
	if err != nil {
		t.Fatalf("logd status, as the CMS: %v\n%s", err, got)
	}
	text := string(got)
	if strings.Contains(text, "writes the audit log itself") {
		t.Errorf("with the log another account's and no writer, status says this account writes it:\n%s", text)
	}
	for _, want := range []string{"another account's", "until the writer runs"} {
		if !strings.Contains(text, want) {
			t.Errorf("status does not say %q:\n%s", want, text)
		}
	}
}

// `quilzo logd` asked for help after its flags prints the help, as root or
// not, and starts nothing; a word it does not take is refused rather than
// ignored.
//
// Main answers `logd help` itself, but not `logd --log-dir /srv/audit
// help`, the service's own command with help put after it: the word was
// left over and ignored, so as root the writer refused to run, and as any
// other account it started, the help never printed. So did `quilzo logd
// anything`.
func TestLogdHelpAfterItsFlagsPrintsTheHelp(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := filepath.Join(t.TempDir(), "st")
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "audit")

	saved := os.Stdout
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = wr
	herr := cmdLogd(root, []string{"--log-dir", dir, "help"})
	os.Stdout = saved
	_ = wr.Close()
	said, _ := io.ReadAll(r)
	if herr != nil {
		t.Fatalf("logd --log-dir DIR help: %v", herr)
	}
	if !strings.Contains(string(said), "quilzo logd") {
		t.Errorf("logd --log-dir DIR help printed %q", said)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("asking for help made the log directory: %v", err)
	}

	if err := cmdLogd(root, []string{"--log-dir", dir, "frobnicate"}); err == nil ||
		!strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("logd with a word it does not take: %v", err)
	}
}

// Moving the audit log says that what was signed before the move is checked
// against the head.pub.json it leaves behind.
//
// The writer in the new directory makes a key of its own, so a head, a
// receipt or a statement signed before the move no longer checks against
// the head.pub.json beside the log, and nothing said where the one that
// checks it is.
func TestMovingTheAuditLogSaysWhichKeysCheckWhatWasSignedBefore(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	saved := w
	t.Cleanup(func() { w = saved })
	root := filepath.Join(t.TempDir(), "st")
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if _, err := localHeadSigner(root); err != nil {
		t.Fatal(err)
	}
	old := headKeysPath(root)
	if !fileExists(old) {
		t.Fatalf("no head keys at %s to move away from", old)
	}
	logs := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(logs, 0o750); err != nil {
		t.Fatal(err)
	}
	var said bytes.Buffer
	w = &out.Writer{Out: &said, Err: &bytes.Buffer{}}
	if err := cmdAuditDir(root, []string{logs}); err != nil {
		t.Fatal(err)
	}
	if auditDir(root) != logs {
		t.Fatalf("the log did not move: %s", auditDir(root))
	}
	if !strings.Contains(said.String(), old) || !strings.Contains(said.String(), "before") {
		t.Errorf("moving the log does not say what was signed before it checks against %s:\n%s", old, said.String())
	}
}

// A socket left behind by a writer that is no longer running is said to
// be one: status said "log writer at" it, and every record sent to it was
// refused.
func TestLogdStatusSaysASocketNothingAnswersIsNotAWriter(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	saved := w
	t.Cleanup(func() { w = saved })
	root := filepath.Join(t.TempDir(), "st")
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", logSocketPath(root))
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	t.Cleanup(func() { _ = os.Remove(logSocketPath(root)) })

	var said bytes.Buffer
	w = &out.Writer{Out: &said, Err: &bytes.Buffer{}}
	if err := cmdLogdStatus(root); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(said.String(), "nothing answers on it") {
		t.Errorf("status with a socket nothing answers on:\n%s", said.String())
	}
}

// The administrator who approves a move of the audit log is told the same:
// it is their approval that moves it.
func TestApprovingAMoveOfTheAuditLogSaysWhichKeysCheckWhatWasSignedBefore(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	saved := w
	t.Cleanup(func() { w = saved })
	root, boss, lee := twoAdmins(t)
	if _, err := localHeadSigner(root); err != nil {
		t.Fatal(err)
	}
	old := headKeysPath(root)
	logs := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(logs, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdAuditDir(root, []string{logs}); err != nil {
		t.Fatal(err)
	}
	var said bytes.Buffer
	w = &out.Writer{Out: &said, Err: &bytes.Buffer{}}
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", waiting(t, root).ID}); err != nil {
		t.Fatal(err)
	}
	if auditDir(root) != logs {
		t.Fatalf("approved, and the log did not move: %s", auditDir(root))
	}
	if !strings.Contains(said.String(), old) {
		t.Errorf("approving the move does not say what was signed before it checks against %s:\n%s", old, said.String())
	}
}
