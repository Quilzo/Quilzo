// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/render"
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

// Approved on People, a move of the audit log says the same: the screen's
// approval moves the log as surely as the command line's does.
//
// The command line said which head.pub.json checks what was signed before
// the move, and the People screen, where an administrator approves it as
// often, said only "move the audit log to DIR: approved by lee."
func TestApprovingAMoveOfTheAuditLogOnPeopleSaysWhichKeysCheckWhatWasSignedBefore(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, boss, _ := twoAdmins(t)
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
	id := waiting(t, root).ID

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
	lee, _, err := toks.IssueSession("passkey:lee", "lee", auth.RoleAdmin, "/", time.Hour,
		auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(s, pol, toks, render.Layouts{})
	if err != nil {
		t.Fatal(err)
	}
	srv.Dual = dualHooks(root)
	form := url.Values{"id": {id}, "do": {"approve"}}
	req := httptest.NewRequest(http.MethodPost, "/people/pending", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Authorization", "Bearer "+lee)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusSeeOther || err != nil {
		t.Fatalf("approving on People: %d %s", rec.Code, rec.Body.String())
	}
	if auditDir(root) != logs {
		t.Fatalf("approved on People, and the log did not move: %s (%s)", auditDir(root), loc.Query().Get("m"))
	}
	if said := loc.Query().Get("m"); !strings.Contains(said, old) {
		t.Errorf("approving the move on People does not say what was signed before it checks against %s: %q",
			old, said)
	}
}

// With no log writer running, `logd status` and the posture scan say that
// nothing can write the log wherever this account cannot write it: where
// the log is another account's, before the writer has made it in a
// directory that is the writer's, and where this account cannot so much as
// look at it.
//
// Status was asked whether the log was another account's, which a log
// nobody has made yet, or one this account cannot inspect, is not, and so
// said "this process writes the audit log itself" of a log it could not
// open. The posture scan said "The CMS writes its own audit log ... the
// CMS opens the audit log directly" wherever no socket was there, as under
// the reference compose with logd stopped, when the CMS could not open it
// at all.
func TestNothingWritingTheLogIsSaidWhereverThisAccountCannotWriteIt(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root on Linux, to give the log to another account and ask as the CMS")
	}
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	for _, c := range []struct {
		name string
		// lay gives the log's directory to the writer as this case has it.
		lay func(t *testing.T, dir string)
	}{
		{"the writer's", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "audit.jsonl"), nil, 0o640); err != nil {
				t.Fatal(err)
			}
			chownTree(t, dir, writerAccount, cmsAccount)
		}},
		{"not made yet", func(t *testing.T, dir string) {
			chownTree(t, dir, writerAccount, cmsAccount)
		}},
		{"out of reach", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "audit.jsonl"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			chownTree(t, dir, writerAccount, writerAccount)
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			base := sharedTempDir(t)
			bin := filepath.Join(base, "quilzo")
			copyExecutable(t, os.Args[0], bin)
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
			home := filepath.Join(base, "home")
			if err := os.Mkdir(home, 0o700); err != nil {
				t.Fatal(err)
			}
			c.lay(t, dir)
			chownTree(t, root, cmsAccount, cmsAccount)
			chownTree(t, home, cmsAccount, cmsAccount)

			asCMS := func(args ...string) string {
				t.Helper()
				cmd := exec.Command(bin, append([]string{"quilzo-main", "--root", root}, args...)...)
				cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: cmsAccount, Gid: cmsAccount}}
				cmd.Env = append(os.Environ(), "HOME="+home, "NO_COLOR=1")
				got, _ := cmd.CombinedOutput()
				return string(got)
			}
			status := asCMS("logd", "status")
			if strings.Contains(status, "writes the audit log itself") {
				t.Errorf("with a log this account cannot write and no writer, status says this account writes it:\n%s",
					status)
			}
			if !strings.Contains(status, "until the writer runs") {
				t.Errorf("status does not say nothing is recorded until the writer runs:\n%s", status)
			}
			scan := asCMS("posture")
			if strings.Contains(scan, "opens the audit log directly") || strings.Contains(scan, "writes its own audit log") {
				t.Errorf("with a log this account cannot write and no writer, the posture scan says the CMS "+
					"opens it directly:\n%s", scan)
			}
			if !strings.Contains(scan, "not answering") {
				t.Errorf("the posture scan does not say the writer is not answering:\n%s", scan)
			}
		})
	}
}

// A socket left behind that nothing answers on is reported by the posture
// scan as a writer that is not answering, the state its rule has for it,
// and not as a writer in force.
//
// The scan asked only whether the socket was there, so with the writer
// gone and its socket left behind it found the separation in force and
// said nothing, while every record sent to it was refused.
func TestPostureSaysASocketNothingAnswersIsAWriterNotAnswering(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
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

	if got := Observe(root, "", posture.ServerFacts{}).Extra["log_writer"]; got != "unreachable" {
		t.Errorf("with nothing answering on the writer's socket, the posture scan reads the writer as %q", got)
	}
}
