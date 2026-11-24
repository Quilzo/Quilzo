// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

// The log writer's tests that start Quilzo as other accounts: they need root
// on Linux, and the credentials and file ownership they use exist only on
// Unix, so they are kept here, where the other platforms do not compile them.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/logd"
	"github.com/quilzo/quilzo/internal/out"
)

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
	// this test's own account, for the setup below, and signs for it, for
	// the forged root further down.
	writerStore := filepath.Join(base, "writer-root")
	if err := os.Mkdir(writerStore, 0o755); err != nil {
		t.Fatal(err)
	}
	logdErr, err := os.Create(filepath.Join(base, "logd.stderr"))
	if err != nil {
		t.Fatal(err)
	}
	writer := exec.Command(bin, "quilzo-main", "--root", writerStore, "logd", "--log-dir", dir,
		"--allow-uid", "65532,0", "--sign-gid", "65532,0")
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

	// The site, as compose runs it: the admin's uid in a group of its own,
	// with the writer's beside it. Nothing it asks for is signed, and the
	// writer says why; it signed for the site as for the admin.
	site := exec.Command(bin, "quilzo-main", "--root", root, "auditlog", "head")
	site.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: cmsAccount, Gid: siteGroup,
		Groups: []uint32{cmsAccount}}}
	site.Env = append(os.Environ(), "HOME="+home, "QUILZO_TOKEN="+secret, "NO_COLOR=1")
	if got, err := site.CombinedOutput(); err == nil || !strings.Contains(string(got), "may not ask for a signature") {
		t.Errorf("a head asked for as the site: %v\n%s", err, got)
	}

	// The writer stopped: the key is still its own, and asking for a head
	// says to start it rather than suggesting this account take the key.
	// It said both: start the writer, and chown its key over.
	_ = writer.Process.Signal(syscall.SIGTERM)
	_ = writer.Wait()
	stdout, stderr, err := asCMS("auditlog", "head")
	if err == nil || !strings.Contains(stdout+stderr, "start quilzo logd") || strings.Contains(stdout+stderr, "chown") {
		t.Errorf("a head with the writer stopped: %v\n%s%s", err, stdout, stderr)
	}
	// And status says so, rather than that this account signs the heads.
	status = nil
	if err := json.Unmarshal([]byte(cms("--json", "logd", "status")), &status); err != nil {
		t.Fatal(err)
	}
	if status["heads_signed_by"] != "the log writer" || status["writer_signs"] != false ||
		!strings.Contains(statusText(status["writer_refuses"]), "start quilzo logd") {
		t.Errorf("logd status with the writer stopped, as the CMS: %v", status)
	}
	if got := cms("logd", "status"); !strings.Contains(got, "its heads are the writer's to sign") {
		t.Errorf("logd status with the writer stopped does not say the heads wait for it:\n%s", got)
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
