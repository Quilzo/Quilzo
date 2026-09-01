//go:build windows

package ext

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// A grandchild does not outlive the extension that started it.
//
// # What this is proving
//
// The sandbox argument is that an extension cannot outlive the host's decision
// to stop it. On Windows it could: the child got CREATE_NEW_PROCESS_GROUP and a
// Kill that reached only the child, so anything the extension spawned survived,
// still holding whatever it had opened, with nothing left to reap it.
//
// # The two ways a test like this proves nothing
//
// Both have happened in this tree, and the issue that asked for this named
// them.
//
// The helper dies before it spawns anything and the parent reads "nothing
// survived" as success. So the helper prints the grandchild's pid, this test
// refuses to continue until it has read one, and the assertion is about that
// pid rather than about the absence of something unnamed.
//
// The sabotage breaks the build, `go test` prints [build failed] with no FAIL:
// line, and a harness grepping for FAIL: calls it a pass. So this file has a
// companion in the commit message: removing the job object and re-running is
// what was done before believing it, and the run is recorded there.
func TestAGrandchildDiesWithItsExtension(t *testing.T) {
	helper := buildHelper(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, helper, "spawn")
	contained := confineProcess(cmd)
	cmd.WaitDelay = time.Second

	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- contained.run(cmd) }()

	// The grandchild's pid, straight from the process that started it. Nothing
	// below is meaningful without this line, so a helper that died early fails
	// here rather than passing quietly.
	pid := readPID(t, out)
	if !alive(pid) {
		t.Fatalf("the grandchild %d was not running before anything was "+
			"cancelled, so this test would prove nothing", pid)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the extension did not stop")
	}

	// The kernel terminates a job's processes when the last handle closes;
	// that is not instantaneous, so this waits rather than sampling once.
	deadline := time.Now().Add(10 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("the grandchild %d is still running after its extension "+
				"was stopped, so an extension can outlive the decision to "+
				"stop it", pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// And the ordinary case still works: a contained extension runs, produces its
// output and exits.
//
// Here because the containment creates the process suspended and resumes it by
// hand. A mistake in that sequence does not look like a security failure — it
// looks like every extension hanging for ever — and this is the test that says
// so plainly.
func TestAContainedExtensionStillRuns(t *testing.T) {
	helper := buildHelper(t)
	// CommandContext, not Command: confineProcess sets Cancel, and os/exec
	// refuses to start a command that has one and no context. That is true on
	// every platform and is how the host builds these — worth stating here,
	// because the error it produces ("command with a non-nil Cancel was not
	// created with CommandContext") reads like a bug in the containment.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, helper, "hello")
	contained := confineProcess(cmd)
	cmd.WaitDelay = time.Second

	// A buffer rather than a pipe. run() calls Wait, and Wait closes a pipe as
	// soon as the process exits — so a reader racing it against a program that
	// prints one line and stops reads EOF and nothing, which is what the first
	// version of this test did.
	var out strings.Builder
	cmd.Stdout = &out

	done := make(chan error, 1)
	go func() { done <- contained.run(cmd) }()
	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("a contained extension failed: %v", runErr)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a contained extension never exited; the resume after " +
			"assignment is what stops a suspended process staying suspended")
	}
	if strings.TrimSpace(out.String()) != "hello" {
		t.Errorf("the extension said %q", out.String())
	}
}

// buildHelper produces the helper executable this test drives.
//
// A real program rather than a script: this test is about what the operating
// system does with a process tree, and a shell in the middle is another process
// with its own opinions about signals.
//
// Two ways to get one, because of how this test actually gets run. On a Windows
// machine with Go installed it is compiled here. On a machine that
// cross-compiled this test binary and is running it under Windows without a
// toolchain — which is how it was first verified, from WSL — the helper is
// cross-compiled too and its path passed in QUILZO_TEST_HELPER.
//
// With neither, this skips and says so. A test that cannot build what it drives
// has not passed, and reporting it as a pass is the second of the two failure
// modes the issue asking for this warned about.
func buildHelper(t *testing.T) string {
	t.Helper()
	if given := os.Getenv("QUILZO_TEST_HELPER"); given != "" {
		if _, err := os.Stat(given); err != nil {
			t.Fatalf("QUILZO_TEST_HELPER names %s, which is not there: %v",
				given, err)
		}
		return given
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "helper.go")
	if err := os.WriteFile(src, []byte(helperSource), 0o600); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "helper.exe")
	build := exec.Command("go", "build", "-o", exe, src)
	out, err := build.CombinedOutput()
	if err == nil {
		return exe
	}
	if _, look := exec.LookPath("go"); look != nil {
		t.Skipf("no Go toolchain here and no QUILZO_TEST_HELPER: this test " +
			"needs the helper program, and a skip is the honest answer. " +
			"Build it with GOOS=windows go build -o helper.exe and point " +
			"QUILZO_TEST_HELPER at it.")
	}
	t.Fatalf("building the helper failed: %v\n%s", err, out)
	return ""
}

// helperSource is an extension that starts something that tries to outlive it.
//
// "spawn" starts a copy of itself in "linger" mode, prints that process's pid
// and then waits for ever. "linger" waits for ever and prints nothing: it is
// the process that must not survive, and it announces itself through its
// parent so that the pid this test asserts on came from the process that
// created it.
const helperSource = `package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func main() {
	mode := ""
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "spawn":
		child := exec.Command(os.Args[0], "linger")
		if err := child.Start(); err != nil {
			fmt.Println("ERR", err)
			os.Exit(1)
		}
		fmt.Println("GRANDCHILD", child.Process.Pid)
		os.Stdout.Sync()
		select {}
	case "linger":
		time.Sleep(10 * time.Minute)
	default:
		fmt.Println("hello")
	}
}
`

// readPID waits for the helper's announcement and returns the pid it names.
func readPID(t *testing.T, out interface{ Read([]byte) (int, error) }) int {
	t.Helper()
	line := readLine(t, out)
	fields := strings.Fields(line)
	if len(fields) != 2 || fields[0] != "GRANDCHILD" {
		t.Fatalf("the helper said %q instead of naming the process it started; "+
			"without a pid this test asserts on nothing", line)
	}
	pid, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("the helper named %q as a pid", fields[1])
	}
	return pid
}

func readLine(t *testing.T, out interface{ Read([]byte) (int, error) }) string {
	t.Helper()
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var b []byte
		buf := make([]byte, 1)
		for {
			n, err := out.Read(buf)
			if n > 0 {
				if buf[0] == '\n' {
					ch <- result{string(b), nil}
					return
				}
				b = append(b, buf[0])
			}
			if err != nil {
				ch <- result{string(b), err}
				return
			}
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil && r.line == "" {
			t.Fatalf("the helper printed nothing: %v", r.err)
		}
		return r.line
	case <-time.After(30 * time.Second):
		t.Fatal("the helper printed nothing within thirty seconds")
		return ""
	}
}

// alive reports whether a process id still names a running process.
//
// OpenProcess and then the exit code, because a handle can be opened to a
// process that has already exited: on Windows a pid stays openable while
// anything holds a handle to it, and STILL_ACTIVE is the difference between
// "there is a process" and "there is a corpse".
func alive(pid int) bool {
	const (
		processQueryLimitedInformation = 0x1000
		stillActive                    = 259
	)
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)

	var code uint32
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetExitCodeProcess")
	if ok, _, _ := proc.Call(uintptr(h), uintptr(unsafe.Pointer(&code))); ok == 0 {
		return false
	}
	return code == stillActive
}
