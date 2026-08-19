//go:build linux

package sandbox

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The decisive test: a sandboxed process must not be able to read the secret.
//
// Asserted by actually running one, because every part of this can fail
// silently. A wrong struct layout, an unclamped access bit, a missing
// no_new_privs — each produces a call that returns success and restricts
// nothing, and no unit test of the constants would notice.
//
// The child is this test binary re-executed, which is the standard way to test
// something that only takes effect across execve.
func TestASandboxedProcessCannotReadOutsideItsRules(t *testing.T) {
	requireSandbox(t)

	dir := t.TempDir()
	allowed := filepath.Join(dir, "allowed.txt")
	if err := os.WriteFile(allowed, []byte("readable"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The secret lives somewhere the rules do not name. A separate directory,
	// because Landlock grants a hierarchy and a sibling file in the same
	// directory would be granted with it.
	secretDir := t.TempDir()
	secret := filepath.Join(secretDir, "tokens.json")
	if err := os.WriteFile(secret, []byte("qz_supersecret"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(target string) (string, error) {
		cmd := exec.Command(os.Args[0], "-test.run=TestSandboxHelper")
		cmd.Env = append(os.Environ(),
			"QUILZO_SANDBOX_HELPER=1",
			"QUILZO_SANDBOX_ALLOW="+dir,
			"QUILZO_SANDBOX_TARGET="+target,
		)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// Inside the allowed hierarchy: readable.
	out, err := run(allowed)
	if err != nil {
		t.Fatalf("the sandboxed child could not read an allowed file: %v\n%s", err, out)
	}
	if !strings.Contains(out, "read-ok") {
		t.Fatalf("the allowed read did not succeed: %s", out)
	}

	// Outside it: denied. This is the whole control.
	out, err = run(secret)
	if err == nil && strings.Contains(out, "read-ok") {
		t.Fatalf("a sandboxed process read a file outside its rules; the "+
			"sandbox reported success and restricted nothing\n%s", out)
	}
	if strings.Contains(out, "qz_supersecret") {
		t.Fatal("the secret's contents reached the sandboxed process")
	}
}

// requireSandbox skips a test that cannot run here, and says which reason.
//
// Coverage is the interesting one. The child writes its coverage profile into
// the temporary directory, and the sandbox — correctly — denies it, so the
// child dies after the read it was asked to make. That is the control working,
// and it cannot be fixed by widening the rules: the test's own secret lives
// under the same temporary root, so allowing it would allow the secret and the
// test would prove nothing.
//
// So these are skipped under coverage rather than weakened. CI runs
// `go test -count=1 ./...` without it, which is where they matter.
func requireSandbox(t *testing.T) {
	t.Helper()
	if !Supported() {
		t.Skip("this kernel has no Landlock")
	}
	if testing.CoverMode() != "" {
		t.Skip("the sandbox denies the child its coverage file; run without -cover")
	}
}

// TestSandboxHelper is the child. It is a test only so that the test binary can
// re-execute itself; it does nothing unless the environment asks.
func TestSandboxHelper(t *testing.T) {
	if os.Getenv("QUILZO_SANDBOX_HELPER") != "1" {
		t.Skip("not the helper")
	}
	st, err := Restrict(Rules{Read: []string{os.Getenv("QUILZO_SANDBOX_ALLOW")}})
	if err != nil {
		t.Fatalf("restrict failed: %v", err)
	}
	if !st.Enforced {
		t.Fatalf("nothing was enforced: %s", st.Why)
	}
	body, err := os.ReadFile(os.Getenv("QUILZO_SANDBOX_TARGET"))
	if err != nil {
		t.Fatalf("denied: %v", err)
	}
	// Printed rather than logged: t.Log is suppressed in the child unless -v
	// is passed to it, and the parent asserts on this string.
	fmt.Printf("read-ok %s\n", body)
}

// Writing is separate from reading, so a read-only rule really is read-only.
func TestAReadRuleDoesNotGrantWriting(t *testing.T) {
	requireSandbox(t)
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestSandboxWriteHelper")
	cmd.Env = append(os.Environ(),
		"QUILZO_SANDBOX_HELPER=1", "QUILZO_SANDBOX_ALLOW="+dir)
	out, err := cmd.CombinedOutput()
	if err == nil && strings.Contains(string(out), "wrote") {
		t.Fatalf("a read-only rule allowed a write\n%s", out)
	}
}

func TestSandboxWriteHelper(t *testing.T) {
	if os.Getenv("QUILZO_SANDBOX_HELPER") != "1" {
		t.Skip("not the helper")
	}
	dir := os.Getenv("QUILZO_SANDBOX_ALLOW")
	if _, err := Restrict(Rules{Read: []string{dir}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte("x"), 0o600); err != nil {
		t.Skipf("denied, as intended: %v", err)
	}
	fmt.Println("wrote")
}

// The access mask is clamped to what the kernel knows.
//
// Requesting a bit an older kernel has not heard of fails the entire ruleset,
// which would mean this sandboxes nothing on exactly the systems where nobody
// is watching.
func TestTheAccessMaskIsClampedToTheKernelABI(t *testing.T) {
	for _, tc := range []struct {
		abi      int
		wantBit  uint64
		wantGone uint64
		size     uintptr
	}{
		{abi: 1, wantBit: accessReadFile, wantGone: accessRefer, size: 8},
		{abi: 2, wantBit: accessRefer, wantGone: accessTruncate, size: 8},
		{abi: 3, wantBit: accessTruncate, wantGone: accessIoctlDev, size: 8},
		{abi: 4, wantBit: accessTruncate, wantGone: accessIoctlDev, size: 16},
		{abi: 5, wantBit: accessIoctlDev, size: 16},
		{abi: 7, wantBit: accessIoctlDev, size: 24},
	} {
		mask, size := handledFor(tc.abi)
		if mask&tc.wantBit == 0 {
			t.Errorf("ABI %d does not handle %#x", tc.abi, tc.wantBit)
		}
		if tc.wantGone != 0 && mask&tc.wantGone != 0 {
			t.Errorf("ABI %d handles %#x, which it cannot know about",
				tc.abi, tc.wantGone)
		}
		if size != tc.size {
			t.Errorf("ABI %d uses an attr size of %d, want %d",
				tc.abi, size, tc.size)
		}
	}
}

// An unsupported kernel says so rather than reporting a sandbox.
func TestAnUnsupportedKernelIsReportedNotHidden(t *testing.T) {
	if Supported() {
		t.Skip("this kernel supports Landlock, so the fallback cannot be exercised here")
	}
	st, err := Restrict(Rules{Read: []string{"/tmp"}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Enforced {
		t.Error("an unsupported kernel reported an enforced sandbox")
	}
	if st.Why == "" {
		t.Error("nothing explains why there is no sandbox")
	}
}

// A sandboxed process cannot open a TCP connection.
//
// An extension is handed its input on stdin and answers on stdout. A socket it
// opens is either a fetch nobody asked for or a way out with the data, so the
// default is that it has none.
//
// Tested against a listener in this process rather than a public address:
// asserting on a remote host would make the test depend on the network being
// there, and a security test that passes because the internet was down is a
// test that will one day pass for the wrong reason.
func TestASandboxedProcessCannotOpenATCPConnection(t *testing.T) {
	requireSandbox(t)
	if ABI() < 4 {
		t.Skip("this kernel has no Landlock network rules (ABI 4 or later)")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// Unsandboxed first, so a failure to connect cannot be mistaken for the
	// sandbox working.
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("the listener is not reachable unsandboxed: %v", err)
	}
	c.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestSandboxDialHelper")
	cmd.Env = append(os.Environ(),
		"QUILZO_SANDBOX_HELPER=1",
		"QUILZO_SANDBOX_ALLOW="+t.TempDir(),
		"QUILZO_SANDBOX_DIAL="+ln.Addr().String(),
	)
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "dialled") {
		t.Fatalf("a sandboxed process opened a TCP connection\n%s", out)
	}
	// The denial has to be the reason. Accepting any failure would let a
	// helper that crashed early stand in for a sandbox that worked.
	if !strings.Contains(string(out), "dial-denied") {
		t.Fatalf("the helper did not reach the dial, so this proves nothing "+
			"about the sandbox: %v\n%s", err, out)
	}
}

func TestSandboxDialHelper(t *testing.T) {
	if os.Getenv("QUILZO_SANDBOX_HELPER") != "1" {
		t.Skip("not the helper")
	}
	allowNet := os.Getenv("QUILZO_SANDBOX_ALLOW_NET") == "1"
	st, err := Restrict(Rules{
		Read:         []string{os.Getenv("QUILZO_SANDBOX_ALLOW")},
		AllowNetwork: allowNet,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.NetworkDenied == allowNet {
		t.Fatalf("network restriction is %v with AllowNetwork=%v: %+v",
			st.NetworkDenied, allowNet, st)
	}
	c, err := net.DialTimeout("tcp", os.Getenv("QUILZO_SANDBOX_DIAL"), 2*time.Second)
	if err != nil {
		// A distinct marker, printed rather than logged. The parent must be
		// able to tell "the connection was refused by the sandbox" from "the
		// helper fell over before it got that far" — without this, a helper
		// that dies for any reason looks like a working sandbox, which is how
		// the first version of this test passed against a build with the
		// network restriction removed.
		fmt.Println("dial-denied")
		return
	}
	c.Close()
	fmt.Println("dialled")
}

// Asking for the network leaves it alone.
//
// Handling no network rights is how Landlock expresses "do not restrict this",
// and it is easy to confuse with declaring the rights and granting none — which
// denies everything. The two are opposite and this is the test that keeps them
// apart.
//
// In a subprocess, like every other test here, and the first version of it was
// not: calling Restrict in the test process sandboxes the test process, and it
// then failed cleaning up its own temporary directory. That is the hazard the
// package documentation warns about, demonstrated by walking into it — Restrict
// belongs on a thread that is about to be replaced by execve and nowhere else.
func TestAllowNetworkLeavesTCPAlone(t *testing.T) {
	requireSandbox(t)
	if ABI() < 4 {
		t.Skip("no network rules on this kernel")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	cmd := exec.Command(os.Args[0], "-test.run=TestSandboxDialHelper")
	cmd.Env = append(os.Environ(),
		"QUILZO_SANDBOX_HELPER=1",
		"QUILZO_SANDBOX_ALLOW="+t.TempDir(),
		"QUILZO_SANDBOX_DIAL="+ln.Addr().String(),
		"QUILZO_SANDBOX_ALLOW_NET=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "dialled") {
		t.Fatalf("AllowNetwork did not leave TCP usable: %v\n%s", err, out)
	}
}

// The network mask is clamped like the filesystem one.
func TestTheNetworkMaskIsClampedToTheKernelABI(t *testing.T) {
	if handledNetFor(3) != 0 {
		t.Error("ABI 3 was asked for network rights it cannot know about, " +
			"which would fail the whole ruleset and lose the filesystem " +
			"restriction with it")
	}
	if handledNetFor(4)&accessNetConnectTCP == 0 {
		t.Error("ABI 4 does not restrict outbound TCP")
	}
}
