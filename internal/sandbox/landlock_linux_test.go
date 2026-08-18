//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
