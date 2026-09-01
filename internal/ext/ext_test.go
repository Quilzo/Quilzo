package ext

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// script writes a shell extension and returns a manifest for it.
//
// Every test that needs an extension to actually run goes through here, and
// what it writes is a POSIX shell script. On Windows there is no /bin/sh, so
// those tests cannot mean anything — they used to fail, all of them, which is a
// suite nobody can read. They skip instead, and the containment that is
// specific to that platform has its own tests in proc_windows_test.go.
func script(t *testing.T, body string, m Manifest) Manifest {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("this extension is a shell script and Windows has no /bin/sh; " +
			"see proc_windows_test.go for what is checked there")
	}
	path := filepath.Join(t.TempDir(), "ext.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	m.Command = []string{path}
	if m.Name == "" {
		m.Name = "test"
	}
	if len(m.Hooks) == 0 {
		m.Hooks = []Hook{OnValidate}
	}
	return m
}

func run(t *testing.T, m Manifest, req Request, lim Limits) Result {
	t.Helper()
	r := &Runner{Limits: lim}
	return r.Run(context.Background(), m, req)
}

// -- it works -----------------------------------------------------------------

func TestAnExtensionCanRefuseAPage(t *testing.T) {
	m := script(t, `echo '{"refuse":true,"reason":"no swearing"}'`, Manifest{})
	res := run(t, m, Request{Hook: OnValidate, Page: "index"}, Limits{})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if !res.Response.Refuse || res.Response.Reason != "no swearing" {
		t.Errorf("got %+v", res.Response)
	}
}

// Silence is agreement, so the simplest useful extension is a script rather
// than a program.
func TestAnExtensionThatSaysNothingAgrees(t *testing.T) {
	res := run(t, script(t, `exit 0`, Manifest{}), Request{Hook: OnValidate},
		Limits{})
	if res.Err != nil || res.Response.Refuse {
		t.Errorf("silence was not agreement: %+v", res)
	}
}

func TestAnExtensionSeesTheFieldsItDeclared(t *testing.T) {
	m := script(t, `cat > /dev/null; echo '{}'`, Manifest{Fields: []string{"title"}})
	// Read what it was actually sent by echoing stdin back instead.
	m = script(t, `printf '{"note":"'; head -c 400 | tr -d '\n' | sed 's/"/@/g'; printf '"}'`,
		Manifest{Fields: []string{"title"}})
	res := run(t, m, Request{
		Hook: OnValidate, Page: "index",
		Fields: map[string]any{
			"title":  "Hello",
			"secret": "must not be sent",
			"body":   "also not sent",
		},
	}, Limits{})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	got := res.Response.Note
	if !strings.Contains(got, "Hello") {
		t.Errorf("the declared field was not sent: %s", got)
	}
	for _, leak := range []string{"must not be sent", "also not sent", "secret", "body"} {
		if strings.Contains(got, leak) {
			t.Errorf("an undeclared field reached the extension: %q in %s",
				leak, got)
		}
	}
}

// A field returned that was not declared is dropped and named. Refusing the
// whole publish over a version skew would be worse; hiding it would be worse
// still.
func TestAnUndeclaredFieldInTheResponseIsDroppedAndReported(t *testing.T) {
	m := script(t, `echo '{"fields":{"title":"ok","other":"sneaky"}}'`,
		Manifest{Fields: []string{"title"}})
	res := run(t, m, Request{Hook: OnTransform}, Limits{})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if _, ok := res.Response.Fields["other"]; ok {
		t.Error("an undeclared field was accepted from the extension")
	}
	if len(res.Dropped) != 1 || res.Dropped[0] != "other" {
		t.Errorf("the drop was not reported: %v", res.Dropped)
	}
}

// -- it cannot take the site down ---------------------------------------------

// A hanging extension must not hang a publish.
func TestAHangingExtensionIsKilled(t *testing.T) {
	m := script(t, `sleep 30`, Manifest{})
	began := time.Now()
	res := run(t, m, Request{Hook: OnValidate}, Limits{Timeout: 300 * time.Millisecond})
	if res.Err == nil {
		t.Fatal("a sleeping extension was allowed to finish")
	}
	if elapsed := time.Since(began); elapsed > 5*time.Second {
		t.Errorf("it took %s to give up", elapsed)
	}
	if !strings.Contains(res.Err.Error(), "did not answer") {
		t.Errorf("wrong error: %v", res.Err)
	}
}

// A talkative one must not fill memory.
func TestAnExtensionCannotReturnUnboundedOutput(t *testing.T) {
	m := script(t, `yes AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA | head -c 10000000`, Manifest{})
	res := run(t, m, Request{Hook: OnValidate},
		Limits{MaxOutput: 4096, Timeout: 10 * time.Second})
	// Either it errors or it returns nothing usable; what must not happen is
	// ten megabytes in memory or a hang.
	if res.Took > 10*time.Second {
		t.Error("it was not stopped")
	}
}

// A crashing one is a failure, not a crash.
func TestACrashingExtensionDoesNotTakeTheHostWithIt(t *testing.T) {
	res := run(t, script(t, `echo boom >&2; exit 3`, Manifest{}),
		Request{Hook: OnValidate}, Limits{})
	if res.Err == nil {
		t.Fatal("a failing extension reported success")
	}
	if !strings.Contains(res.Err.Error(), "boom") {
		t.Errorf("the error does not carry what the extension said: %v", res.Err)
	}
}

func TestGarbageOutputIsAnErrorRatherThanAPanic(t *testing.T) {
	res := run(t, script(t, `echo 'not json at all'`, Manifest{}),
		Request{Hook: OnValidate}, Limits{})
	if res.Err == nil {
		t.Error("unparseable output was accepted")
	}
}

// -- the environment ----------------------------------------------------------

// An empty environment, not a filtered one. The process this inherits from
// holds tokens and store paths, and an allow-list is a list somebody forgets
// to update.
func TestAnExtensionGetsNoEnvironment(t *testing.T) {
	os.Setenv("QUILZO_TOKEN", "qz_thismustnotleak")
	defer os.Unsetenv("QUILZO_TOKEN")

	m := script(t, `printf '{"note":"%s"}' "${QUILZO_TOKEN:-empty}"`, Manifest{})
	res := run(t, m, Request{Hook: OnValidate}, Limits{})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if strings.Contains(res.Response.Note, "thismustnotleak") {
		t.Fatal("the extension read a token out of the environment")
	}
	if res.Response.Note != "empty" {
		t.Errorf("the environment was not empty: %q", res.Response.Note)
	}
}

// -- pinning ------------------------------------------------------------------

// The binary that runs is the binary that was reviewed.
func TestAChangedBinaryIsRefusedWhenPinned(t *testing.T) {
	m := script(t, `echo '{}'`, Manifest{})
	sum, err := Pin(m.Command[0])
	if err != nil {
		t.Fatal(err)
	}
	m.SHA256 = sum

	lim := Limits{RequirePin: true}
	if res := run(t, m, Request{Hook: OnValidate}, lim); res.Err != nil {
		t.Fatalf("the pinned binary was refused: %v", res.Err)
	}

	// Somebody replaces it on disk.
	if err := os.WriteFile(m.Command[0],
		[]byte("#!/bin/sh\necho '{\"refuse\":true}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := run(t, m, Request{Hook: OnValidate}, lim)
	if res.Err == nil {
		t.Fatal("a swapped binary ran")
	}
	if !strings.Contains(res.Err.Error(), "not the one that was reviewed") {
		t.Errorf("unclear error: %v", res.Err)
	}
}

func TestAnUnpinnedExtensionIsRefusedWhenPinningIsRequired(t *testing.T) {
	m := script(t, `echo '{}'`, Manifest{})
	res := run(t, m, Request{Hook: OnValidate}, Limits{RequirePin: true})
	if res.Err == nil {
		t.Error("an extension with no recorded hash ran under require_pinned")
	}
}

// -- manifests ----------------------------------------------------------------

func TestAManifestMustBeUsable(t *testing.T) {
	for _, tc := range []struct {
		why string
		m   Manifest
	}{
		{"no name", Manifest{Command: []string{"/bin/true"}, Hooks: []Hook{OnValidate}}},
		{"no command", Manifest{Name: "x", Hooks: []Hook{OnValidate}}},
		{"no hooks", Manifest{Name: "x", Command: []string{"/bin/true"}}},
		{"unknown hook", Manifest{Name: "x", Command: []string{"/bin/true"},
			Hooks: []Hook{"whenever"}}},
		{"relative command", Manifest{Name: "x", Command: []string{"./ext.sh"},
			Hooks: []Hook{OnValidate}}},
	} {
		if err := tc.m.Validate(); err == nil {
			t.Errorf("a manifest with %s was accepted", tc.why)
		}
	}
}

// A relative command resolves against whatever directory the operator was in,
// which is how running a publish inside a checkout runs a binary from it.
func TestARelativeCommandIsRefused(t *testing.T) {
	err := Manifest{Name: "x", Command: []string{"ext.sh"},
		Hooks: []Hook{OnValidate}}.Validate()
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("got %v", err)
	}
}

// An extension declaring no fields sees no fields, rather than all of them.
// The other default would mean an extension sees the unpublished legal review
// because somebody added a field last Tuesday.
func TestDeclaringNoFieldsMeansNoneRatherThanAll(t *testing.T) {
	m := script(t, `printf '{"note":"'; head -c 200 | tr -d '\n' | sed 's/"/@/g'; printf '"}'`,
		Manifest{})
	res := run(t, m, Request{
		Hook: OnValidate, Page: "index",
		Fields: map[string]any{"title": "Secret Title"},
	}, Limits{})
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if strings.Contains(res.Response.Note, "Secret Title") {
		t.Error("an extension declaring no fields was sent one")
	}
}

var _ = json.Marshal

// The grandchild case, stated on its own because it is the one that was
// broken and the fix is not obvious from the symptom.
//
// CommandContext signals the direct child, and Wait then blocks until the
// output pipes close — which anything the extension spawned holds open. A
// script running `sleep 30 &` therefore held the host for thirty seconds
// despite a much shorter timeout.
func TestAnExtensionCannotHoldTheHostWithAGrandchild(t *testing.T) {
	m := script(t, "sleep 30 &\nsleep 30\n", Manifest{})
	began := time.Now()
	res := run(t, m, Request{Hook: OnValidate},
		Limits{Timeout: 200 * time.Millisecond})
	elapsed := time.Since(began)

	if res.Err == nil {
		t.Fatal("it was allowed to finish")
	}
	if elapsed > 5*time.Second {
		t.Errorf("the host waited %s for a 200ms timeout; a surviving "+
			"grandchild is holding the output pipe open", elapsed)
	}
}

// An absolute path is whatever the platform means by one.
//
// The rule was a leading slash, which refused every Windows path: C:\Tools\
// lint.exe does not start with one, so on that platform every manifest was
// rejected at validation and the extension feature did not work at all. Found
// while testing the Windows containment — the job object passed and no ordinary
// extension could run to be contained.
func TestAnAbsolutePathIsPlatformShaped(t *testing.T) {
	abs := "/usr/local/bin/lint"
	rel := "lint"
	if runtime.GOOS == "windows" {
		abs = `C:\Tools\lint.exe`
		rel = `Tools\lint.exe`
	}

	ok := Manifest{Name: "lint", Command: []string{abs}, Hooks: []Hook{OnValidate}}
	if err := ok.Validate(); err != nil {
		t.Errorf("an absolute path for this platform was refused: %v", err)
	}

	bad := Manifest{Name: "lint", Command: []string{rel}, Hooks: []Hook{OnValidate}}
	if err := bad.Validate(); err == nil {
		t.Error("a relative command was accepted; it resolves against " +
			"whatever directory the operator was in")
	}
}
