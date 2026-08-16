package logd

import (
	"os/exec"
	"strings"
	"testing"
)

// The program has to compile for every platform a release carries.
//
// It did not. internal/logd used SO_PEERCRED with no build tag, so the whole
// binary failed to build for macOS — and nobody found out until a release was
// cross-compiled for the first time, because every check until then ran on
// Linux. A contributor on a Mac could not have built this at all.
//
// Cheap to check and impossible to notice otherwise, so it is checked. `go vet`
// with GOOS set type-checks the tree for that platform without producing a
// binary, which is fast enough to belong in the ordinary suite.
func TestTheTreeBuildsForEveryReleasedPlatform(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-platform type check is skipped under -short")
	}
	// Kept in step with PLATFORMS in the Makefile. A mismatch means a release
	// ships a binary nothing type-checked.
	for _, p := range []string{
		"linux/amd64", "linux/arm64", "darwin/arm64", "darwin/amd64",
	} {
		os, arch, _ := strings.Cut(p, "/")
		t.Run(p, func(t *testing.T) {
			cmd := exec.Command("go", "vet", "./...")
			cmd.Dir = "../.."
			cmd.Env = append(cmd.Environ(),
				"GOOS="+os, "GOARCH="+arch, "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("the tree does not build for %s:\n%s", p, out)
			}
		})
	}
}
