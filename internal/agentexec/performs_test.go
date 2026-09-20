// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentexec

import (
	"context"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
)

// Performs must name exactly what the switches carry out.
//
// A list that drifts from the code it describes is worse than no list: it is
// the thing Validate will trust. So it is read back out of the source.
func TestPerformsMatchesTheDispatchSwitches(t *testing.T) {
	arm := regexp.MustCompile(`(?m)^\s*case "([a-z_]+)":`)

	inSource := map[string]bool{}
	for _, f := range []string{"exec.go", "write.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range arm.FindAllStringSubmatch(string(src), -1) {
			inSource[m[1]] = true
		}
	}
	if len(inSource) == 0 {
		t.Fatal("found no dispatch arms; the parse is wrong and a test that " +
			"sees nothing passes")
	}

	listed := map[string]bool{}
	for _, op := range Performs() {
		listed[op] = true
	}
	for op := range Refuses() {
		listed[op] = true
	}

	var missing, extra []string
	for op := range inSource {
		if !listed[op] {
			missing = append(missing, op)
		}
	}
	for _, op := range Performs() {
		if !inSource[op] {
			extra = append(extra, op)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("these operations are dispatched and not in Performs or "+
			"Refuses:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(extra) > 0 {
		t.Errorf("Performs names these and nothing dispatches them:\n  %s",
			strings.Join(extra, "\n  "))
	}
}

// A refused operation is refused, not silently absent. The distinction is the
// point of having two lists.
//
// Written against this branch's fixtures rather than main's. The helpers the
// upstream version uses live in a file that does not exist here: this package
// was one reader when v0.2.1 was cut and was split into exec.go and
// retrieve.go afterwards. Carrying the split too would be backporting a
// refactor, which is not what a patch release is for.
func TestARefusedOperationSaysWhy(t *testing.T) {
	for op, why := range Refuses() {
		if strings.TrimSpace(why) == "" {
			t.Errorf("%s is refused with no reason", op)
		}
	}
	// And the fixture works, so a test that found nothing would not pass by
	// checking nothing.
	st := testStore(t)
	s := liveSession(t)
	out, err := Reader{Store: st}.Perform(s)(context.Background(),
		agent.Action{Op: "read_page", Input: map[string]any{"page": "index"}})
	if err != nil || out == "" {
		t.Fatalf("the fixture is wrong: %v", err)
	}
}
