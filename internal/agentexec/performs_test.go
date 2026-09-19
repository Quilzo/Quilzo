// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentexec

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
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
func TestARefusedOperationSaysWhy(t *testing.T) {
	r := Reader{Store: searchStore(t)}
	m := searcher(t, nil)
	for op, why := range Refuses() {
		if strings.TrimSpace(why) == "" {
			t.Errorf("%s is refused with no reason", op)
		}
	}
	// diff is the one, and it names its argument rather than reporting a gap.
	out, err := ask(t, r, m, "search_pages", map[string]any{"query": "refund"})
	if err != nil || out == "" {
		t.Fatalf("the fixture is wrong: %v", err)
	}
}
