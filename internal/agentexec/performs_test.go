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

// Anything the dispatcher routes on, Done must not call finished.
//
// This has now been the same bug twice. Action.Done was written as
// `Op == "" && Tool == ""`, which was complete on the day it was written and
// stopped being complete the moment a field carrying work was added beside
// those two. An action naming only a Tool, and later an action naming only a
// Delegate, each looked to the run loop like the model saying it had no more
// to do — so the loop ended, took whatever the action's Say held as the
// answer, and reported a clean run.
//
// That failure is invisible from either side on its own. Dispatch is right:
// it has a branch and the branch works. Done is right about the fields it
// knows. The bug lives in the gap, and the only evidence is that one names a
// field the other does not.
//
// So the two are compared. A new branch in Dispatch that nobody adds to Done
// fails here, in the package that added the branch.
func TestEveryRoutedFieldIsOneDoneKnowsAbout(t *testing.T) {
	dispatch := functionBody(t, "write.go", "func Dispatch(")
	routed := fieldsTestedIn(dispatch)
	if len(routed) == 0 {
		t.Fatal("found no routing in Dispatch; the parse is wrong and a test " +
			"that sees nothing passes")
	}

	done := functionBody(t, "../agent/run.go", "func (a Action) Done()")
	if strings.TrimSpace(done) == "" {
		t.Fatal("found no body for Action.Done; the parse is wrong")
	}
	known := fieldsTestedIn(done)

	for _, f := range routed {
		if !contains(known, f) {
			t.Errorf(
				"Dispatch routes on Action.%s and Action.Done does not "+
					"mention it. An action carrying only that field has no "+
					"Op, so Done says the model has finished, the run loop "+
					"stops before the branch is ever reached, and the trace "+
					"reads as a clean run that did nothing. This is the "+
					"third field to which that applies", f)
		}
	}

	// And the run loop's own gate has to ask about them too, or the branch is
	// reached with nothing having authorised it.
	gate := functionBody(t, "../agent/run.go", "func (r Runner) Run(")
	asked := fieldsTestedIn(gate)
	for _, f := range routed {
		if !contains(asked, f) {
			t.Errorf(
				"Dispatch routes on Action.%s and the run loop never asks "+
					"the session about it. The executor would be reached "+
					"with nothing having authorised the action", f)
		}
	}
}

// fieldsTestedIn finds the Action fields a body compares against "".
var fieldTest = regexp.MustCompile(`\b(?:a|action)\.([A-Z][A-Za-z]*)\s*[!=]=\s*""`)

func fieldsTestedIn(body string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range fieldTest.FindAllStringSubmatch(body, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	// TrimSpace'd comparisons read as strings.TrimSpace(a.X) != "", which the
	// pattern above misses, so the same fields are found by the call instead.
	trimmed := regexp.MustCompile(
		`strings\.TrimSpace\((?:a|action)\.([A-Z][A-Za-z]*)\)`)
	for _, m := range trimmed.FindAllStringSubmatch(body, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

// functionBody returns the source of one function, by brace matching.
func functionBody(t *testing.T, path, signature string) string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, signature)
	if i < 0 {
		t.Fatalf("%s does not contain %q. This test walks the source, so a "+
			"rename here is a test that silently stops checking", path, signature)
	}
	open := strings.Index(s[i:], "{")
	if open < 0 {
		t.Fatalf("no body for %q in %s", signature, path)
	}
	depth, start := 0, i+open
	for j := start; j < len(s); j++ {
		switch s[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : j+1]
			}
		}
	}
	t.Fatalf("unbalanced braces after %q in %s", signature, path)
	return ""
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
