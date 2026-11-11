// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package out

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The property that matters: anything reading this programmatically gets clean,
// parseable output. Every test here is a way that fails in practice.

func TestJSONModeEmitsExactlyOneDocumentOnStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	w := &Writer{Mode: JSON, Out: &stdout, Err: &stderr}

	// Prose calls must vanish. A command that interleaves a friendly line with
	// its JSON produces a stream nothing can parse, and call sites are
	// deliberately free to call Human() unconditionally.
	w.Human("checking %d pages...\n", 3)
	w.Human("done\n")
	if !w.JSON(map[string]any{"pages": 3}) {
		t.Fatal("JSON() should report that it wrote")
	}

	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%q", err, stdout.String())
	}
	if doc["pages"].(float64) != 3 {
		t.Errorf("wrong document: %v", doc)
	}
}

// A list with nothing in it is [], and nothing is null.
//
// A nil slice is how Go spells an empty list, and encoding/json writes it
// as null, so thirteen listings answered `null` on a store with nothing in
// them and a script iterating the answer failed where it had no work to do.
// An untyped nil is left alone: it is a command saying there is no such
// thing, as `booking setup` does for a site that takes no bookings. So is a
// []byte, which JSON writes as a string rather than a list.
func TestJSONGivesAnEmptyListAsAList(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string
	}{
		{[]string(nil), "[]"},
		{[]map[string]any(nil), "[]"},
		{[]string{}, "[]"},
		{[]byte(nil), "null"},
		{nil, "null"},
		{(*struct{})(nil), "null"},
	} {
		var stdout bytes.Buffer
		w := &Writer{Mode: JSON, Out: &stdout, Err: &bytes.Buffer{}}
		w.JSON(c.v)
		got := strings.Join(strings.Fields(stdout.String()), "")
		if got != c.want {
			t.Errorf("%#v was written as %s, not %s", c.v, got, c.want)
		}
	}
}

// The list inside a document is a list too.
//
// Most listings answer a document, {"boards": [...]}, rather than the bare
// list, and the list inside it went on being null on an empty store once the
// bare ones were []: `board list`, `booking list`, `lock list`, `menu list`,
// `spend list`, `trust list` and more, some built as a map and some as a
// struct, so a script reading doc.boards still failed where it had no work
// to do. A map is Go's empty collection too: `type list` said "broken": null
// for no broken types. A nil pointer is still null, being how a status says
// there is none, and so is a value that writes itself, as json.RawMessage
// does.
func TestJSONGivesAnEmptyListInADocumentAsAList(t *testing.T) {
	type board struct {
		Name  string   `json:"name"`
		Posts []string `json:"posts"`
	}
	type set struct {
		Boards  []board           `json:"boards"`
		Broken  map[string]string `json:"broken"`
		Owner   *board            `json:"owner"`
		Sig     []byte            `json:"sig"`
		private []string
	}
	type node struct {
		Kids []string `json:"kids"`
		Next *node    `json:"next"`
	}
	doc := map[string]any{"boards": []string(nil), "total": 0}
	loop := &node{}
	loop.Next = loop
	for _, c := range []struct {
		v    any
		want string
	}{
		{doc, `{"boards":[],"total":0}`},
		{map[string]any{"a": map[string]any{"b": []int(nil)}}, `{"a":{"b":[]}}`},
		{[]map[string]any{{"x": []string(nil)}}, `[{"x":[]}]`},
		{[]any{map[string][]string{"k": nil}}, `[{"k":[]}]`},
		{map[string]any{"none": nil, "since": (*int)(nil)}, `{"none":null,"since":null}`},
		{map[string]any{"raw": json.RawMessage(nil)}, `{"raw":null}`},
		{&set{}, `{"boards":[],"broken":{},"owner":null,"sig":null}`},
		{set{Boards: []board{{Name: "a"}}}, `{"boards":[{"name":"a","posts":[]}],"broken":{},"owner":null,"sig":null}`},
		{map[string]any{"types": map[string]string(nil)}, `{"types":{}}`},
		{&node{Next: &node{}}, `{"kids":[],"next":{"kids":[],"next":null}}`},
	} {
		var stdout bytes.Buffer
		w := &Writer{Mode: JSON, Out: &stdout, Err: &bytes.Buffer{}}
		w.JSON(c.v)
		got := strings.Join(strings.Fields(stdout.String()), "")
		if got != c.want {
			t.Errorf("%#v was written as %s, not %s", c.v, got, c.want)
		}
	}
	// The command's own document is not changed under it: it may go on to
	// use it.
	if doc["boards"].([]string) != nil {
		t.Error("writing the document changed the command's own map")
	}
	// One that points back at itself is refused by the encoder, as it was,
	// rather than followed for ever. Through a map or a slice as well as a
	// pointer: only pointers were watched for, so a map holding itself was
	// followed until the stack ran out, which ends the process rather than
	// the command, where the encoder had answered "encountered a cycle".
	selfMap := map[string]any{}
	selfMap["self"] = selfMap
	selfList := []any{nil}
	selfList[0] = selfList
	for name, v := range map[string]any{"a pointer": loop, "a map": selfMap, "a slice": selfList} {
		var stderr bytes.Buffer
		w := &Writer{Mode: JSON, Out: &bytes.Buffer{}, Err: &stderr}
		w.JSON(v)
		if !strings.Contains(stderr.String(), "cannot encode") {
			t.Errorf("a cycle through %s was not left to the encoder: %q", name, stderr.String())
		}
	}
}

// A document that could not be written is remembered, so the process can
// fail with it.
//
// JSON said "cannot encode output" on stderr and the command went on to
// return nil, so the process exited 0 with nothing on stdout: `config list`
// and `posture rules`, for a function in what they wrote, and every command
// for a stdout that will not take the document, as a full disk will not.
func TestJSONThatCannotBeWrittenIsAFailure(t *testing.T) {
	var stderr bytes.Buffer
	w := &Writer{Mode: JSON, Out: &bytes.Buffer{}, Err: &stderr}
	w.JSON(map[string]int{"n": 1})
	if w.Failed() {
		t.Fatal("a document that was written is reported as a failure")
	}
	w.JSON(map[string]any{"check": func() {}})
	if !w.Failed() {
		t.Fatal("a document the encoder refused is not reported as a failure")
	}
	// Said in the form the caller reads: an error document, in JSON mode.
	var e struct{ Error string }
	if err := json.Unmarshal(stderr.Bytes(), &e); err != nil || !strings.Contains(e.Error, "cannot encode output") {
		t.Errorf("the failure was said as %q, not as an error document", stderr.String())
	}
}

// What a field asks to be left out when it is zero is still left out.
//
// An empty list is not a zero one, so making the nil lists in an omitzero
// struct empty made it something to write: a kept output with no file
// changes gained "changes": {} where it had said nothing.
func TestJSONLeavesOutWhatOmitzeroLeavesOut(t *testing.T) {
	type changes struct {
		Added []string `json:"added,omitempty"`
	}
	type output struct {
		N       int     `json:"n"`
		Changes changes `json:"changes,omitzero"`
		Files   []string
	}
	var stdout bytes.Buffer
	w := &Writer{Mode: JSON, Out: &stdout, Err: &bytes.Buffer{}}
	w.JSON([]output{{N: 1}})
	got := strings.Join(strings.Fields(stdout.String()), "")
	if want := `[{"n":1,"Files":[]}]`; got != want {
		t.Errorf("written as %s, not %s", got, want)
	}
}

func TestJSONModeNeverColours(t *testing.T) {
	w := &Writer{Mode: JSON, Colour: true, Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	// Even if something sets Colour, JSON must not carry escape codes.
	if w.Bold() != "" || w.Red() != "" || w.Reset() != "" {
		t.Error("JSON output must never contain escape codes")
	}
}

func TestErrorsGoToStderrSoStdoutStaysParseable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	w := &Writer{Mode: JSON, Out: &stdout, Err: &stderr}

	w.Error(errors.New("no such page"))

	if stdout.Len() != 0 {
		t.Errorf("an error polluted stdout: %q", stdout.String())
	}
	var doc map[string]string
	if err := json.Unmarshal(stderr.Bytes(), &doc); err != nil {
		t.Fatalf("the error should be JSON too: %v", err)
	}
	if doc["error"] != "no such page" {
		t.Errorf("wrong error document: %v", doc)
	}
}

func TestHumanModeWithoutColourHasNoEscapeCodes(t *testing.T) {
	var buf bytes.Buffer
	w := &Writer{Mode: Human, Colour: false, Out: &buf, Err: &buf}

	w.Human("%sok%s pricing\n", w.Green(), w.Reset())

	if strings.Contains(buf.String(), "\033") {
		t.Errorf("escape codes leaked into non-terminal output: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "ok pricing") {
		t.Errorf("the text should survive: %q", buf.String())
	}
}

func TestColourIsOffForANonTerminal(t *testing.T) {
	// New() reads the real stdout, which under `go test` is not a character
	// device — the same situation as a pipe or an agent capturing output.
	w := New(false)
	if w.Colour {
		t.Error("colour should be off when stdout is not a terminal")
	}
}

func TestJSONModeIsAlwaysUncoloured(t *testing.T) {
	w := New(true)
	if w.Mode != JSON {
		t.Fatal("expected JSON mode")
	}
	if w.Colour {
		t.Error("JSON mode must not be coloured")
	}
}

func TestExitCodesAreDistinctAndNamed(t *testing.T) {
	seen := map[int]bool{}
	for _, c := range []int{OK, ExitFailure, ExitUsage, ExitBlocked, ExitNotFound, ExitUnavailable} {
		if seen[c] {
			t.Errorf("exit code %d is used twice; a caller cannot distinguish them", c)
		}
		seen[c] = true
		if Describe(c) == "unknown" {
			t.Errorf("exit code %d has no description", c)
		}
	}
	// A gate refusing is not the same as the command failing, and an agent
	// should be able to tell "you may not" from "it broke".
	if ExitBlocked == ExitFailure {
		t.Error("a refusal must be distinguishable from a failure")
	}
}
