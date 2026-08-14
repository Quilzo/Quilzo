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
