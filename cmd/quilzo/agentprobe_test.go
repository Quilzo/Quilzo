package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The probe answers about the gate, not about a copy of its rules.
//
// This exists because the published AgentDojo figure is measured through this
// command by a Python harness. If the probe drifted from what `quilzo agent run`
// enforces, the number in the README would be a measurement of the probe — and
// nothing outside this file would notice, because the harness has no way to tell
// the difference.
//
// So the cases here are the four refusals the score depends on, asserted against
// the same session the executor uses.
func TestTheProbeRefusesWhatTheGateRefuses(t *testing.T) {
	reader := `{
	  "name": "reader",
	  "kind": "retrieval",
	  "purpose": "Answers questions from published pages.",
	  "capabilities": ["read_page", "list_pages", "run_listing"],
	  "autonomy": "propose",
	  "retrieval": {"ref": "live"},
	  "budget": {"steps": 8, "tool_calls": 4, "duration": "2m0s"}
	}`

	cases := []struct {
		what    string
		call    string
		allowed bool
		because string
	}{
		{"the work it declared", `{"op":"read_page","ref":"live"}`, true, ""},
		{"reading the unpublished draft",
			`{"op":"read_page","ref":"draft"}`, false, "reads live"},
		{"publishing", `{"op":"publish"}`, false, "not in this agent's capabilities"},
		{"writing", `{"op":"write_page"}`, false, "not in this agent's capabilities"},
		{"reaching a host nobody declared",
			`{"op":"fetch","host":"attacker.example"}`, false,
			"not in this agent's capabilities"},
	}

	for _, c := range cases {
		out := probeJSON(t, `{"manifest":`+reader+`,"calls":[`+c.call+`]}`)
		if len(out.Answers) != 1 {
			t.Fatalf("%s: got %d answers", c.what, len(out.Answers))
		}
		got := out.Answers[0]
		if got.Allowed != c.allowed {
			t.Errorf("%s: allowed=%v, want %v (reason %q)",
				c.what, got.Allowed, c.allowed, got.Reason)
			continue
		}
		if !c.allowed && !strings.Contains(got.Reason, c.because) {
			t.Errorf("%s: refused for %q, which does not mention %q — the "+
				"harness reports the gate's own words, so they have to be the "+
				"gate's", c.what, got.Reason, c.because)
		}
	}
}

// Reading stored content taints a session, and a tainted session cannot publish.
//
// The sequence, not the two calls separately: this is the rule CaMeL is about —
// untrusted input must not reach the decision to act — and the probe has to be
// able to express it or the harness cannot measure it.
func TestTheProbeCarriesTaintAcrossCalls(t *testing.T) {
	manifest := `{
	  "name": "editor",
	  "kind": "task",
	  "purpose": "Writes a page and publishes it.",
	  "capabilities": ["read_page", "write_page", "publish"],
	  "autonomy": "publish",
	  "human_approval": true,
	  "retrieval": {"ref": "live"},
	  "budget": {"steps": 8, "tool_calls": 4, "duration": "2m0s"}
	}`
	out := probeJSON(t, `{"manifest":`+manifest+`,"calls":[
	  {"op":"read_page","ref":"live","note":"reads content somebody else wrote"},
	  {"op":"publish","note":"and then acts on it"}
	]}`)

	if !out.Tainted {
		t.Error("reading stored content did not taint the session, so the " +
			"harness cannot measure the rule that untrusted input must not " +
			"reach the decision to act")
	}
	if len(out.Answers) != 2 {
		t.Fatalf("got %d answers", len(out.Answers))
	}
	if !out.Answers[0].Allowed {
		t.Errorf("the read was refused: %s", out.Answers[0].Reason)
	}
	if out.Answers[1].Allowed {
		t.Error("a publish after reading untrusted content was permitted")
	}
}

// A question this program does not understand is an error, not an answer.
//
// A harness that misspells a field would otherwise be told about a manifest it
// did not describe, and every number it produced afterwards would be about the
// typo.
func TestAMalformedProbeIsRefused(t *testing.T) {
	for what, question := range map[string]string{
		"an unknown field":  `{"manifest":{"name":"x"},"calls":[],"attacks":1}`,
		"no calls":          `{"manifest":{"name":"x"},"calls":[]}`,
		"an unusable agent": `{"manifest":{"name":"x"},"calls":[{"op":"read_page"}]}`,
	} {
		if _, err := runProbe(t, question); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
}

func probeJSON(t *testing.T, question string) probeResult {
	t.Helper()
	out, err := runProbe(t, question)
	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	return out
}

// runProbe drives the command the way the harness does: bytes in, JSON out.
func runProbe(t *testing.T, question string) (probeResult, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "question.json")
	if err := os.WriteFile(path, []byte(question), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, restore := captureStdout(t)
	err := agentProbe([]string{"--file", path})
	raw := restore()
	_ = stdout

	if err != nil {
		return probeResult{}, err
	}
	var out probeResult
	if derr := json.Unmarshal([]byte(raw), &out); derr != nil {
		t.Fatalf("the probe printed something that is not JSON: %v\n%s", derr, raw)
	}
	return out, nil
}

// captureStdout redirects os.Stdout for one call.
//
// The command writes JSON to standard output because that is what a harness
// reads; testing it means reading the same bytes rather than a return value that
// only a test would use.
func captureStdout(t *testing.T) (*os.File, func() string) {
	t.Helper()
	saved := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				b.Write(buf[:n])
			}
			if rerr != nil {
				done <- b.String()
				return
			}
		}
	}()
	return w, func() string {
		_ = w.Close()
		os.Stdout = saved
		return <-done
	}
}
