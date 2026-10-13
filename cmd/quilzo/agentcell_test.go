// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/cell"
)

// ledgerCell is a desktop as the run test wants it: an order form whose
// Pay button is consequential, so the run asks a person before paying.
type ledgerCell struct {
	mu      sync.Mutex
	pressed map[string]int
	typed   []string
}

func (l *ledgerCell) Read(context.Context) (cell.Tree, error) {
	return cell.Tree{
		Text: "Ledger — Order form\n[1] textbox \"Amount\"\n[2] button \"Pay now\"",
		Elements: map[string]cell.Element{
			"e1": {Ref: "e1", Role: "textbox", Name: "Amount"},
			"e2": {Ref: "e2", Role: "button", Name: "Pay now", Consequential: "pays the order"},
		},
	}, nil
}

func (l *ledgerCell) Press(_ context.Context, ref string) (string, error) {
	switch ref {
	case "e1":
		l.mu.Lock()
		l.pressed[ref]++
		l.mu.Unlock()
		return "pressed", nil
	case "e2":
		l.mu.Lock()
		l.pressed[ref]++
		l.mu.Unlock()
		return "paid the order", nil
	}
	return "", errNotOnOutline
}

type errText string

func (e errText) Error() string { return string(e) }

const errNotOnOutline = errText("that reference is not on the outline read last")

func (l *ledgerCell) Type(_ context.Context, text string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.typed = append(l.typed, text)
	return nil
}
func (l *ledgerCell) Key(context.Context, string) error { return nil }
func (l *ledgerCell) Screen(context.Context) ([]byte, error) {
	return []byte{0xFF, 0xD8, 0x00, 0x01}, nil
}
func (l *ledgerCell) Close() error { return nil }

func (l *ledgerCell) pays() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pressed["e2"]
}

// A run works a desktop cell as it works a browser: the outline read,
// the field pressed and filled, and the press that pays held for a
// person, going through once they agree.
func TestARunWorksACellAndAPersonApprovesThePayment(t *testing.T) {
	root := demoStore(t)
	declaredAutonomy(t, root)
	lc := &ledgerCell{pressed: map[string]int{}}
	old := cellTestConnect
	cellTestConnect = func(context.Context) (cell.Conn, error) { return lc, nil }
	t.Cleanup(func() { cellTestConnect = old })

	m := asker("clerk")
	m.Capabilities = []string{"desktop_read", "desktop_press", "desktop_type"}
	m.AskFirst = []string{"desktop_press"}
	m.Cell = &agent.Cell{}
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}

	// The model works what it is shown: read the screen, press the
	// amount field, type into it, press Pay — and finish once paid or
	// refused.
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		last := body
		if i := strings.LastIndex(body, "[desktop_"); i >= 0 {
			last = body[i:]
		}
		choice := `{"op":"desktop_read"}`
		switch {
		case strings.Contains(last, "paid the order") || strings.Contains(last, "declined") ||
			strings.Contains(last, "refused") || strings.Contains(last, "failed"):
			choice = `{"op":"done","say":"the order is dealt with"}`
		case strings.Contains(last, "typed into"):
			choice = `{"op":"desktop_press","input":{"ref":"e2"}}`
		case strings.Contains(last, "pressed textbox"):
			choice = `{"op":"desktop_type","input":{"text":"4210.00"}}`
		case strings.Contains(last, "Pay now"):
			choice = `{"op":"desktop_press","input":{"ref":"e1"}}`
		}
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": choice}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(model.Close)
	t.Setenv("QUILZO_MODEL_URL", model.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")

	answered := answerAllAsked(t, root, "clerk", true, "lee")
	id, out, err := runAgentKeptBy(context.Background(), root, "clerk", "pay the order", true, false, asAdmin("dana"))
	if aerr := <-answered; aerr != nil {
		t.Fatalf("answering: %v (%v)\n%s", aerr, err, describeRun(out.Trace))
	}
	if err != nil {
		t.Fatal(err)
	}
	if !out.Trace.Complete || lc.pays() != 1 {
		t.Fatalf("paid %d times; complete=%v; stopped=%q", lc.pays(), out.Trace.Complete, out.Trace.Stopped)
	}
	if len(lc.typed) != 1 || lc.typed[0] != "4210.00" {
		t.Fatalf("typed %v", lc.typed)
	}
	// Both presses were held and answered by a person: the field press
	// the declaration asks about, and the paying press the tree's own word
	// asks about. An approved hold leaves no refusal on the step; it
	// leaves the answer on the run.
	rec, err := loadAgentRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Answers) != 2 {
		t.Fatalf("two presses should have been held; %d answers: %+v", len(rec.Answers), rec.Answers)
	}
	for _, a := range rec.Answers {
		if !a.Approve || a.By != "lee" {
			t.Fatalf("an answer is not lee approving: %+v", a)
		}
	}
	frames, _ := loadRunFrames(root, id)
	sawAsking := false
	for _, f := range frames {
		sawAsking = sawAsking || strings.Contains(f.Asking, "Pay now")
	}
	if !sawAsking {
		t.Fatalf("no picture of what the person was asked about: %+v", frames)
	}
}

// A run that declines pays nothing, and the model is told who declined.
func TestARunThatIsDeclinedPaysNothing(t *testing.T) {
	root := demoStore(t)
	declaredAutonomy(t, root)
	lc := &ledgerCell{pressed: map[string]int{}}
	old := cellTestConnect
	cellTestConnect = func(context.Context) (cell.Conn, error) { return lc, nil }
	t.Cleanup(func() { cellTestConnect = old })

	m := asker("clerk")
	m.Capabilities = []string{"desktop_read", "desktop_press"}
	m.AskFirst = []string{"desktop_press"}
	m.Cell = &agent.Cell{}
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		choice := `{"op":"desktop_read"}`
		switch {
		case strings.Contains(body, "declined") || strings.Contains(body, "refused"):
			choice = `{"op":"done","say":"not paid"}`
		case strings.Contains(body, "Pay now"):
			choice = `{"op":"desktop_press","input":{"ref":"e2"}}`
		}
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": choice}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(model.Close)
	t.Setenv("QUILZO_MODEL_URL", model.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")

	answered := answerAllAsked(t, root, "clerk", false, "lee")
	_, out, err := runAgentKeptBy(context.Background(), root, "clerk", "pay the order", true, false, asAdmin("dana"))
	if aerr := <-answered; aerr != nil {
		t.Fatalf("answering: %v (%v)\n%s", aerr, err, describeRun(out.Trace))
	}
	if lc.pays() != 0 {
		t.Fatal("paid after a person declined")
	}
	declined := false
	for _, st := range out.Trace.Steps {
		declined = declined || strings.Contains(st.Why, "lee declined this")
	}
	if !declined {
		t.Errorf("the run was not told who declined: %+v", out.Trace.Steps)
	}
}

// answerAllAsked answers each distinct question a run asks — a cell's
// flow asks about more than one press — and reports when the run has
// finished, which is when it stops running.
func answerAllAsked(t *testing.T, root, name string, approve bool, by string) chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(30 * time.Second)
		quiet := time.Now().Add(1500 * time.Millisecond)
		lastErr := error(nil)
		answered := map[string]int{}
		for time.Now().Before(deadline) {
			recs, _ := listAgentRuns(root, name, 0)
			for _, r := range recs {
				if w := r.Trace.Waiting; w != nil && w.Live && answered[r.ID] != w.N {
					_, err := continueAgentRun(context.Background(), root, r.ID,
						&agent.Verdict{N: w.N, Approve: approve}, asAdmin(by))
					lastErr = err
					answered[r.ID] = w.N
					// The question stays on the record until the waiting
					// process has taken the answer in; quiet means taken.
					quiet = time.Now().Add(1500 * time.Millisecond)
				}
			}
			// A record's state is not the run's liveness: quiet — nothing
			// asking, nothing to take — is the run having finished.
			if time.Now().After(quiet) {
				done <- lastErr
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		done <- fmt.Errorf("the run never stopped asking or never started")
	}()
	return done
}

// One cell runs at a time on a machine: every restore of the warm snapshot
// binds the same vsock, so a second run is told plainly rather than
// colliding with the first.
func TestOneCellRunsAtATime(t *testing.T) {
	dir := t.TempDir()
	release, err := holdCell(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holdCell(dir); err == nil || !strings.Contains(err.Error(), "one runs at a time") {
		t.Fatalf("a second cell was held: %v", err)
	}
	release()
	again, err := holdCell(dir)
	if err != nil {
		t.Fatalf("the cell was not free after its run: %v", err)
	}
	again()
}

// The helper is reached through the vsock the snapshot binds, which the
// settings name; a machine whose settings do not is told so before any
// microVM is started.
func TestACellNeedsTheSnapshotsVsock(t *testing.T) {
	root := demoStore(t)
	for _, kv := range [][2]string{{"cell.backend", "firecracker"}, {"cell.binary", "/opt/firecracker/firecracker"}} {
		if err := cmdConfig(root, []string{"set", kv[0], kv[1]}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := cellBackendFor(root); err == nil || !strings.Contains(err.Error(), "cell.vsock") {
		t.Fatalf("a cell without its vsock was offered: %v", err)
	}
}
