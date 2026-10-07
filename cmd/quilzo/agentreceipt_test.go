// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
)

func keptRunOf(t *testing.T) (root, id string) {
	t.Helper()
	root, _ = identityStore(t)
	// Walking every capability without stopping to ask, so the run has
	// several steps.
	m := asker("tidy")
	m.AskFirst = nil
	if err := declareAgent(root, m, false, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, _, err := runAgentKept(context.Background(), root, "tidy", "tidy the about page", false, asAdmin("dana"))
	if err != nil && id == "" {
		t.Fatal(err)
	}
	return root, id
}

func TestEveryActionOfARunIsOneRecord(t *testing.T) {
	root, id := keptRunOf(t)
	rec, err := loadAgentRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	events, _ := audit.Read(auditPath(root))
	var actions []audit.Event
	sawRun := false
	for _, e := range events {
		if e.Detail["run"] != id {
			continue
		}
		switch e.Action {
		case "agent.action":
			actions = append(actions, e)
		case "agent.run":
			sawRun = true
		}
	}
	if len(actions) != len(rec.Trace.Steps) || !sawRun {
		t.Fatalf("%d action records for %d steps, run record %v", len(actions), len(rec.Trace.Steps), sawRun)
	}
	for i, e := range actions {
		st := rec.Trace.Steps[i]
		if e.Detail["step"] != strconv.Itoa(st.N) || e.Detail["agent"] != "tidy" {
			t.Errorf("record %d: %v", i, e.Detail)
		}
		if !st.Allowed && (e.Outcome != audit.Denied || e.Detail["why"] == "") {
			t.Errorf("a refused step is not recorded as refused: %+v", e)
		}
		for k, v := range e.Detail {
			if strings.Contains(v, "tidy the about page") && k != "goal" {
				t.Errorf("the goal leaked into %s", k)
			}
		}
	}
}

func TestAReceiptVerifiesAndTamperingShows(t *testing.T) {
	root, id := keptRunOf(t)
	rf, err := buildReceipt(root, id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c := checkReceipt(rf, nil); len(c.Problems) != 0 || !c.OwnKeys || len(c.Missing) != 0 || c.Agent != "tidy" {
		t.Fatalf("a fresh receipt: %+v", c)
	}
	// Against the store's published keys, as an auditor would.
	signer, _ := headSigner(root)
	ed, ml := signer.Verifier().PublicKeys()
	keys := &publishedKeys{Ed25519: base64.StdEncoding.EncodeToString(ed), MLDSA: base64.StdEncoding.EncodeToString(ml)}
	if c := checkReceipt(rf, keys); len(c.Problems) != 0 || c.OwnKeys {
		t.Fatalf("against published keys: %+v", c)
	}

	// A record altered after the fact.
	altered := *rf
	altered.Entries = append([]receiptEntry(nil), rf.Entries...)
	e := altered.Entries[0]
	d := map[string]string{}
	for k, v := range e.Entry.Detail {
		d[k] = v
	}
	d["op"] = "publish"
	e.Entry.Detail = d
	altered.Entries[0] = e
	if c := checkReceipt(&altered, nil); len(c.Problems) == 0 {
		t.Fatal("an altered record verified")
	}
	// A record left out: it verifies, and says which step is missing.
	short := *rf
	short.Entries = append([]receiptEntry(nil), rf.Entries[1:]...)
	if rf.Entries[0].Entry.Detail["step"] != "1" || len(short.Entries) == 0 {
		t.Fatalf("the run's first record is not step 1: %+v", rf.Entries[0].Entry.Detail)
	}
	if c := checkReceipt(&short, nil); len(c.Problems) != 0 || len(c.Missing) != 1 || c.Missing[0] != 1 {
		t.Fatalf("a missing step went unremarked: %+v", c)
	}
	// A head re-signed by somebody else's keys.
	edSeed, mlSeed, _ := audit.GenerateHeadSeeds()
	forger, err := audit.NewHeadSigner(edSeed, mlSeed)
	if err != nil {
		t.Fatal(err)
	}
	forged := *rf
	forged.Head, _ = forger.Sign(rf.Head.Head)
	if c := checkReceipt(&forged, keys); len(c.Problems) == 0 {
		t.Fatal("a head signed by another key verified against the published keys")
	}
	// And it brings its own keys: that only proves it agrees with itself.
	fe, fm := forger.Verifier().PublicKeys()
	forged.Keys = publishedKeys{Ed25519: base64.StdEncoding.EncodeToString(fe), MLDSA: base64.StdEncoding.EncodeToString(fm)}
	if c := checkReceipt(&forged, nil); len(c.Problems) != 0 || !c.OwnKeys {
		t.Fatalf("self-consistent forgery: %+v", c)
	}
	// A record from another run slipped in.
	mixed := *rf
	mixed.Run = "run-20260101-00000000"
	if c := checkReceipt(&mixed, nil); len(c.Problems) == 0 {
		t.Fatal("records of another run were accepted")
	}
	if _, err := buildReceipt(root, "../etc", time.Now()); err == nil {
		t.Fatal("a path was taken as a run")
	}
	if _, err := buildReceipt(root, "run-20260101-00000000", time.Now()); err == nil {
		t.Fatal("a receipt for a run the log does not hold")
	}
}

func TestARefusedActionIsRecordedAsRefused(t *testing.T) {
	m := asker("tidy")
	r := actionRecord(asAdmin("dana"), m, nil, "run-20261006-00000001",
		agent.Step{N: 3, Action: agent.Action{Op: "publish", Input: map[string]any{"page": "about"}}, Why: "this agent does not publish"})
	if r.Outcome != audit.Denied || r.Detail["why"] != "this agent does not publish" || r.Detail["step"] != "3" ||
		r.Resource != "/about" || r.Detail["input_sha256"] == "" || r.Detail["run"] != "run-20261006-00000001" {
		t.Fatalf("%+v", r)
	}
	failed := actionRecord(asAdmin("dana"), m, nil, "", agent.Step{N: 1, Allowed: true, Action: agent.Action{Tool: "x"}, Err: "timed out"})
	if failed.Outcome != audit.Failure || failed.Detail["tool"] != "x" {
		t.Fatalf("%+v", failed)
	}
	if long := clip(strings.Repeat("é", 400), 301); !utf8.ValidString(long) {
		t.Fatal("clipping split a character")
	}
}

// What an app did through one connection, for the person it acted for:
// the same proofs and signed head as a run's receipt, and only that
// connection's calls.
func TestAnAppsReceiptHoldsOnlyItsConnectionsCalls(t *testing.T) {
	root, _ := identityStore(t)
	call := func(grant, tool string, outcome audit.Outcome) {
		record(root, audit.Record{Action: "mcp.call", Resource: "/mcp", Outcome: outcome,
			Principal: "app:https://app.example.com/meta", Kind: audit.KindAI, Model: "https://app.example.com/meta",
			Verified: true, Detail: map[string]string{"tool": tool, "on_behalf_of": "dana", "grant": grant}})
	}
	const mine, theirs = "gr_00000000000000aa", "gr_00000000000000bb"
	call(mine, "list_pages", audit.Success)
	call(theirs, "list_pages", audit.Success)
	call(mine, "publish", audit.Denied)
	rf, err := buildAppReceipt(root, mine, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(rf.Entries) != 2 || rf.App != "https://app.example.com/meta" || rf.Format != appReceiptFormat {
		t.Fatalf("%d entries, app %q, format %q", len(rf.Entries), rf.App, rf.Format)
	}
	if c := checkReceipt(rf, nil); len(c.Problems) != 0 || c.Connection != mine {
		t.Fatalf("a fresh app receipt: %+v", c)
	}
	// Another connection's call slipped in still proves it is in the log,
	// and is still refused as not this connection's.
	other, err := buildAppReceipt(root, theirs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mixed := *rf
	mixed.Entries = append(append([]receiptEntry(nil), rf.Entries...), other.Entries...)
	if c := checkReceipt(&mixed, nil); len(c.Problems) == 0 {
		t.Fatal("another connection's call was accepted")
	}
	for _, bad := range []string{"../etc", "gr_xyz", "run-20260101-00000000"} {
		if _, err := buildAppReceipt(root, bad, time.Now()); err == nil || !strings.Contains(err.Error(), "not an app connection") {
			t.Errorf("%q was taken as a connection: %v", bad, err)
		}
	}
	if _, err := buildAppReceipt(root, "gr_00000000000000cc", time.Now()); err == nil {
		t.Fatal("a receipt for a connection that made no call")
	}
}
