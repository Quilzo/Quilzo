// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register/side"
)

// Ada is the person these tests erase: how the systems that name her know
// her, and the words written about her.
const (
	adaUPN   = "ada.lovelace@example.com"
	adaName  = "Ada Lovelace"
	adaWords = "Ada Lovelace raised this after the access review; she owns the fix."
)

// withAda is a register holding a person and what was written about her: a
// risk she raised and owns, with free text naming her, and a control she
// owns. dana writes it.
func withAda(t *testing.T) (*bench, ID, Text) {
	t.Helper()
	b := newBench(t)
	ada, err := b.SubjectFor(adaUPN, "person")
	if err != nil {
		t.Fatal(err)
	}
	words, err := b.PutText(dana, KindRisk, adaWords, ada)
	if err != nil {
		t.Fatal(err)
	}
	mustPut(t, b, dana,
		Subject{Pseudonym: ada, Type: "person"},
		Risk{Ref: "R-7", Title: "Shared administrator accounts", Description: words, Owner: ada, Raised: ada,
			Likelihood: 3, Impact: 4, Status: "open"},
		Control{Ref: "AC-01", Title: "Second factor for every account", Domain: "identity", Owner: ada})
	return b, ada, words
}

// erasure is what a privacy officer, dana, asks for when Ada asks to be
// erased, with one other person who may decide it.
func erasure(ada ID) ErasureRequest {
	return ErasureRequest{Subject: ada, Basis: "request", RequestedBy: ada, Eligible: 2,
		Evidence: []byte("the decider's passkey assertion over the surface")}
}

// PLAN theme 7, the buyer's test: after a person is erased, every record,
// every commit and every object still checks. The register is append-only
// and addressed by hash, so erasing nothing in it is what keeps it whole;
// what was erased was beside it.
func TestEraseSubjectChainVerifies(t *testing.T) {
	b, ada, words := withAda(t)
	headBefore := b.Head()
	rc, err := b.Erase(dana, erasure(ada))
	if err != nil {
		t.Fatal(err)
	}
	if rc.Parent != headBefore || rc.Commit == "" {
		t.Fatalf("the erasure's commit is %s on %s; the head was %s", rc.Commit, rc.Parent, headBefore)
	}
	if n, err := b.Store.Verify(); err != nil || n == 0 {
		t.Fatalf("after the erasure the store verifies %d objects with %v", n, err)
	}
	// Every commit from the head back to the first reads, and each names
	// its parent, so the chain is unbroken.
	seen := 0
	for c := b.Head(); c != ""; {
		commit, err := b.Store.GetCommit(c)
		if err != nil {
			t.Fatalf("the commit %s does not read: %v", c, err)
		}
		seen++
		if len(commit.Parents) == 0 {
			break
		}
		c = commit.Parents[0]
	}
	if seen < 2 {
		t.Fatalf("the chain holds %d commits", seen)
	}
	// Every record reads back, and the index built from the store equals
	// the one kept.
	for _, k := range Kinds() {
		if _, _, err := b.List(k.Kind, 0, 0); err != nil {
			t.Errorf("the %s records do not read after the erasure: %v", k.Kind, err)
		}
	}
	kept, err := b.Index()
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := b.Rebuild()
	if err != nil || !kept.Equal(rebuilt) {
		t.Errorf("the index built afresh differs from the one kept (%v)", err)
	}
	// The risk still reads, still holds its digest, and says its words
	// were erased; the pseudonym says its person was.
	risk, err := b.Get(mustID(t, Risk{Ref: "R-7"}))
	if err != nil || risk.Record.(Risk).Description != words {
		t.Fatalf("the risk reads as %+v (%v)", risk, err)
	}
	held := b.TextOf(words)
	if held.State != TextErased || held.Words != "" || held.Erased == nil {
		t.Errorf("the risk's words are %+v", held)
	}
	if who := b.SubjectState(ada); who.State != SubjectErased {
		t.Errorf("the erased pseudonym reads as %+v", who)
	}
}

// PLAN theme 7, the buyer's test: after a person is erased, nothing that
// identifies them is left in any store object, any index row, any file of
// the side store or the detail of any audit entry the register wrote. The
// scan reads every file under the store's directory, as they are on disk,
// so it finds what a copy of the disk would.
func TestErasedIdentifiersUnrecoverable(t *testing.T) {
	b, ada, _ := withAda(t)
	if _, err := b.Index(); err != nil {
		t.Fatal(err)
	}
	identifiers := []string{adaUPN, adaName, "ada.lovelace"}
	scan := func() []string {
		var found []string
		_ = filepath.WalkDir(b.Store.Root(), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, id := range identifiers {
				if bytes.Contains(bytes.ToLower(body), bytes.ToLower([]byte(id))) {
					found = append(found, strings.TrimPrefix(path, b.Store.Root())+" holds "+id)
				}
			}
			return nil
		})
		for _, r := range b.log {
			for k, v := range r.Detail {
				for _, id := range identifiers {
					if strings.Contains(strings.ToLower(v), strings.ToLower(id)) {
						found = append(found, "the audit entry "+r.Action+" holds "+id+" under "+k)
					}
				}
			}
		}
		return found
	}
	// The scan finds her before: it is looking in the right places.
	if before := scan(); len(before) == 0 {
		t.Fatal("nothing identified Ada before she was erased; the scan is looking in the wrong place")
	}
	if _, err := b.Erase(dana, erasure(ada)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Index(); err != nil {
		t.Fatal(err)
	}
	for _, f := range scan() {
		t.Error(f)
	}
}

// PLAN theme 7: retention is per kind, declared beside the kind's schema,
// and a sweep deletes what every kind holding it has kept long enough. The
// records that named the words still read, and say the words are gone.
func TestRetentionDeletesSideEntries(t *testing.T) {
	b := newBench(t)
	obs := RetentionOf(KindObservation)
	if obs <= 0 {
		t.Fatalf("an observation's raw file is kept for %v", obs)
	}
	if RetentionOf(KindDecision) != 0 {
		t.Fatalf("a decision's words are kept for %v; they are kept until a person erases them", RetentionOf(KindDecision))
	}
	raw, err := b.PutRaw(dana, KindObservation, "application/json", []byte(`{"userPrincipalName":"someone"}`))
	if err != nil {
		t.Fatal(err)
	}
	source := ID("5000000000000000000000000000000a")
	mustPut(t, b, dana, Observation{Source: source, About: owner, Fact: "mfa.registered", Value: BoolValue(true),
		Grade: GradeConnector, Raw: raw})
	words, err := b.PutText(dana, KindDecision, "Minuted at the board of 20 November.")
	if err != nil {
		t.Fatal(err)
	}

	b.clock.forward(obs - time.Hour)
	if n, err := b.ExpireSide(); err != nil || n != 0 {
		t.Fatalf("an hour early the sweep deleted %d (%v)", n, err)
	}
	b.clock.forward(2 * time.Hour)
	if n, err := b.ExpireSide(); err != nil || n != 1 {
		t.Fatalf("past the observation's period the sweep deleted %d (%v)", n, err)
	}
	if held := b.RawOf(raw); held.State != TextErased || held.Erased.Basis != side.BasisRetention {
		t.Errorf("the expired raw file reads as %+v", held)
	}
	if held := b.TextOf(Text(words)); held.State != TextHeld {
		t.Errorf("the decision's words are %+v", held)
	}
	if _, err := b.Get(mustID(t, Observation{Source: source, About: owner, Fact: "mfa.registered"})); err != nil {
		t.Errorf("the observation does not read after its raw file expired: %v", err)
	}
	if n, err := b.Store.Verify(); err != nil || n == 0 {
		t.Errorf("after the sweep the store verifies %d objects with %v", n, err)
	}
}

// PLAN theme 7: a plain string holding an address or an account name is
// refused at Put, in a label, a fact's value or a write's own line. A
// person goes in a record as a pseudonym, and who they are goes in the
// subject map.
func TestPutRefusesInlinePersonalIdentifier(t *testing.T) {
	b := newBench(t)
	for what, rec := range map[string]Record{
		"an address in a title": Control{Ref: "AC-09", Title: "Reviewed by ada.lovelace@example.com", Domain: "identity", Owner: owner},
		"a UPN in a reference":  Risk{Ref: "ada@contoso.onmicrosoft.com", Title: "T", Owner: owner, Raised: owner, Likelihood: 1, Impact: 1, Status: "open"},
		"an address as a fact": Observation{Source: owner, About: owner, Fact: "upn", Value: TextValue("Ada.Lovelace@Example.COM"),
			Grade: GradeConnector},
	} {
		_, err := b.Put(dana, "a test's write", rec)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "subject map") {
			t.Errorf("%s was answered %v", what, err)
		}
	}
	if _, err := b.Put(dana, "imported from ada@example.com", control("AC-10")); !errors.Is(err, ErrInvalid) {
		t.Errorf("an address in a write's own line was answered %v", err)
	}
	// What looks like an address and is not one is a label like any other.
	for _, title := range []string{"lodash@4.17.21 is pinned", "Rotate keys @ quarter end", "security@ alias is monitored"} {
		c := control("AC-11")
		c.Title = title
		if _, err := b.Put(dana, "a test's write", c); err != nil {
			t.Errorf("the title %q was refused: %v", title, err)
		}
	}
	if len(b.log) == 0 {
		t.Fatal("nothing was written at all")
	}
}

// PLAN theme 7: an erasure is a decision, and its record is a signed one:
// it carries the approval that made it, bound to the record as shown, by a
// person who is not the one erased; it is written once and never changed;
// and the register refuses one that does not carry its approval.
func TestErasureIsSignedRecord(t *testing.T) {
	spec, ok := SpecOf("Erasure")
	if !ok || !spec.Signed || !spec.Immutable || spec.Class != ClassRestricted {
		t.Fatalf("the erasure kind is %+v", spec)
	}
	b, ada, _ := withAda(t)
	bare := Erasure{Subject: ada, Basis: "request", Decider: dana.Subject, At: TimeOf(b.now())}
	if _, err := b.Put(dana, "an erasure without its approval", bare); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an erasure without its approval was answered %v", err)
	}

	// A model does not erase anybody, nor does somebody the policy does
	// not let decide; and nothing is erased when either is refused.
	if _, err := b.Erase(model, erasure(ada)); !errors.Is(err, ErrModel) {
		t.Errorf("a model's erasure was answered %v", err)
	}
	refused := dana
	refused.May = func(act auth.Action, res string) error {
		if act == auth.ActApprove {
			return deny(act, res)
		}
		return nil
	}
	if _, err := b.Erase(refused, erasure(ada)); !errors.Is(err, ErrRefused) {
		t.Errorf("an erasure by somebody who may not decide one was answered %v", err)
	}
	// Nor does a person decide their own.
	self := dana
	self.Subject = ada
	if _, err := b.Erase(self, erasure(ada)); !errors.Is(err, ErrInvalid) {
		t.Errorf("a person deciding their own erasure was answered %v", err)
	}
	if who := b.SubjectState(ada); who.State != SubjectHeld {
		t.Fatalf("a refused erasure erased the person: %+v", who)
	}

	rc, err := b.Erase(dana, erasure(ada))
	if err != nil {
		t.Fatal(err)
	}
	if len(rc.Written) != 1 || rc.Written[0].Kind != KindErasure {
		t.Fatalf("the erasure wrote %+v", rc.Written)
	}
	e, err := b.Get(rc.Written[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	rec := e.Record.(Erasure)
	a := rec.Approval
	if a == nil || len(a.Signers) != 1 || a.Signers[0].Subject != dana.Subject || a.Raised != ada ||
		rec.Decider != dana.Subject || rec.Subject != ada || !rec.Map || rec.Entries != 1 {
		t.Fatalf("the erasure record is %+v with %+v", rec, a)
	}
	shown := rec
	shown.Approval = nil
	if a.Surface != SurfaceOf(shown) {
		t.Errorf("the approval is over %s and the record as shown is %s", a.Surface, SurfaceOf(shown))
	}
	// Written once: changed, it is refused; asked for again, the person
	// is already erased.
	changed := rec
	changed.Basis = "objection"
	if _, err := b.Put(dana, "a changed erasure", changed); !errors.Is(err, ErrImmutable) && !errors.Is(err, ErrInvalid) {
		t.Errorf("a changed erasure was answered %v", err)
	}
	if _, err := b.Erase(dana, erasure(ada)); !errors.Is(err, ErrErased) {
		t.Errorf("erasing an erased person again was answered %v", err)
	}
	// The audit log has the erasure under its own name, with the
	// pseudonym under an identity key, which the log pseudonymises again.
	var logged bool
	for _, r := range b.log {
		if r.Action == EraseAction && r.Outcome == audit.Success && r.Detail["subject"] == string(ada) &&
			r.Detail["receipt"] == string(rc.Digest) && audit.IdentityKeys["subject"] {
			logged = true
		}
	}
	if !logged {
		t.Errorf("the erasure is not in the audit log as one: %+v", b.log)
	}
}

// A person's free text goes in through the policy gate, as a record does.
func TestTextIsPutThroughTheGate(t *testing.T) {
	b := newBench(t)
	stopped := dana
	stopped.May = deny
	if _, err := b.PutText(stopped, KindRisk, "anything"); !errors.Is(err, ErrRefused) {
		t.Errorf("text from somebody refused the kind was answered %v", err)
	}
	if _, err := b.PutText(model, KindRisk, "anything"); !errors.Is(err, ErrModel) {
		t.Errorf("text from a model was answered %v", err)
	}
	if _, err := b.PutText(dana, "Nonsense", "anything"); !errors.Is(err, ErrInvalid) {
		t.Errorf("text for a kind nobody defined was answered %v", err)
	}
	words, err := b.PutText(dana, KindRisk, "A fine line.")
	if err != nil || !words.Valid() {
		t.Fatalf("the text is %q (%v)", words, err)
	}
	if held := b.TextOf(words); held.State != TextHeld || held.Words != "A fine line." {
		t.Errorf("the words read back as %+v", held)
	}
	if held := b.TextOf(Text(digest(9))); held.State != TextNotHeld {
		t.Errorf("words never put here read as %+v", held)
	}
}
