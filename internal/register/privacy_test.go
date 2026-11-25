// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

// erasure is what a privacy officer, dana, enters when Ada asks to be
// erased.
func erasure(ada ID) ErasureRequest {
	return ErasureRequest{Subject: ada, Basis: "request", RequestedBy: ada}
}

// decided is the approval of a waiting erasure by somebody, over what it
// shows: what the approvals module gives, without the module, which the
// register's own tests do not have.
func decided(t testing.TB, b *bench, id ID, by Actor) *Approval {
	t.Helper()
	p, err := b.proposal(id)
	if err != nil {
		t.Fatal(err)
	}
	raised := p.Subject
	if e, ok := p.Record.(Erasure); ok && e.RequestedBy != "" {
		raised = e.RequestedBy
	}
	return &Approval{Atom: "approve", Rule: "erasure", Needed: 1, Of: 2, Surface: shown(t, b, p.Record), Raised: raised,
		Signers: []Signer{{Subject: by.Subject, At: TimeOf(b.now()), Assertion: digest(9)}}}
}

// erase is an erasure entered by dana and decided by lee: raised, then
// accepted with lee's approval.
func erase(t testing.TB, b *bench, req ErasureRequest) (Receipt, error) {
	t.Helper()
	if _, _, err := b.RaiseErasure(dana, req); err != nil {
		return Receipt{}, err
	}
	id := ErasureID(req.Subject)
	return b.Accept(lee, id, decided(t, b, id, lee))
}

// PLAN theme 7, the buyer's test: after a person is erased, every record,
// every commit and every object still checks. The register is append-only
// and addressed by hash, so erasing nothing in it is what keeps it whole;
// what was erased was beside it.
func TestEraseSubjectChainVerifies(t *testing.T) {
	b, ada, words := withAda(t)
	headBefore := b.Head()
	rc, err := erase(t, b, erasure(ada))
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
				if readsAs(body, id) {
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
	if _, err := erase(t, b, erasure(ada)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Index(); err != nil {
		t.Fatal(err)
	}
	for _, f := range scan() {
		t.Error(f)
	}
}

// readsAs reports whether a file holds s as somebody reading the disk
// would find it: in its bytes, or in a string of its JSON that is bytes
// written as base64, as a side entry's words are. The bytes alone are not
// enough: on a store that is not encrypted the words about a person are
// base64 in their entry's file, and a scan of the bytes found the person
// in the subject map and passed over every word written about them.
func readsAs(body []byte, s string) bool {
	if bytes.Contains(bytes.ToLower(body), bytes.ToLower([]byte(s))) {
		return true
	}
	var v any
	if json.Unmarshal(body, &v) != nil {
		return false
	}
	var walk func(v any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case string:
			b, err := base64.StdEncoding.DecodeString(x)
			return err == nil && len(b) > 0 && readsAs(b, s)
		case map[string]any:
			for _, e := range x {
				if walk(e) {
					return true
				}
			}
		case []any:
			for _, e := range x {
				if walk(e) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}

// Nothing more is kept beside the register about a person once they are
// erased. Their pseudonym stays in the records that named it, and a
// surface that writes words or a file about whoever a record names would
// otherwise keep them under a pseudonym that names nobody: the person
// cannot be erased a second time, so those words would be kept until a
// retention period ended, or for good for a kind that has none.
func TestNothingIsKeptAboutAPersonErased(t *testing.T) {
	b, ada, _ := withAda(t)
	if _, err := erase(t, b, erasure(ada)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PutText(dana, KindRisk, "Ada Lovelace still owns the fix.", ada); !errors.Is(err, ErrErased) {
		t.Errorf("words about an erased person were answered %v", err)
	}
	if _, err := b.PutRaw(dana, KindObservation, "application/json", []byte(`{"user":"ada.lovelace"}`), ada); !errors.Is(err, ErrErased) {
		t.Errorf("a file about an erased person was answered %v", err)
	}
	if about, err := b.Side().About(string(ada)); err != nil || len(about) != 0 {
		t.Errorf("after the erasure the side store keeps %d entries about her (%v)", len(about), err)
	}
	if held := b.TextOf(Text(digestOfWords("Ada Lovelace still owns the fix."))); held.State != TextNotHeld {
		t.Errorf("the words refused read as %+v", held)
	}
	// Words about somebody else, and about nobody, are kept as before.
	if _, err := b.PutText(dana, KindRisk, "The fix is owned by the identity team.", owner); err != nil {
		t.Errorf("words about somebody not erased were answered %v", err)
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
		// An address may be written in any script (RFC 6531), and its
		// domain is a name of any script too: an address ending in a
		// letter outside ASCII before the at sign, or with a domain or a
		// top-level domain that is not ASCII, is still somebody's.
		"an address ending in a letter outside ASCII": Control{Ref: "AC-12", Title: "Reviewed by jos\u00e9@example.com",
			Domain: "identity", Owner: owner},
		"an address with a domain outside ASCII": Control{Ref: "AC-13", Title: "Owned by anna@b\u00fccher.de",
			Domain: "identity", Owner: owner},
		"an address in Cyrillic": Control{Ref: "AC-14", Title: "\u0418\u0432\u0430\u043d@\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444 is the owner",
			Domain: "identity", Owner: owner},
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
	for _, title := range []string{"lodash@4.17.21 is pinned", "Rotate keys @ quarter end", "security@ alias is monitored",
		"@types/node@20.11.5 is pinned", "Stra\u00dfe @ M\u00fcnchen", "Bericht f\u00fcr Q3@2026"} {
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

	// A model asks for nobody's erasure, nor does somebody the policy does
	// not let decide one decide it; and nothing is erased when either is
	// refused.
	if _, _, err := b.RaiseErasure(model, erasure(ada)); !errors.Is(err, ErrModel) {
		t.Errorf("a model's erasure was answered %v", err)
	}
	if _, _, err := b.RaiseErasure(dana, erasure(ada)); err != nil {
		t.Fatal(err)
	}
	id := ErasureID(ada)
	refused := lee
	refused.May = func(act auth.Action, res string) error {
		if act == auth.ActApprove {
			return deny(act, res)
		}
		return nil
	}
	if _, err := b.Accept(refused, id, decided(t, b, id, refused)); !errors.Is(err, ErrRefused) {
		t.Errorf("an erasure decided by somebody who may not decide one was answered %v", err)
	}
	// Whoever entered it does not decide it while somebody else may, and a
	// person does not decide their own.
	if _, err := b.Accept(dana, id, decided(t, b, id, dana)); !errors.Is(err, ErrRefused) {
		t.Errorf("the person who entered the erasure deciding it was answered %v", err)
	}
	self := lee
	self.Subject = ada
	if _, err := b.Accept(self, id, decided(t, b, id, self)); !errors.Is(err, ErrInvalid) {
		t.Errorf("a person deciding their own erasure was answered %v", err)
	}
	if who := b.SubjectState(ada); who.State != SubjectHeld {
		t.Fatalf("a refused erasure erased the person: %+v", who)
	}

	rc, err := b.Accept(lee, id, decided(t, b, id, lee))
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
	if a == nil || len(a.Signers) != 1 || a.Signers[0].Subject != lee.Subject || a.Raised != ada ||
		rec.Decider != lee.Subject || rec.At != a.Signers[0].At || rec.Subject != ada || rec.RequestedBy != ada ||
		rec.EnteredBy != dana.Subject || !rec.Map || rec.Entries != 1 {
		t.Fatalf("the erasure record is %+v with %+v", rec, a)
	}
	if want := shown(t, b, rec); a.Surface != want {
		t.Errorf("the approval is over %s and the record as shown is %s", a.Surface, want)
	}
	if left, _ := b.Proposals(); len(left) != 0 {
		t.Errorf("%d proposals wait after the erasure was decided", len(left))
	}
	// Written once: changed, it is refused; asked for again, the person
	// is already erased.
	changed := rec
	changed.Basis = "objection"
	if _, err := b.Put(dana, "a changed erasure", changed); !errors.Is(err, ErrImmutable) && !errors.Is(err, ErrInvalid) {
		t.Errorf("a changed erasure was answered %v", err)
	}
	if _, _, err := b.RaiseErasure(dana, erasure(ada)); !errors.Is(err, ErrErased) {
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
	// Kept as a write is: in the audit log, with what was kept and never
	// what it says, and not at all while nothing can record it.
	var kept *audit.Record
	for i := range b.log {
		if b.log[i].Action == SideAction {
			kept = &b.log[i]
		}
	}
	if kept == nil || kept.Detail["digest"] != string(words) || kept.Detail["kind"] != "sec_risk" {
		t.Errorf("the words kept are recorded as %+v", kept)
	}
	for _, rec := range b.log {
		for _, v := range rec.Detail {
			if strings.Contains(v, "fine line") {
				t.Errorf("an audit entry holds the words: %+v", rec)
			}
		}
	}
	b.Ready = func() error { return errors.New("the disk holding the audit log is full") }
	if d, err := b.PutText(dana, KindRisk, "Unrecordable."); err == nil {
		t.Errorf("words were kept while the audit log could not record it, as %s", d)
	}
	if held := b.TextOf(Text(digestOfWords("Unrecordable."))); held.State != TextNotHeld {
		t.Errorf("words kept while the audit log could not record it read as %+v", held)
	}
	b.Ready = nil
	b.Audit = nil
	if _, err := b.PutText(dana, KindRisk, "Unrecorded."); err == nil {
		t.Error("words were kept with no audit log to record it")
	}
}

// digestOfWords is the digest words are kept under.
func digestOfWords(words string) string {
	sum := sha256.Sum256([]byte(words))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// An erasure's approval is held to the register's check of the decider's
// authentication evidence before anything is deleted, as every other rule
// of its record is: an approval that does not hold leaves the person in
// the map and every word about them where it was, rather than erasing them
// and failing to write the record that says so.
func TestAnErasureWhoseApprovalDoesNotHoldErasesNothing(t *testing.T) {
	b, ada, words := withAda(t)
	b.Approvals = func(rec Record, id ID, a *Approval) error {
		if rec.Kind() == KindErasure {
			return errors.New("the passkey assertion does not verify")
		}
		return nil
	}
	head := b.Head()
	if _, err := erase(t, b, erasure(ada)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an erasure whose approval does not hold was answered %v", err)
	}
	if who := b.SubjectState(ada); who.State != SubjectHeld {
		t.Errorf("the person was erased all the same: %+v", who)
	}
	if held := b.TextOf(words); held.State != TextHeld {
		t.Errorf("the words about them were erased all the same: %+v", held)
	}
	if b.Head() != head {
		t.Errorf("the register moved from %s to %s", head, b.Head())
	}
	b.Approvals = nil
	id := ErasureID(ada)
	if _, err := b.Accept(lee, id, decided(t, b, id, lee)); err != nil {
		t.Errorf("with the approval holding, the erasure was answered %v", err)
	}
}

// An erasure's requester is a recorded request: raised by the person who
// asked, or entered on behalf of whoever asked, and the record says who
// asked and who entered it. A pseudonym typed in for somebody the subject
// map does not name is no request. Entered for a person and decided by
// somebody else, it is the person's request, entered by the one and
// decided by the other.
//
// The requester was any pseudonym the decider typed into --requested-by,
// so the person who raised an erasure decided it by naming somebody else
// as having asked.
func TestAnErasureIsARequestRecordedWithWhoEnteredIt(t *testing.T) {
	b, ada, _ := withAda(t)
	if _, _, err := b.RaiseErasure(dana, ErasureRequest{Subject: ada, Basis: "request",
		RequestedBy: "a0000000000000000000000000000099"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("an erasure asked for by a pseudonym nobody holds was answered %v", err)
	}
	if left, _ := b.Proposals(); len(left) != 0 {
		t.Fatalf("a refused request waits: %+v", left)
	}
	// Asked for by somebody the subject map names, and entered by dana.
	hr, err := b.SubjectFor("people-team@example.com", "account")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.RaiseErasure(dana, ErasureRequest{Subject: ada, Basis: "no-longer-needed", RequestedBy: hr}); err != nil {
		t.Fatal(err)
	}
	p, err := b.proposal(ErasureID(ada))
	if err != nil {
		t.Fatal(err)
	}
	if e := p.Record.(Erasure); e.RequestedBy != hr || e.EnteredBy != dana.Subject || e.Decider != "" || e.At != 0 {
		t.Errorf("the request waits as %+v", e)
	}
	// Raised by dana herself, she asked for it, and nobody entered it for
	// her.
	if _, _, err := b.RaiseErasure(dana, ErasureRequest{Subject: ada, Basis: "no-longer-needed"}); err != nil {
		t.Fatal(err)
	}
	p, _ = b.proposal(ErasureID(ada))
	if e := p.Record.(Erasure); e.RequestedBy != dana.Subject || e.EnteredBy != "" {
		t.Errorf("an erasure dana raised herself waits as %+v", e)
	}
	// Entered on Ada's own request, it is approved over what it shows, and
	// what is about Ada changing since is what was not approved.
	if _, _, err := b.RaiseErasure(dana, erasure(ada)); err != nil {
		t.Fatal(err)
	}
	id := ErasureID(ada)
	before := decided(t, b, id, lee)
	if _, err := b.PutText(dana, KindRisk, "Ada also asked about her old laptop.", ada); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Accept(lee, id, before); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "raise it again") {
		t.Errorf("an erasure whose person had more kept about them since it was approved was answered %v", err)
	}
	if who := b.SubjectState(ada); who.State != SubjectHeld {
		t.Fatalf("the refused erasure erased the person: %+v", who)
	}
	if _, err := erase(t, b, erasure(ada)); err != nil {
		t.Fatalf("raised again and approved as it stands: %v", err)
	}
	e, _ := b.Get(id)
	if rec := e.Record.(Erasure); rec.Entries != 2 || rec.RequestedBy != ada || rec.EnteredBy != dana.Subject || rec.Decider != lee.Subject {
		t.Errorf("the erasure record is %+v", rec)
	}
}

// A person two older maps gave two pseudonyms is one person: erased under
// either, both go, and the record names the other as erased with it.
func TestAPersonIsErasedUnderEveryPseudonymTheMapHolds(t *testing.T) {
	b, ada, _ := withAda(t)
	const older = ID("a0000000000000000000000000000077")
	if _, err := b.Side().Adopt(adaUPN, "person", string(older)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PutText(dana, KindRisk, "Ada approved the exception under her older name.", older); err != nil {
		t.Fatal(err)
	}
	if _, err := erase(t, b, erasure(ada)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []ID{ada, older} {
		if who := b.SubjectState(id); who.State != SubjectErased {
			t.Errorf("after the erasure %s reads as %+v", id, who)
		}
		if about, _ := b.Side().About(string(id)); len(about) != 0 {
			t.Errorf("after the erasure %d entries are kept about %s", len(about), id)
		}
	}
	e, _ := b.Get(ErasureID(ada))
	if rec := e.Record.(Erasure); len(rec.Also) != 1 || rec.Also[0] != older || rec.Entries != 2 {
		t.Errorf("the erasure record is %+v", rec)
	}
	if _, found, _ := b.Side().Lookup(adaUPN); found {
		t.Error("the subject map still names Ada")
	}
}
