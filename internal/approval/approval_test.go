// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/webauthn"
)

const (
	testRP     = "quilzo.example"
	testOrigin = "https://quilzo.example"
)

// authenticator is a stand-in for a real one, built from the WebAuthn
// specification rather than from the code under test: it signs the
// authenticator data followed by the hash of the client data, with its PIN
// asked for.
type authenticator struct {
	key   *ecdsa.PrivateKey
	id    []byte
	count uint32
}

func newAuthenticator(t *testing.T, id string) *authenticator {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{key: k, id: []byte(id), count: 1}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// prove is the authenticator answering a challenge, as the passkey proof
// the admin hands the module.
func (a *authenticator) prove(t *testing.T, challenge string) *PasskeyProof {
	t.Helper()
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": testOrigin,
		"crossOrigin": false})
	rp := sha256.Sum256([]byte(testRP))
	a.count++
	ad := binary.BigEndian.AppendUint32(append(append([]byte{}, rp[:]...), 0x05), a.count)
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(a.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return &PasskeyProof{RelyingParty: testRP, Origin: testOrigin, Credential: a.id, PublicKey: der,
		Algorithm: webauthn.AlgES256, Challenge: challenge,
		Assertion: webauthn.Assertion{ID: b64(a.id), ClientDataJSON: b64(cd), AuthenticatorData: b64(ad), Signature: b64(sig)}}
}

// bench is a store's register and its approvals, on a clock the test moves.
type bench struct {
	t      *testing.T
	root   string
	reg    *register.Register
	m      *Approvals
	access *auth.Policy
	clock  time.Time
	log    []audit.Record
	keys   map[string]*authenticator
}

func newBench(t *testing.T, grants ...auth.Binding) *bench {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	b := &bench{t: t, root: dir, access: &auth.Policy{}, clock: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC),
		keys: map[string]*authenticator{}}
	for _, g := range grants {
		if err := b.access.Grant(g); err != nil {
			t.Fatal(err)
		}
	}
	b.reg = register.Open(s)
	if b.reg.Approvals == nil {
		t.Fatal("a register opened with the approvals module does not check approvals' evidence")
	}
	rec := func(r audit.Record) error { b.log = append(b.log, r); return nil }
	b.reg.Audit, b.reg.Now = rec, func() time.Time { return b.clock }
	b.m = &Approvals{Root: dir, Register: b.reg, Access: b.access, Audit: rec, Now: func() time.Time { return b.clock }}
	return b
}

// holds is a grant of an atom on the register.
func holds(who string, atom auth.Action) auth.Binding {
	return auth.Binding{Principal: who, Permission: atom, Resource: register.Area}
}

func (b *bench) subject(name string) register.ID {
	b.t.Helper()
	id, err := b.m.people().Pseudonym(name)
	if err != nil {
		b.t.Fatal(err)
	}
	return id
}

// person is somebody signed in with a passkey, whose requests ask the
// access policy as them.
func (b *bench) person(name string) Person {
	return Person{Name: name, Kind: audit.KindHuman, Verified: true, Methods: []string{auth.MethodPasskey},
		May: func(act auth.Action, resource string) error {
			if d := b.access.Evaluate(name, act, resource); !d.Allowed {
				return errors.New(d.Reason)
			}
			return nil
		}}
}

// propose puts a record on the proposals ref, as the person named raises
// it.
func (b *bench) propose(by string, rec register.Record) register.ID {
	b.t.Helper()
	allow := func(auth.Action, string) error { return nil }
	actor := register.Actor{Name: by, Subject: b.subject(by), Kind: audit.KindHuman, Verified: true, May: allow}
	rc, err := b.reg.Propose(actor, "raised for a test", rec)
	if err != nil {
		b.t.Fatal(err)
	}
	return rc.Written[0].ID
}

func (b *bench) key(who string) *authenticator {
	if b.keys[who] == nil {
		b.keys[who] = newAuthenticator(b.t, "credential-of-"+who)
	}
	return b.keys[who]
}

func nonce(t *testing.T) []byte {
	n := make([]byte, nonceSize)
	if _, err := rand.Read(n); err != nil {
		t.Fatal(err)
	}
	return n
}

// proofFor is who's passkey signing the challenge for a hash.
func (b *bench) proofFor(who string, p Purpose, of register.Digest) Proof {
	b.t.Helper()
	ch, err := Challenge(p, of, nonce(b.t))
	if err != nil {
		b.t.Fatal(err)
	}
	return Proof{Passkey: b.key(who).prove(b.t, ch)}
}

// sign is who approving a waiting decision with their passkey, over the
// hash of what it is now.
func (b *bench) sign(who string, id register.ID) (*Outcome, error) {
	b.t.Helper()
	a, err := b.m.Ask(id)
	if err != nil {
		b.t.Fatal(err)
	}
	return b.m.Sign(b.person(who), id, b.proofFor(who, ForApproval, a.Hash))
}

func (b *bench) risk(ref, raiser string, impact int64) register.Risk {
	return register.Risk{Ref: ref, Title: "Payments supplier outage", Owner: b.subject("owner"), Raised: b.subject(raiser),
		Likelihood: 3, Impact: impact, Status: "accepted"}
}

func (b *bench) audited(action string) []audit.Record {
	var out []audit.Record
	for _, r := range b.log {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

// An assertion made for one surface approves that surface and no other:
// another record, or this record as it was before it changed. It is refused
// where it is given, and refused again by the register if somebody puts the
// approval together by hand.
func TestAssertionForOtherSurfaceRefused(t *testing.T) {
	b := newBench(t, holds("ciso", auth.ActAcceptRisk))
	one := b.propose("dana", b.risk("R-1", "dana", 3))
	two := b.propose("dana", b.risk("R-2", "dana", 3))
	askTwo, _ := b.m.Ask(two)

	_, err := b.m.Sign(b.person("ciso"), one, b.proofFor("ciso", ForApproval, askTwo.Hash))
	if !errors.Is(err, ErrOtherSurface) || !errors.Is(err, ErrRefused) {
		t.Fatalf("an assertion over another record's surface approved this one: %v", err)
	}
	if b.reg.Head() != "" {
		t.Fatal("the refused approval wrote the record")
	}
	if len(b.audited(AuditRefused)) == 0 {
		t.Error("the refusal is not in the audit log")
	}

	// The same record changed after it was shown is another surface.
	askOne, _ := b.m.Ask(one)
	shown := askOne.Hash
	changed := b.risk("R-1", "dana", 3)
	changed.Title = "Payments supplier outage, widened"
	b.propose("dana", changed)
	if _, err := b.m.Sign(b.person("ciso"), one, b.proofFor("ciso", ForApproval, shown)); !errors.Is(err, ErrOtherSurface) {
		t.Fatalf("an assertion over the record as it was approved it as it is: %v", err)
	}
	// A signature for another purpose is not an approval either.
	now, _ := b.m.Ask(one)
	if _, err := b.m.Sign(b.person("ciso"), one, b.proofFor("ciso", ForReview, now.Hash)); err == nil {
		t.Fatal("a review's signature was taken for an approval")
	}

	// Put together by hand, with genuine evidence of the other surface, the
	// register refuses it at its one write path.
	ev, err := b.m.evidenceOf(b.person("ciso"), b.subject("ciso"), ForApproval, askTwo.Hash,
		b.proofFor("ciso", ForApproval, askTwo.Hash), b.clock)
	if err != nil {
		t.Fatal(err)
	}
	d, err := keep(b.root, ev)
	if err != nil {
		t.Fatal(err)
	}
	forged := b.risk("R-1", "dana", 3)
	forged.Approval = &register.Approval{Atom: "accept-risk", Rule: "risk-acceptance", Needed: 1, Of: 1, Surface: askTwo.Hash,
		Raised: b.subject("dana"), Signers: []register.Signer{{Subject: b.subject("ciso"), At: register.TimeOf(b.clock), Assertion: d}}}
	allow := func(auth.Action, string) error { return nil }
	if _, err := b.reg.Put(register.Actor{Name: "ciso", Subject: b.subject("ciso"), Kind: audit.KindHuman, May: allow},
		"a test's write", forged); !errors.Is(err, register.ErrInvalid) || !strings.Contains(err.Error(), "not what is being written") {
		t.Fatalf("the register wrote an approval of another surface: %v", err)
	}
	changed.Approval = forged.Approval
	changed.Approval.Surface = now.Hash
	if _, err := b.reg.Put(register.Actor{Name: "ciso", Subject: b.subject("ciso"), Kind: audit.KindHuman, May: allow},
		"a test's write", changed); !errors.Is(err, register.ErrInvalid) || !strings.Contains(err.Error(), "not an approval of this surface") {
		t.Fatalf("the register took evidence of one surface for another: %v", err)
	}

	// And the assertion for the record as it stands approves it.
	out, err := b.sign("ciso", one)
	if err != nil || !out.Done {
		t.Fatalf("the right assertion did not approve it: %+v %v", out, err)
	}
}

// Whoever raised a risk does not accept it, however much they may; and no
// agent approves anything.
func TestRaiserCannotAccept(t *testing.T) {
	b := newBench(t, holds("dana", auth.ActAcceptRisk), holds("ciso", auth.ActAcceptRisk))
	id := b.propose("dana", b.risk("R-3", "dana", 2))
	if _, err := b.sign("dana", id); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "raised or drafted") {
		t.Fatalf("the person who raised the risk accepted it: %v", err)
	}
	// "Dana " is Dana.
	if _, err := b.sign("Dana ", id); !errors.Is(err, ErrRefused) {
		t.Fatalf("the raiser under another spelling accepted it: %v", err)
	}
	agent := b.person("risk-clerk")
	agent.Kind = audit.KindAI
	a, _ := b.m.Ask(id)
	if _, err := b.m.Sign(agent, id, b.proofFor("risk-clerk", ForApproval, a.Hash)); !errors.Is(err, ErrRefused) ||
		!strings.Contains(err.Error(), "no agent") {
		t.Fatalf("an agent approved: %v", err)
	}
	out, err := b.sign("ciso", id)
	if err != nil || !out.Done || out.Alone {
		t.Fatalf("the acceptor was refused: %+v %v", out, err)
	}
	e, err := b.reg.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	ap := register.ApprovalOf(e.Record)
	if ap.Raised != b.subject("dana") || len(ap.Signers) != 1 || ap.Signers[0].Subject != b.subject("ciso") ||
		ap.Atom != "accept-risk" || ap.Of != 2 || ap.Needed != 1 {
		t.Errorf("the approval does not say who raised and who accepted: %+v", ap)
	}
	if ap.Expires != register.TimeOf(b.clock.Add(365*24*time.Hour)) {
		t.Errorf("a risk acceptance lapses at %v, a year after it was given", ap.Expires.At())
	}
}

// Above the threshold a second approver is needed, a different person, and
// where the policy says the second comes from, it comes from there.
func TestSecondApproverAboveThreshold(t *testing.T) {
	b := newBench(t, holds("ciso", auth.ActAcceptRisk), holds("cfo", auth.ActAcceptRisk))
	id := b.propose("dana", b.risk("R-4", "dana", 4))
	a, _ := b.m.Ask(id)
	if a.Needed != 2 || len(a.Over) != 1 {
		t.Fatalf("an impact of four asks %d approvers (%v)", a.Needed, a.Over)
	}
	out, err := b.sign("ciso", id)
	if err != nil || out.Done || out.Signed != 1 || out.Needed != 2 {
		t.Fatalf("one approver of two wrote the record: %+v %v", out, err)
	}
	if b.reg.Head() != "" {
		t.Fatal("the register holds a decision with one of its two approvals")
	}
	if _, err := b.sign("ciso", id); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "counts once") {
		t.Fatalf("the same person approved twice: %v", err)
	}
	if out, err = b.sign("cfo", id); err != nil || !out.Done {
		t.Fatalf("the second approver did not complete it: %+v %v", out, err)
	}
	e, _ := b.reg.Get(id)
	if ap := register.ApprovalOf(e.Record); len(ap.Signers) != 2 || ap.Needed != 2 || ap.Alone {
		t.Errorf("the approval does not hold its two approvers: %+v", ap)
	}

	// A policy that takes its second approver from the risk function: the
	// head of risk holds no atom and approves as second; another holder of
	// the atom is not who the rule asks for.
	b2 := newBench(t, holds("ciso", auth.ActAcceptRisk), holds("cfo", auth.ActAcceptRisk))
	pol := Default()
	pol.Rules[0].SecondFrom = []string{"risk"}
	pol.Seconds = []Second{{Principal: "head-of-risk", As: "risk"}}
	b2.m.Separation = pol
	id2 := b2.propose("dana", b2.risk("R-5", "dana", 5))
	if _, err := b2.sign("head-of-risk", id2); err != nil {
		t.Fatalf("the head of risk could not approve as second: %v", err)
	}
	if a, _ := b2.m.Ask(id2); a.Of != 3 {
		t.Errorf("a named second is not counted among those eligible: %d", a.Of)
	}
	// Two signatures that are both named seconds, or with no holder of the
	// atom, are not enough; a holder completes it.
	if _, err := b2.sign("cfo", id2); err != nil {
		t.Fatalf("the holder of the atom could not approve beside the head of risk: %v", err)
	}
	if e, err := b2.reg.Get(id2); err != nil || len(register.ApprovalOf(e.Record).Signers) != 2 {
		t.Fatalf("the approval of the second from the risk function was not written: %v", err)
	}
	// The named second may be the one whose signature completes it.
	id4 := b2.propose("dana", b2.risk("R-6b", "dana", 5))
	if _, err := b2.sign("ciso", id4); err != nil {
		t.Fatal(err)
	}
	if out, err := b2.sign("head-of-risk", id4); err != nil || !out.Done {
		t.Fatalf("the head of risk's signature did not complete the approval: %+v %v", out, err)
	}
	id3 := b2.propose("dana", b2.risk("R-6", "dana", 5))
	if _, err := b2.sign("ciso", id3); err != nil {
		t.Fatal(err)
	}
	if _, err := b2.sign("cfo", id3); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "risk") {
		t.Fatalf("a second from outside the risk function completed it: %v", err)
	}
}

// A team of one approves alone, and the record says so, with a review by
// somebody else due; that review is not theirs to make, and approving alone
// waits out the day after another administrator stopped being one.
func TestSingleOperatorRecordsAloneAndReview(t *testing.T) {
	b := newBench(t, holds("solo", auth.ActAcceptRisk))
	b.m.Separation = Default()
	b.m.Separation.Seconds = []Second{{Principal: "adviser", As: "adviser"}}
	b.m.Separation.Rules[0].SecondFrom = []string{"executive"} // the adviser is no second for acceptances
	id := b.propose("solo", b.risk("R-7", "solo", 2))
	a, _ := b.m.Ask(id)
	if a.Of != 1 || !a.AloneFor(b.subject("solo")) {
		t.Fatalf("a team of one is not alone: %d eligible", a.Of)
	}

	removed := &dual.Removal{Principal: "other", At: b.clock.Add(-time.Hour)}
	b.m.Settling = func(time.Time) (*dual.Removal, error) { return removed, nil }
	if _, err := b.sign("solo", id); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "approving alone is refused") {
		t.Fatalf("approving alone went ahead an hour after another administrator left: %v", err)
	}
	b.m.Settling = nil

	out, err := b.sign("solo", id)
	if err != nil || !out.Done || !out.Alone {
		t.Fatalf("the team of one could not approve alone: %+v %v", out, err)
	}
	e, _ := b.reg.Get(id)
	ap := register.ApprovalOf(e.Record)
	if !ap.Alone || ap.Of != 1 || ap.ReviewDue != register.TimeOf(b.clock.Add(30*24*time.Hour)) {
		t.Fatalf("the approval made alone is not recorded so: %+v", ap)
	}
	ix, _ := b.reg.Index()
	if row, ok := ix.Find(register.KindRisk, id); !ok || row.Flags&register.FlagAlone == 0 {
		t.Error("the decision made alone is not flagged in the index")
	}

	held, _ := b.m.Held()
	if len(held) != 1 || held[0].Review != nil || held[0].Overdue {
		t.Fatalf("the decision made alone is not shown owing its review: %+v", held)
	}
	review := func(who string) error {
		_, err := b.m.Review(b.person(who), id, "upheld", b.proofFor(who, ForReview, ap.Surface))
		return err
	}
	if err := review("solo"); !errors.Is(err, ErrRefused) {
		t.Fatalf("the person who decided alone reviewed their own decision: %v", err)
	}
	if err := review("stranger"); !errors.Is(err, ErrRefused) {
		t.Fatalf("somebody neither eligible nor named reviewed it: %v", err)
	}
	// An approval's signature is not a review's.
	if _, err := b.m.Review(b.person("adviser"), id, "upheld", b.proofFor("adviser", ForApproval, ap.Surface)); err == nil {
		t.Fatal("an approval's signature was taken for a review")
	}
	if err := review("adviser"); err != nil {
		t.Fatalf("the adviser named in the policy could not review it: %v", err)
	}
	if err := review("adviser"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a decision was reviewed twice: %v", err)
	}
	held, _ = b.m.Held()
	if held[0].Review == nil || held[0].Review.Outcome != "upheld" || held[0].Review.Reviewer != b.subject("adviser") {
		t.Errorf("the review is not shown: %+v", held[0].Review)
	}
	if len(b.audited(AuditReviewed)) != 1 {
		t.Error("the review is not in the audit log")
	}
}

// An approval made alone whose review has not come by the day it was due is
// a problem, and so is an approval that has lapsed.
func TestOverdueCompensatingReviewIsPostureProblemInTheModule(t *testing.T) {
	b := newBench(t, holds("solo", auth.ActAcceptRisk))
	id := b.propose("solo", b.risk("R-8", "solo", 2))
	if _, err := b.sign("solo", id); err != nil {
		t.Fatal(err)
	}
	if overdue, lapsed, _ := b.m.Problems(); len(overdue)+len(lapsed) != 0 {
		t.Fatalf("a review due in thirty days is a problem today: %+v %+v", overdue, lapsed)
	}
	b.clock = b.clock.Add(31 * 24 * time.Hour)
	overdue, _, err := b.m.Problems()
	if err != nil || len(overdue) != 1 || overdue[0].Record != id {
		t.Fatalf("the review a day overdue is not a problem: %+v %v", overdue, err)
	}
	b.clock = b.clock.Add(340 * 24 * time.Hour)
	if _, lapsed, _ := b.m.Problems(); len(lapsed) != 1 {
		t.Fatalf("a year on, the acceptance has not lapsed: %+v", lapsed)
	}
}

// Whoever approves signed in with a method that cannot be phished: a
// passkey, or a single sign-on whose provider said it used one. A single
// sign-on that said only "mfa" is asked for a passkey first.
func TestAmrMfaCannotApprove(t *testing.T) {
	b := newBench(t, holds("ciso", auth.ActAcceptRisk))
	id := b.propose("dana", b.risk("R-9", "dana", 2))
	a, _ := b.m.Ask(id)
	sso := b.person("ciso")
	sso.Methods = []string{auth.MethodSSO}
	if _, err := b.m.Sign(sso, id, b.proofFor("ciso", ForApproval, a.Hash)); !errors.Is(err, ErrRefused) ||
		!strings.Contains(err.Error(), "can be phished") {
		t.Fatalf("a single sign-on that said only mfa approved: %v", err)
	}
	sso.Methods = []string{auth.MethodSSO, auth.MethodSSOPhishingResistant}
	if out, err := b.m.Sign(sso, id, b.proofFor("ciso", ForApproval, a.Hash)); err != nil || !out.Done {
		t.Fatalf("a single sign-on its provider said resisted phishing could not approve: %v", err)
	}
	if !auth.PhishingResistant([]string{auth.MethodSSO, auth.MethodPasskey}) || auth.PhishingResistant([]string{auth.MethodSSO}) {
		t.Error("PhishingResistant is wrong about which sign-ins cannot be phished")
	}
}

// An administrator at the store's console approves by typing back the hash
// they were shown, and the approval says it was given that way.
func TestTheConsoleApprovesByTheHashTypedBack(t *testing.T) {
	b := newBench(t, holds("root-admin", auth.ActAcceptRisk))
	id := b.propose("dana", b.risk("R-10", "dana", 2))
	a, _ := b.m.Ask(id)
	console := b.person("root-admin")
	console.Console, console.Methods = true, nil
	other, _ := Challenge(ForApproval, a.Hash, nonce(t))
	if _, err := b.m.Sign(console, id, Proof{Console: &ConsoleProof{Typed: register.Digest("sha256:" + strings.Repeat("0", 64))}}); !errors.Is(err, ErrOtherSurface) {
		t.Fatalf("a hash that is not the surface's was taken at the console: %v", err)
	}
	if _, err := b.m.Sign(console, id, Proof{Passkey: b.key("root-admin").prove(t, other)}); !errors.Is(err, ErrRefused) {
		t.Fatalf("the console was taken for a passkey: %v", err)
	}
	out, err := b.m.Sign(console, id, Proof{Console: &ConsoleProof{Typed: a.Hash, Credential: "cli"}})
	if err != nil || !out.Done {
		t.Fatalf("the console could not approve: %v", err)
	}
	e, _ := b.reg.Get(id)
	if s := register.ApprovalOf(e.Record).Signers[0]; s.Method != "console" {
		t.Errorf("the console's approval says it was given by %q", s.Method)
	}
}

// Approvals expire: an acceptance after its term, an exception's with the
// exception, and a request still waiting for its second approver after the
// policy's days, with the signature it gathered.
func TestApprovalsExpire(t *testing.T) {
	b := newBench(t, holds("ciso", auth.ActApproveException), holds("cfo", auth.ActApproveException))
	starts := register.TimeOf(b.clock)
	ex := register.Exception{Ref: "EX-1", About: "c0000000000000000000000000000001", Reason: register.Text("sha256:" + strings.Repeat("a", 64)),
		Owner: b.subject("owner"), Starts: starts, Expires: starts + 60*86400}
	id := b.propose("dana", ex)
	if _, err := b.sign("ciso", id); err != nil {
		t.Fatal(err)
	}
	e, err := b.reg.Get(id)
	if err != nil {
		t.Fatalf("a sixty-day exception was not granted by one approver: %v", err)
	}
	if ap := register.ApprovalOf(e.Record); ap.Expires != ex.Expires {
		t.Errorf("the exception's approval lapses at %v, not with the exception", ap.Expires.At())
	}

	long := ex
	long.Ref, long.Expires = "EX-2", starts+120*86400
	id2 := b.propose("dana", long)
	if out, err := b.sign("ciso", id2); err != nil || out.Done {
		t.Fatalf("a four-month exception was granted by one approver: %+v %v", out, err)
	}
	b.clock = b.clock.Add(15 * 24 * time.Hour)
	if a, _ := b.m.Ask(id2); len(a.Signed) != 0 {
		t.Fatalf("a signature waited past the policy's fourteen days: %+v", a.Signed)
	}
	if out, err := b.sign("cfo", id2); err != nil || out.Done || out.Signed != 1 {
		t.Fatalf("the lapsed signature still counted: %+v %v", out, err)
	}
}

// The register checks an approval against the evidence kept beside the
// store, whoever wrote it: evidence that is not there, or not what its
// digest names, approves nothing.
func TestTheRegisterChecksTheEvidence(t *testing.T) {
	b := newBench(t, holds("ciso", auth.ActAcceptRisk))
	id := b.propose("dana", b.risk("R-11", "dana", 2))
	a, _ := b.m.Ask(id)
	rec := b.risk("R-11", "dana", 2)
	rec.Approval = &register.Approval{Atom: "accept-risk", Rule: "risk-acceptance", Needed: 1, Of: 1, Surface: a.Hash,
		Raised: b.subject("dana"), Signers: []register.Signer{{Subject: b.subject("ciso"), At: register.TimeOf(b.clock),
			Assertion: register.Digest("sha256:" + strings.Repeat("1", 64))}}}
	allow := func(auth.Action, string) error { return nil }
	who := register.Actor{Name: "ciso", Subject: b.subject("ciso"), Kind: audit.KindHuman, May: allow}
	if _, err := b.reg.Put(who, "a test's write", rec); !errors.Is(err, register.ErrInvalid) {
		t.Fatalf("an approval with no evidence behind it was written: %v", err)
	}
	if _, err := b.sign("ciso", id); err != nil {
		t.Fatal(err)
	}
	e, _ := b.reg.Get(id)
	d := register.ApprovalOf(e.Record).Signers[0].Assertion
	path, _ := evidencePath(b.root, d)
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), `"method":"passkey"`, `"method":"console"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEvidence(b.root, d); err == nil {
		t.Fatal("evidence changed after it was kept still reads as the evidence")
	}
	if _, err := os.Stat(filepath.Join(b.root, "approvals", "evidence")); err != nil {
		t.Fatal(err)
	}
}

// An overdue compensating review is a problem in the posture, named by the
// record, until somebody else reviews the decision.
func TestOverdueCompensatingReviewIsPostureProblem(t *testing.T) {
	b := newBench(t, holds("solo", auth.ActAcceptRisk))
	b.m.Separation = Default()
	b.m.Separation.Seconds = []Second{{Principal: "adviser", As: "adviser"}}
	id := b.propose("solo", b.risk("R-12", "solo", 2))
	if _, err := b.sign("solo", id); err != nil {
		t.Fatal(err)
	}
	scan := func() []posture.Finding {
		var out []posture.Finding
		rep := posture.Scan(posture.State{Now: b.clock, Approvals: b.m.Posture()}, nil)
		for _, f := range rep.Findings {
			if strings.HasPrefix(f.Rule, "approval.") {
				out = append(out, f)
			}
		}
		for _, skipped := range rep.Skipped {
			if strings.HasPrefix(skipped, "approval.") {
				t.Fatalf("the approvals were handed over and the rule %s was skipped", skipped)
			}
		}
		return out
	}
	if got := scan(); len(got) != 0 {
		t.Fatalf("a review not yet due is a problem: %+v", got)
	}
	b.clock = b.clock.Add(31 * 24 * time.Hour)
	got := scan()
	if len(got) != 1 || got[0].Rule != "approval.review-overdue" || got[0].Resource != string(id) ||
		!strings.Contains(got[0].Detail, "approved alone") {
		t.Fatalf("the overdue review is not a posture problem: %+v", got)
	}
	e, _ := b.reg.Get(id)
	if _, err := b.m.Review(b.person("adviser"), id, "upheld",
		b.proofFor("adviser", ForReview, register.ApprovalOf(e.Record).Surface)); err != nil {
		t.Fatal(err)
	}
	if got := scan(); len(got) != 0 {
		t.Fatalf("the reviewed decision is still a problem: %+v", got)
	}
	// Not handed over is not looked at, and the posture says so.
	rep := posture.Scan(posture.State{Now: b.clock}, nil)
	skipped := strings.Join(rep.Skipped, " ")
	if !strings.Contains(skipped, "approval.review-overdue") || !strings.Contains(skipped, "approval.lapsed") {
		t.Errorf("approvals nobody looked at were taken for none owed: %v", rep.Skipped)
	}
}
