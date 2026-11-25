// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register/side"
)

// Personal data, by design: who a pseudonym is, the words people wrote and
// the raw files facts were read from, kept beside the register in its side
// store (internal/register/side), and erased from there.
//
// The register holds a person as a pseudonym and free text as a digest,
// and that is a rule of its types (types.go). This file is the other half:
// where the person and the words are, how a surface puts them there and
// reads them back, how long they are kept, and how a person is erased so
// that the register still checks and says what happened.

var (
	// ErrErased is a person who was erased already: the record of it is in
	// the register, there is nothing left to erase, and nothing more is
	// kept about them.
	ErrErased = errors.New("the person was erased already")
)

// EraseAction is the name a person's erasure is recorded under in the
// audit log, beside the register.put of its record.
const EraseAction = "register.erase"

// Side is the register's side store, beside its store and sealed by it.
func (r *Register) Side() *side.Store {
	s := side.Open(filepath.Join(r.Store.Root(), "side"), r.Store)
	s.Now = r.now
	return s
}

// SubjectFor is the pseudonym of a person or an account, by the name the
// systems that name them use, minted the first time they are named. The
// name goes in the subject map and nowhere else.
func (r *Register) SubjectFor(name string, typ SubjectType) (ID, error) {
	if !slices.Contains(typ.Values(), string(typ)) {
		return "", fmt.Errorf("%w: a subject is one of %s, not %q", ErrInvalid, strings.Join(typ.Values(), ", "), clipped(string(typ)))
	}
	id, _, err := r.Side().Enrol(name, string(typ))
	return ID(id), err
}

// Person is who a pseudonym stands for, as the subject map says. It is
// for the privacy officer's work, finding whom to erase; a screen of the
// register shows the pseudonym.
func (r *Register) Person(id ID) (side.Person, error) { return r.Side().Who(string(id)) }

// PutText keeps words a person wrote for a record of kind, about the
// people about names, and returns the Text the record holds in their
// place. It is asked of the policy gate as a write of the kind is: the
// words are part of the record that will name them. Words about somebody
// erased already are refused (ErrErased).
func (r *Register) PutText(by Actor, kind Kind, words string, about ...ID) (Text, error) {
	d, err := r.putSide(by, kind, "text", []byte(words), about)
	return Text(d), err
}

// PutRaw keeps a raw file a record of kind is read from, as PutText keeps
// words, and returns the Digest the record holds.
func (r *Register) PutRaw(by Actor, kind Kind, media string, content []byte, about ...ID) (Digest, error) {
	if !reMedia.MatchString(media) {
		return "", fmt.Errorf("%w: %q is not a media type", ErrInvalid, clipped(media))
	}
	d, err := r.putSide(by, kind, media, content, about)
	return Digest(d), err
}

// reMedia is a media type, as a raw file is named by: a type, a slash and
// a subtype, in lower case.
var reMedia = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,62}/[a-z0-9][a-z0-9.+-]{0,62}$`)

func (r *Register) putSide(by Actor, kind Kind, media string, content []byte, about []ID) (string, error) {
	switch by.Kind {
	case audit.KindHuman, audit.KindService:
	default:
		return "", fmt.Errorf("%w (register.Propose)", ErrModel)
	}
	spec, err := specFor(kind)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := r.gate(by, auth.ActEditDraft, spec.Resource()); err != nil {
		r.audited(by, Ref, audit.Denied, map[string]string{"reason": "authorisation", "kind": spec.Collection})
		return "", err
	}
	people := make([]string, 0, len(about))
	for _, id := range about {
		if !id.Valid() {
			return "", fmt.Errorf("%w: %q is not a pseudonym", ErrInvalid, clipped(string(id)))
		}
		// Nothing more is kept about somebody erased. Their pseudonym
		// stays in the records that named it, and words kept about it now
		// could never be erased with them: a person is erased once.
		if r.erased(id) {
			return "", fmt.Errorf("%w: %s names nobody now, and nothing more is kept about them", ErrErased, id)
		}
		people = append(people, string(id))
	}
	// Kept as a write is: not while nothing can record it, and recorded
	// with what it is, never what it says.
	if r.Audit == nil {
		return "", fmt.Errorf("the register has no audit log to record a write in, so it keeps nothing beside it")
	}
	if r.Ready != nil {
		if err := r.Ready(); err != nil {
			return "", fmt.Errorf("nothing was kept, because the audit log cannot record it: %w", err)
		}
	}
	d, err := r.Side().Put(string(kind), media, content, people...)
	if err != nil {
		return "", err
	}
	if aerr := r.Audit(audit.Record{Action: SideAction, Resource: Area, Outcome: audit.Success, Principal: by.Name,
		Kind: by.Kind, Model: by.Model, Verified: by.Verified,
		Detail: map[string]string{"kind": spec.Collection, "digest": d, "media": media,
			"bytes": strconv.Itoa(len(content)), "about": strconv.Itoa(len(people))}}); aerr != nil {
		return d, fmt.Errorf("%w: %v", ErrUnrecorded, aerr)
	}
	return d, nil
}

// erased reports whether the person behind a pseudonym was erased: the
// register holds the record of it, or the subject map the tombstone.
func (r *Register) erased(id ID) bool {
	if _, err := r.Get(ErasureID(id)); err == nil {
		return true
	}
	return r.Side().SubjectErased(string(id)) != nil
}

// SideAction is the name words or a file kept beside the register are
// recorded under in the audit log.
const SideAction = "register.side"

// What a record names in the side store, as a screen says it.
const (
	// TextHeld is words or a file the side store holds and that check
	// against the digest.
	TextHeld = "held"
	// TextErased is words or a file that were erased: by a person's
	// erasure, or when its retention ended.
	TextErased = "erased"
	// TextNotHeld is a digest this instance's side store holds nothing
	// under: kept elsewhere, or never kept.
	TextNotHeld = "not held here"
	// TextUnreadable is an entry that does not check against its digest,
	// or cannot be opened.
	TextUnreadable = "unreadable"
)

// Held is what the side store holds under a record's digest.
type Held struct {
	State string `json:"state"`
	// Words is the text, when it is held and is words.
	Words string `json:"words,omitempty"`
	// Erased says when and why, when it was erased.
	Erased *side.Erased `json:"erased,omitempty"`
	// Why says what is wrong with an entry that cannot be read.
	Why string `json:"why,omitempty"`
}

// TextOf is the words a record's Text names, or why they are not shown.
func (r *Register) TextOf(t Text) Held { return r.held(string(t), true) }

// RawOf is what the side store holds of a raw file, without the file.
func (r *Register) RawOf(d Digest) Held { return r.held(string(d), false) }

func (r *Register) held(digest string, words bool) Held {
	content, err := r.Side().Get(digest)
	var erased *side.Erased
	switch {
	case err == nil:
		h := Held{State: TextHeld}
		if words {
			h.Words = string(content)
		}
		return h
	case errors.As(err, &erased):
		return Held{State: TextErased, Erased: erased}
	case errors.Is(err, side.ErrNotHeld):
		return Held{State: TextNotHeld}
	}
	return Held{State: TextUnreadable, Why: err.Error()}
}

// What a pseudonym is, as a screen says it.
const (
	SubjectHeld     = "mapped"
	SubjectErased   = "erased"
	SubjectUnmapped = "not in the subject map"
)

// SubjectState says whether the subject map names the person behind a
// pseudonym, or erased them, without saying who they are.
func (r *Register) SubjectState(id ID) Held {
	_, err := r.Side().Who(string(id))
	var erased *side.Erased
	switch {
	case err == nil:
		return Held{State: SubjectHeld}
	case errors.As(err, &erased):
		return Held{State: SubjectErased, Erased: erased}
	case errors.Is(err, side.ErrNoSubject):
		return Held{State: SubjectUnmapped}
	}
	return Held{State: TextUnreadable, Why: err.Error()}
}

// ExpireSide deletes what every kind holding it has kept for as long as its
// retention says, and says how many entries went. The server's upkeep runs
// it every quarter of an hour.
func (r *Register) ExpireSide() (int, error) {
	gone, err := r.Side().Expire(func(kind string) time.Duration { return RetentionOf(Kind(kind)) })
	return len(gone), err
}

// ErasureRequest is what a surface asks Erase for.
type ErasureRequest struct {
	// Subject is the pseudonym of the person to erase.
	Subject ID
	// Basis is the ground it is erased on.
	Basis ErasureBasis
	// RequestedBy is who asked for it: the person themselves, for a
	// request, an objection or a consent withdrawn. Empty is the decider,
	// which the rule that the person who asks is not the one who decides
	// allows only to somebody who is the only one eligible.
	RequestedBy ID
	// Eligible is how many people may decide an erasure, the decider
	// among them, as the surface's policy counts them.
	Eligible int
	// Evidence is the decider's authentication evidence as the surface
	// holds it, bound to the record by the approval's assertion.
	Evidence []byte
	// ReviewDue is when somebody else is to look at an erasure decided by
	// the only person eligible; zero is thirty days after.
	ReviewDue Time
}

// SurfaceOf is the hash of a record as a person deciding it is shown it:
// SHA-256 over its kind and its fields, domain-separated, so an approval of
// one record is not an approval of another.
func SurfaceOf(rec Record) Digest {
	fields, _ := canonicalFields(rec)
	h := sha256.New()
	h.Write([]byte("quilzo/register/surface/v1\x00" + string(rec.Kind()) + "\x00"))
	h.Write(fields)
	return Digest("sha256:" + hex.EncodeToString(h.Sum(nil)))
}

// assertionOf is the digest of a decider's authentication evidence bound
// to the surface they decided.
func assertionOf(surface Digest, by ID, evidence []byte) Digest {
	h := sha256.New()
	h.Write([]byte("quilzo/register/assertion/v1\x00" + string(surface) + "\x00" + string(by) + "\x00"))
	h.Write(evidence)
	return Digest("sha256:" + hex.EncodeToString(h.Sum(nil)))
}

// ErasureID is the identifier of the record of a person's erasure.
func ErasureID(subject ID) ID {
	id, _ := DeriveID(KindErasure, Local, string(subject))
	return id
}

// Erase erases a person: the free text and files about them and the map's
// entry for them, from the side store, and writes the signed Erasure record
// that says so, as one decision of the person erasing.
//
// In one order. The decider is held to who may decide an erasure, and the
// record and its approval to their rules, before anything is deleted, so a
// refusal deletes nothing. Then what is about the person is deleted, and
// the record is written through Put, with its audit entry and receipt, and
// an entry of its own under EraseAction. Nothing in the register is
// changed, so every hash and chain still checks; the pseudonym names
// nobody from then on, and every screen that shows it says so.
func (r *Register) Erase(by Actor, req ErasureRequest) (Receipt, error) {
	spec := kinds[KindErasure]
	if by.Kind != audit.KindHuman {
		r.audited(by, Ref, audit.Denied, map[string]string{"reason": "an erasure is a person's decision"})
		return Receipt{}, fmt.Errorf("%w: an erasure is a person's decision", ErrModel)
	}
	if err := r.gate(by, auth.ActApprove, spec.Resource()); err != nil {
		r.audited(by, Ref, audit.Denied, map[string]string{"reason": "authorisation", "kind": spec.Collection})
		return Receipt{}, err
	}
	if !by.Subject.Valid() {
		return Receipt{}, fmt.Errorf("%w: an erasure is decided by somebody this session names by pseudonym", ErrRefused)
	}
	if !req.Subject.Valid() {
		return Receipt{}, fmt.Errorf("%w: %q is not a pseudonym", ErrInvalid, clipped(string(req.Subject)))
	}
	if e, err := r.Get(ErasureID(req.Subject)); err == nil {
		return Receipt{}, fmt.Errorf("%w on %s; the record is %s", ErrErased,
			e.Record.(Erasure).At.At().Format("2 January 2006"), e.ID)
	}
	s := r.Side()
	_, err := s.Who(string(req.Subject))
	var gone *side.Erased
	mapped := err == nil || errors.As(err, &gone)
	if err != nil && !mapped && !errors.Is(err, side.ErrNoSubject) {
		return Receipt{}, err
	}
	entries, err := s.About(string(req.Subject))
	if err != nil {
		return Receipt{}, err
	}
	if !mapped && len(entries) == 0 {
		return Receipt{}, fmt.Errorf("%w: the subject map names nobody by %s, and nothing is kept about them",
			ErrNotFound, req.Subject)
	}

	rec := Erasure{Subject: req.Subject, Basis: req.Basis, Decider: by.Subject, At: TimeOf(r.now()), Map: mapped,
		Entries: int64(len(entries))}
	kindsOf := map[string]bool{}
	var list []string
	for _, e := range entries {
		list = append(list, e.Digest)
		for k := range e.Kinds {
			kindsOf[k] = true
		}
	}
	rec.Kinds = sortedKeys(kindsOf)
	if len(list) > 0 {
		sort.Strings(list)
		sum := sha256.Sum256([]byte(strings.Join(list, "\n")))
		rec.Erased = Digest("sha256:" + hex.EncodeToString(sum[:]))
	}
	rec.Approval = r.erasureApproval(rec, req)
	// The record is held to everything Put will hold it to, its approval's
	// check of the decider's evidence (Register.Approvals) among them,
	// before anything is deleted: a person erased with no record of it is
	// the one outcome this must not have.
	why := "erasure of a person, on the basis " + string(req.Basis)
	if _, err := r.prepare(Ref, by, why, []Record{rec}); err != nil {
		return Receipt{}, err
	}
	if r.Audit == nil {
		return Receipt{}, fmt.Errorf("the register has no audit log to record an erasure in, so it erases nobody")
	}
	if r.Ready != nil {
		if err := r.Ready(); err != nil {
			return Receipt{}, fmt.Errorf("nobody was erased, because the audit log cannot record it: %w", err)
		}
	}

	if err := s.EraseEntries(entries, side.BasisSubject); err != nil {
		return Receipt{}, err
	}
	if gone == nil && mapped {
		if err := s.EraseSubject(string(req.Subject), string(req.Basis)); err != nil {
			return Receipt{}, err
		}
	}
	rc, err := r.Put(by, why, rec)
	if err != nil && !errors.Is(err, ErrUnrecorded) {
		return rc, fmt.Errorf("the person's data was erased and the record of it was not written: %w", err)
	}
	if aerr := r.Audit(audit.Record{Action: EraseAction, Resource: Area, Outcome: audit.Success, Principal: by.Name,
		Kind: by.Kind, Model: by.Model, Verified: by.Verified,
		Detail: map[string]string{"subject": string(req.Subject), "basis": string(req.Basis),
			"entries": strconv.Itoa(len(entries)), "receipt": string(rc.Digest)}}); aerr != nil && err == nil {
		err = fmt.Errorf("%w: %v", ErrUnrecorded, aerr)
	}
	return rc, err
}

// erasureApproval is the decider's approval of an erasure as shown: the
// one approver needed, the person who asked as the one who raised it, and
// the decider's authentication evidence bound to the record's hash.
func (r *Register) erasureApproval(rec Erasure, req ErasureRequest) *Approval {
	raised := req.RequestedBy
	if raised == "" {
		raised = rec.Decider
	}
	surface := SurfaceOf(rec)
	a := &Approval{Atom: "erase-personal-data", Rule: "requester-is-not-decider", Needed: 1, Of: max(req.Eligible, 1),
		Surface: surface, Raised: raised,
		Signers: []Signer{{Subject: rec.Decider, At: rec.At, Assertion: assertionOf(surface, rec.Decider, req.Evidence)}}}
	if a.Of == 1 {
		a.Rule, a.Alone, a.ReviewDue = "single-operator", true, req.ReviewDue
		if a.ReviewDue == 0 {
			a.ReviewDue = rec.At + 30*24*60*60
		}
	}
	return a
}
