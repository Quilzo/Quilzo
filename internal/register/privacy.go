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

// migrations move the maps of people that modules kept beside the store,
// before the subject map was the one map, into it.
var migrations []func(*Register) error

// MigrateWith adds the move of a module's older map of people, or of words
// it kept, into the side store, which every register runs as it is opened.
// It is called from the module's init, and each move is idempotent: a
// store moved already, or one that never had the older file, has nothing
// to move, and finding that out is a look at whether a file is there.
//
// The approvals module kept who each pseudonym was in approvals/people.json,
// and the programme in programme/subjects and programme/text, beside a
// subject map that named the same people by other pseudonyms. One person
// was then three people, and the person who raised a decision approved it
// as somebody the register could not tell from anybody else.
func MigrateWith(f func(*Register) error) { migrations = append(migrations, f) }

// Unmerged is why an older map of people beside the store could not be
// moved into the subject map when the register was opened, or nil.
func (r *Register) Unmerged() error { return r.unmerged }

// SubjectFor is the pseudonym of a person or an account, by the name the
// systems that name them use, minted the first time they are named. The
// name goes in the subject map and nowhere else.
func (r *Register) SubjectFor(name string, typ SubjectType) (ID, error) {
	if r.unmerged != nil {
		return "", fmt.Errorf("an older map of people beside the store could not be moved into the subject map, so "+
			"nobody is given a pseudonym until it is: %w", r.unmerged)
	}
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

// ErasureRequest is what a surface raises an erasure with.
type ErasureRequest struct {
	// Subject is the pseudonym of the person to erase.
	Subject ID
	// Basis is the ground it is erased on.
	Basis ErasureBasis
	// RequestedBy is who asked for it: the person themselves, for a
	// request, an objection or a consent withdrawn, or somebody else the
	// subject map names. Empty is whoever enters it, asking themselves.
	RequestedBy ID
}

// ErasureID is the identifier of the record of a person's erasure.
func ErasureID(subject ID) ID {
	id, _ := DeriveID(KindErasure, Local, string(subject))
	return id
}

// erasing is what an erasure of a person deletes, as it stands now: their
// other pseudonyms, whether the map names them, and the entries about any
// of them.
type erasing struct {
	also    []ID
	mapped  bool
	gone    map[ID]bool
	entries []side.Entry
}

// erasingOf is what erasing the person behind a pseudonym would delete.
func (r *Register) erasingOf(subject ID) (erasing, error) {
	s := r.Side()
	out := erasing{gone: map[ID]bool{}}
	_, err := s.Who(string(subject))
	var gone *side.Erased
	switch {
	case err == nil:
		out.mapped = true
		others, err := s.Others(string(subject))
		if err != nil {
			return out, err
		}
		for _, o := range others {
			out.also = append(out.also, ID(o))
		}
		sort.Slice(out.also, func(i, j int) bool { return out.also[i] < out.also[j] })
	case errors.As(err, &gone):
		out.mapped, out.gone[subject] = true, true
	case !errors.Is(err, side.ErrNoSubject):
		return out, err
	}
	seen := map[string]bool{}
	for _, id := range append([]ID{subject}, out.also...) {
		entries, err := s.About(string(id))
		if err != nil {
			return out, err
		}
		for _, e := range entries {
			if !seen[e.Digest] {
				seen[e.Digest] = true
				out.entries = append(out.entries, e)
			}
		}
	}
	return out, nil
}

// record is the erasure a request raises, holding what would go.
func (x erasing) record(subject ID, basis ErasureBasis) Erasure {
	rec := Erasure{Subject: subject, Basis: basis, Map: x.mapped, Entries: int64(len(x.entries)), Also: x.also}
	kindsOf := map[string]bool{}
	var list []string
	for _, e := range x.entries {
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
	return rec
}

// RaiseErasure raises a person's erasure as a request, to wait on the
// proposals ref for somebody to decide it through the approvals module. It
// is raised by the person who asked, or entered by somebody on behalf of
// whoever asked, and the record says which: the request is recorded, with
// who entered it, and never a name typed in for somebody else. It names
// what would go, so the person deciding it decides that and nothing else.
//
// Nothing is deleted here. A person erased already is ErrErased, and one
// the side store holds nothing about is ErrNotFound.
func (r *Register) RaiseErasure(by Actor, req ErasureRequest) (Receipt, ID, error) {
	if by.Kind != audit.KindHuman {
		r.audited(by, ProposalsRef, audit.Denied, map[string]string{"reason": "an erasure is asked for by a person"})
		return Receipt{}, "", fmt.Errorf("%w: an erasure is asked for by a person", ErrModel)
	}
	if !by.Subject.Valid() {
		return Receipt{}, "", fmt.Errorf("%w: an erasure is entered by somebody this session names by pseudonym", ErrRefused)
	}
	if r.unmerged != nil {
		return Receipt{}, "", fmt.Errorf("an older map of people beside the store is not in the subject map yet, so "+
			"nobody is erased from it until it is: %w", r.unmerged)
	}
	if !req.Subject.Valid() {
		return Receipt{}, "", fmt.Errorf("%w: %q is not a pseudonym", ErrInvalid, clipped(string(req.Subject)))
	}
	if e, err := r.Get(ErasureID(req.Subject)); err == nil {
		return Receipt{}, "", fmt.Errorf("%w on %s; the record is %s", ErrErased,
			e.Record.(Erasure).At.At().Format("2 January 2006"), e.ID)
	}
	asked := req.RequestedBy
	switch {
	case asked == "":
		asked = by.Subject
	case !asked.Valid():
		return Receipt{}, "", fmt.Errorf("%w: who asked for it is a pseudonym, and %q is not one", ErrInvalid, clipped(string(asked)))
	case asked != req.Subject && asked != by.Subject:
		// Somebody else asked: the request is theirs only if the subject
		// map names them, so a pseudonym made up for the line is no
		// request.
		if st := r.SubjectState(asked); st.State != SubjectHeld {
			return Receipt{}, "", fmt.Errorf("%w: the subject map names nobody by %s, so nobody it names asked for this",
				ErrInvalid, asked)
		}
	}
	x, err := r.erasingOf(req.Subject)
	if err != nil {
		return Receipt{}, "", err
	}
	if !x.mapped && len(x.entries) == 0 {
		return Receipt{}, "", fmt.Errorf("%w: the subject map names nobody by %s, and nothing is kept about them",
			ErrNotFound, req.Subject)
	}
	rec := x.record(req.Subject, req.Basis)
	rec.RequestedBy = asked
	if asked != by.Subject {
		rec.EnteredBy = by.Subject
	}
	rc, err := r.Propose(by, "erasure of a person, on the basis "+string(req.Basis), rec)
	return rc, ErasureID(req.Subject), err
}

// erase is an erasure accepted: the person decided erased, through
// AcceptWith, with the approval of whoever decided it.
//
// In one order. What is about the person is worked out again, and an
// erasure whose request no longer says what would go is refused, because
// what was approved is not what would be deleted: raised again, it is
// approved as it stands. The record and its approval are held to every
// rule Put holds them to, the approval's surface and its authentication
// evidence among them, before anything is deleted, so a refusal deletes
// nothing. Then what is about the person is deleted, the map's entries for
// them go, and the record is written through Put, with its audit entry and
// receipt, and an entry of its own under EraseAction. Nothing in the
// register is changed, so every hash and chain still checks; the pseudonym
// names nobody from then on, and every screen that shows it says so.
func (r *Register) erase(by Actor, p Proposal, a *Approval) (Receipt, error) {
	proposed, ok := p.Record.(Erasure)
	if !ok {
		return Receipt{}, fmt.Errorf("%w: the proposal is not an erasure", ErrInvalid)
	}
	x, err := r.erasingOf(proposed.Subject)
	if err != nil {
		return Receipt{}, err
	}
	now := x.record(proposed.Subject, proposed.Basis)
	if now.Map != proposed.Map || now.Entries != proposed.Entries || now.Erased != proposed.Erased ||
		!slices.Equal(now.Kinds, proposed.Kinds) || !slices.Equal(now.Also, proposed.Also) {
		return Receipt{}, fmt.Errorf("%w: what is kept about the person has changed since their erasure was raised, so "+
			"what was approved is not what would be deleted; raise it again, and it is approved as it stands", ErrInvalid)
	}
	rec := withApproval(proposed, a)
	accepter, resource := by, kinds[KindErasure].Resource()
	accepter.May = func(act auth.Action, res string) error {
		if act == auth.ActEditDraft && res == resource {
			return nil
		}
		return by.May(act, res)
	}
	why := acceptedWhy(p.Why)
	// The record is held to everything Put will hold it to, its
	// approval's surface and evidence among them, before anything is
	// deleted: a person erased with no record of it is the one outcome
	// this must not have.
	if _, err := r.prepare(Ref, accepter, why, []Record{rec}); err != nil {
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
	s := r.Side()
	if err := s.EraseEntries(x.entries, side.BasisSubject); err != nil {
		return Receipt{}, err
	}
	for _, id := range append([]ID{proposed.Subject}, x.also...) {
		if x.gone[id] {
			continue
		}
		if err := s.EraseSubject(string(id), string(proposed.Basis)); err != nil && !errors.Is(err, side.ErrNoSubject) {
			var already *side.Erased
			if !errors.As(err, &already) {
				return Receipt{}, err
			}
		}
	}
	rc, err := r.Put(accepter, why, rec)
	if err != nil && !errors.Is(err, ErrUnrecorded) {
		return rc, fmt.Errorf("the person's data was erased and the record of it was not written: %w", err)
	}
	if derr := r.drop(p, "accepted"); derr != nil && err == nil {
		err = derr
	}
	if aerr := r.Audit(audit.Record{Action: EraseAction, Resource: Area, Outcome: audit.Success, Principal: by.Name,
		Kind: by.Kind, Model: by.Model, Verified: by.Verified,
		Detail: map[string]string{"subject": string(proposed.Subject), "basis": string(proposed.Basis),
			"entries": strconv.Itoa(len(x.entries)), "receipt": string(rc.Digest)}}); aerr != nil && err == nil {
		err = fmt.Errorf("%w: %v", ErrUnrecorded, aerr)
	}
	if derr := r.audit2(by, audit.Success, map[string]string{"decision": "accepted", "id": string(p.ID),
		"kind": kinds[KindErasure].Collection, "commit": rc.Commit}); derr != nil && err == nil {
		err = fmt.Errorf("%w: %v", ErrUnrecorded, derr)
	}
	return rc, err
}
