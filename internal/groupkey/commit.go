// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package groupkey

import (
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
)

// MaxMembers caps a call.
//
// Not an arbitrary number: a flat commit costs about 1.2 KB a member, so
// this is the point at which a membership change costs about a megabyte and
// somebody should be asking whether this is a call or a broadcast. A
// broadcast wants a different design, not a bigger constant.
const MaxMembers = 1024

// Group is one member's view of the call.
//
// "One member's view" is the whole difficulty. Nothing here trusts the
// server to say who is in the group, so every member computes the roster
// themselves from the commits they have seen, and the confirmation tag is
// how they find out whether everybody computed the same thing.
type Group struct {
	ID    string
	Epoch uint64

	// roster is indexed by member index, with a nil for a slot somebody has
	// left. The holes are kept because the SFrame KID encodes the index and
	// reusing an index inside a session would point a receiver at the wrong
	// sender's key.
	roster []*Member
	me     int

	confirmed []byte // transcript up to the last commit's signature
	interim   []byte // that, plus the last confirmation tag
	keys      schedule
}

// Members is everybody currently in the call, in index order.
func (g *Group) Members() []Member {
	out := make([]Member, 0, len(g.roster))
	for _, m := range g.roster {
		if m != nil {
			out = append(out, *m)
		}
	}
	return out
}

// Size is how many people are in the call.
func (g *Group) Size() int { return len(g.Members()) }

// Slots is how many index positions exist, including the ones people have
// left. This is what the KID's sender field has to be wide enough for.
func (g *Group) Slots() int { return len(g.roster) }

// Me is the caller's own index.
func (g *Group) Me() int { return g.me }

// Member looks somebody up by index.
func (g *Group) Member(i int) (Member, bool) {
	if i < 0 || i >= len(g.roster) || g.roster[i] == nil {
		return Member{}, false
	}
	return *g.roster[i], true
}

// rosterHash commits to exactly who is in the group and with which keys.
func (g *Group) rosterHash() []byte {
	h := sha256.New()
	_ = binary.Write(h, binary.BigEndian, uint32(len(g.roster)))
	for i, m := range g.roster {
		_ = binary.Write(h, binary.BigEndian, uint32(i))
		if m == nil {
			h.Write([]byte{0})
			continue
		}
		h.Write([]byte{1})
		for _, f := range [][]byte{[]byte(m.Name), m.KEM, m.Ed25519,
			m.MLDSA} {
			_ = binary.Write(h, binary.BigEndian, uint32(len(f)))
			h.Write(f)
		}
	}
	return h.Sum(nil)
}

// context is the group context for the current epoch.
//
// Everything that has to be the same for two members to agree: the suite,
// the group, where in its history they are, who is in it, and how they got
// here. It is mixed into every epoch secret, so two members who disagree
// about any of it hold different keys and find out immediately rather than
// at the first frame that will not decrypt.
func (g *Group) context() []byte {
	h := sha256.New()
	for _, f := range [][]byte{
		[]byte(Version), []byte(SuiteName), []byte(g.ID),
	} {
		_ = binary.Write(h, binary.BigEndian, uint32(len(f)))
		h.Write(f)
	}
	_ = binary.Write(h, binary.BigEndian, g.Epoch)
	h.Write(g.rosterHash())
	h.Write(g.confirmed)
	return h.Sum(nil)
}

// Create starts a call with one person in it.
func Create(id string, me *Identity) (*Group, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("a call needs an identifier")
	}
	first := me.Member(0)
	if err := first.Validate(); err != nil {
		return nil, err
	}
	g := &Group{ID: id, roster: []*Member{&first}, me: 0}
	// Epoch zero has no commit to extract, because there is nobody to agree
	// with yet. The secret is simply fresh, and everybody who arrives later
	// arrives through a Welcome.
	seed := make([]byte, Nh)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	keys, err := fromJoiner(seed, g.context())
	if err != nil {
		return nil, err
	}
	g.keys = keys
	tag, err := g.confirmationTag()
	if err != nil {
		return nil, err
	}
	g.interim = interimHash(g.confirmed, tag)
	return g, nil
}

// ChangeKind is what a commit does to the roster.
type ChangeKind string

const (
	// Add brings somebody in. They cannot read anything from before.
	Add ChangeKind = "add"
	// Remove takes somebody out. They cannot read anything after.
	Remove ChangeKind = "remove"
	// Update replaces a member's encapsulation key, which is what closes
	// the door behind a compromised device.
	Update ChangeKind = "update"
)

// Change is one alteration to the roster.
type Change struct {
	Kind   ChangeKind `json:"kind"`
	Member Member     `json:"member,omitzero"`
	Index  int        `json:"index,omitempty"`
}

// Wrapped is a secret encapsulated to one member.
type Wrapped struct {
	For    int    `json:"for"`
	Sealed []byte `json:"sealed"`
}

// Commit moves the call to a new epoch.
type Commit struct {
	Group   string   `json:"group"`
	Epoch   uint64   `json:"epoch"` // the epoch it was sent in
	By      int      `json:"by"`
	Changes []Change `json:"changes,omitempty"`
	// Sealed carries the commit secret to everyone in the new roster,
	// including the committer. The committer could keep its own copy in
	// memory and skip a kilobyte; it does not, because then the committer
	// would reach the new epoch by a different path from everybody else,
	// and a second path is a second thing that can disagree with the first.
	Sealed []Wrapped `json:"sealed"`

	Ed25519 []byte `json:"ed25519"`
	MLDSA   []byte `json:"mldsa"`
	// Confirmation proves the sender reached the same epoch secret from the
	// same roster and the same history.
	//
	// It is the second line rather than the first. Each sealed secret is
	// encapsulated under an info string that already contains the roster
	// hash, so a server that rewrites the membership on the way to one
	// member produces ciphertexts that do not open at all — the tag never
	// gets a chance to disagree, because there is no secret to compute it
	// from. What the tag adds is everything the info cannot cover: it
	// closes over this commit's own signature, and it proves the committer
	// actually holds the epoch secret rather than merely having addressed
	// the envelopes correctly.
	Confirmation []byte `json:"confirmation"`
}

// signed is the part of a commit the signature covers.
//
// Everything except the signatures and the confirmation tag: the tag is
// derived from a secret the signer has and the transcript that includes
// this signature, so it cannot be inside what it covers.
func (c *Commit) signed() []byte {
	h := sha256.New()
	for _, f := range [][]byte{[]byte(Version), []byte(c.Group)} {
		_ = binary.Write(h, binary.BigEndian, uint32(len(f)))
		h.Write(f)
	}
	_ = binary.Write(h, binary.BigEndian, c.Epoch)
	_ = binary.Write(h, binary.BigEndian, uint32(c.By))
	_ = binary.Write(h, binary.BigEndian, uint32(len(c.Changes)))
	for _, ch := range c.Changes {
		h.Write([]byte(ch.Kind))
		_ = binary.Write(h, binary.BigEndian, uint32(ch.Index))
		h.Write([]byte(ch.Member.Name))
		h.Write(ch.Member.KEM)
		h.Write(ch.Member.Ed25519)
		h.Write(ch.Member.MLDSA)
	}
	_ = binary.Write(h, binary.BigEndian, uint32(len(c.Sealed)))
	for _, w := range c.Sealed {
		_ = binary.Write(h, binary.BigEndian, uint32(w.For))
		h.Write(w.Sealed)
	}
	return h.Sum(nil)
}

// sealInfo is what each encapsulation is bound to.
//
// The recipient, the committer, the group, the epoch being entered, the
// roster being entered, and the whole history up to this point. A
// ciphertext lifted out of one commit and dropped into another opens to
// nothing, because the info it was sealed under is not the info it would be
// opened under.
//
// It cannot include the new epoch's transcript hash, which covers this
// commit's own signature, which covers these ciphertexts. The previous
// interim hash is in its place, and it pins every epoch up to this one.
func sealInfo(purpose, group string, epoch uint64, rosterHash, interim []byte,
	by, to int) []byte {
	h := sha256.New()
	for _, f := range [][]byte{
		[]byte(Version), []byte(purpose), []byte(group),
	} {
		_ = binary.Write(h, binary.BigEndian, uint32(len(f)))
		h.Write(f)
	}
	_ = binary.Write(h, binary.BigEndian, epoch)
	h.Write(rosterHash)
	h.Write(interim)
	_ = binary.Write(h, binary.BigEndian, uint32(by))
	_ = binary.Write(h, binary.BigEndian, uint32(to))
	return h.Sum(nil)
}

func interimHash(confirmed, tag []byte) []byte {
	h := sha256.New()
	h.Write(confirmed)
	h.Write(tag)
	return h.Sum(nil)
}

func (g *Group) confirmationTag() ([]byte, error) {
	if len(g.keys.confirmation) == 0 {
		return nil, fmt.Errorf("this group has no epoch secret yet")
	}
	m := hmac.New(sha256.New, g.keys.confirmation)
	m.Write(g.confirmed)
	return m.Sum(nil), nil
}

// apply works out the roster a set of changes produces.
//
// Deterministic and order-independent in its effects, so two members
// applying the same commit reach the same roster or the same error.
// Removals first: a commit that removes index 3 and adds somebody must not
// depend on whether the new arrival landed in slot 3.
func (g *Group) applyChanges(changes []Change) ([]*Member, error) {
	next := make([]*Member, len(g.roster))
	copy(next, g.roster)

	for _, c := range changes {
		if c.Kind != Remove {
			continue
		}
		if c.Index < 0 || c.Index >= len(next) || next[c.Index] == nil {
			return nil, fmt.Errorf("there is nobody at index %d to remove",
				c.Index)
		}
		next[c.Index] = nil
	}
	for _, c := range changes {
		if c.Kind != Update {
			continue
		}
		if c.Index < 0 || c.Index >= len(next) {
			return nil, fmt.Errorf("there is nobody at index %d", c.Index)
		}
		old := next[c.Index]
		if old == nil {
			return nil, fmt.Errorf("there is nobody at index %d to update",
				c.Index)
		}
		m := c.Member
		m.Index = c.Index
		if m.Name != old.Name {
			return nil, fmt.Errorf("an update replaces %s's keys, not who "+
				"they are; this one says %s", old.Name, m.Name)
		}
		if err := m.Validate(); err != nil {
			return nil, err
		}
		next[c.Index] = &m
	}
	for _, c := range changes {
		if c.Kind != Add {
			continue
		}
		m := c.Member
		if err := m.Validate(); err != nil {
			return nil, err
		}
		for _, e := range next {
			if e != nil && e.Fingerprint() == m.Fingerprint() {
				return nil, fmt.Errorf("%s is already in this call", m.Name)
			}
		}
		slot := -1
		for i, e := range next {
			if e == nil {
				slot = i
				break
			}
		}
		if slot < 0 {
			slot = len(next)
			next = append(next, nil)
		}
		if slot >= MaxMembers {
			return nil, fmt.Errorf("a call holds at most %d people; past "+
				"that this is a broadcast and wants a different design",
				MaxMembers)
		}
		m.Index = slot
		next[slot] = &m
	}
	for _, c := range changes {
		switch c.Kind {
		case Add, Remove, Update:
		default:
			return nil, fmt.Errorf("%q is not a change; the kinds are add, "+
				"remove and update", c.Kind)
		}
	}
	live := 0
	for _, m := range next {
		if m != nil {
			live++
		}
	}
	if live == 0 {
		return nil, fmt.Errorf("that would empty the call")
	}
	return next, nil
}

// Commit proposes a set of changes and moves the group to a new epoch.
//
// Returns the commit for everybody who was already there, and a Welcome for
// each person being added — two messages because the joiner secret a new
// arrival needs is derived from the group context, which covers this
// commit's own signature. The commit has to exist before the welcome can be
// built, which is also the order in which they are safe to send.
func (g *Group) Commit(me *Identity, changes []Change) (*Commit,
	[]*Welcome, error) {
	if mine, ok := g.Member(g.me); !ok || mine.Name != me.Name {
		return nil, nil, fmt.Errorf("%s is not at index %d of this call",
			me.Name, g.me)
	}
	next, err := g.applyChanges(changes)
	if err != nil {
		return nil, nil, err
	}

	// Who was already here, so they get the commit secret, and who is
	// arriving, so they get a welcome instead.
	joining := map[int]bool{}
	for i, m := range next {
		if m == nil {
			continue
		}
		if i >= len(g.roster) || g.roster[i] == nil ||
			g.roster[i].Fingerprint() != m.Fingerprint() {
			if i < len(g.roster) && g.roster[i] != nil &&
				g.roster[i].Name == m.Name {
				continue // an update: same person, new key, already here
			}
			joining[i] = true
		}
	}

	secret := make([]byte, Nh)
	if _, err := rand.Read(secret); err != nil {
		return nil, nil, err
	}

	after := &Group{
		ID: g.ID, Epoch: g.Epoch + 1, roster: next, me: g.me,
		confirmed: g.confirmed, interim: g.interim,
	}
	rh := after.rosterHash()

	c := &Commit{Group: g.ID, Epoch: g.Epoch, By: g.me, Changes: changes}
	for i, m := range next {
		if m == nil || joining[i] {
			continue
		}
		info := sealInfo("commit", g.ID, after.Epoch, rh, g.interim, g.me, i)
		sealed, err := seal(*m, info, secret)
		if err != nil {
			return nil, nil, err
		}
		c.Sealed = append(c.Sealed, Wrapped{For: i, Sealed: sealed})
	}

	if c.Ed25519, c.MLDSA, err = me.sign(c.signed()); err != nil {
		return nil, nil, err
	}

	// The transcript closes over the signature, then the schedule runs,
	// then the tag closes over the transcript. That order is what makes the
	// tag mean "I reached this epoch from this history with this roster".
	after.confirmed = confirmedHash(g.interim, c.signed(), c.Ed25519, c.MLDSA)
	if after.keys, err = advance(g.keys.init, secret,
		after.context()); err != nil {
		return nil, nil, err
	}
	tag, err := after.confirmationTag()
	if err != nil {
		return nil, nil, err
	}
	c.Confirmation = tag
	after.interim = interimHash(after.confirmed, tag)

	var welcomes []*Welcome
	for i := range joining {
		w, err := after.welcome(me, i, g.interim, rh)
		if err != nil {
			return nil, nil, err
		}
		welcomes = append(welcomes, w)
	}
	return c, welcomes, nil
}

func confirmedHash(interim, signed, edSig, mlSig []byte) []byte {
	h := sha256.New()
	h.Write(interim)
	h.Write(signed)
	h.Write(edSig)
	h.Write(mlSig)
	return h.Sum(nil)
}

func seal(to Member, info, plaintext []byte) ([]byte, error) {
	pk, err := suiteKEM().NewPublicKey(to.KEM)
	if err != nil {
		return nil, err
	}
	return hpke.Seal(pk, suiteKDF(), suiteAEAD(), info, plaintext)
}

func (i *Identity) open(info, sealed []byte) ([]byte, error) {
	return hpke.Open(i.kem, suiteKDF(), suiteAEAD(), info, sealed)
}

// Apply processes a commit and moves this member to the new epoch.
//
// The committer runs this on its own commit too. There is one way into an
// epoch and everybody takes it.
func (g *Group) Apply(c *Commit, me *Identity) error {
	if c.Group != g.ID {
		return fmt.Errorf("that commit is for call %q, not %q", c.Group, g.ID)
	}
	if c.Epoch != g.Epoch {
		return fmt.Errorf("that commit is from epoch %d and this call is at "+
			"epoch %d", c.Epoch, g.Epoch)
	}
	by, ok := g.Member(c.By)
	if !ok {
		return fmt.Errorf("index %d is not in this call, so nothing it "+
			"signs means anything here", c.By)
	}
	if err := by.verify(c.signed(), c.Ed25519, c.MLDSA); err != nil {
		return err
	}

	next, err := g.applyChanges(c.Changes)
	if err != nil {
		return err
	}
	if next[g.me] == nil {
		return fmt.Errorf("that commit removes %s from the call", me.Name)
	}

	after := &Group{
		ID: g.ID, Epoch: g.Epoch + 1, roster: next, me: g.me,
		confirmed: g.confirmed, interim: g.interim,
	}
	rh := after.rosterHash()

	var sealed []byte
	for _, w := range c.Sealed {
		if w.For == g.me {
			sealed = w.Sealed
			break
		}
	}
	if sealed == nil {
		return fmt.Errorf("that commit carries no secret for %s, who is "+
			"still listed in the call. Either it was built from a different "+
			"roster or somebody has edited it", me.Name)
	}
	info := sealInfo("commit", g.ID, after.Epoch, rh, g.interim, c.By, g.me)
	secret, err := me.open(info, sealed)
	if err != nil {
		return fmt.Errorf("the commit secret does not open: %w", err)
	}

	after.confirmed = confirmedHash(g.interim, c.signed(), c.Ed25519, c.MLDSA)
	if after.keys, err = advance(g.keys.init, secret,
		after.context()); err != nil {
		return err
	}
	tag, err := after.confirmationTag()
	if err != nil {
		return err
	}
	if !equal(tag, c.Confirmation) {
		return fmt.Errorf("the confirmation does not match. %s reached a "+
			"different epoch secret from this one, which means the two of "+
			"you do not agree about who is in this call or how it got here",
			by.Name)
	}
	after.interim = interimHash(after.confirmed, tag)

	*g = *after
	return nil
}
