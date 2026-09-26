// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package groupkey

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Welcome is what a new arrival is given.
//
// Everybody already in the call verifies a commit against a history they
// watched happen. Somebody arriving has no history, so there is nothing for
// them to check it against, and this is the one place in the protocol where
// a member has to take somebody's word for something.
//
// What is done about that: the Welcome is signed by the committer, the
// joiner verifies that signature against the key in the roster they are
// being handed — which proves only internal consistency — and then the
// joiner's client shows the epoch authenticator. Two people who compare
// that short string by any means the attacker does not control have
// established that they are in the same call with the same people. The
// package cannot do that comparison; it can make the string available and
// say plainly that it is the part a machine cannot finish.
type Welcome struct {
	Group string `json:"group"`
	Epoch uint64 `json:"epoch"`
	By    int    `json:"by"`
	For   int    `json:"for"`

	// Roster is the whole membership, because a joiner has no other way to
	// learn it and every key in it is about to matter to them.
	Roster []Member `json:"roster"`
	Slots  int      `json:"slots"`

	// Confirmed and Tag let the joiner rebuild the group context and check
	// that the secret they were given produces the tag the group agreed.
	Confirmed []byte `json:"confirmed"`
	Tag       []byte `json:"tag"`

	// Sealed is the joiner secret, which is one step further down the key
	// schedule than the commit secret. That is deliberate: the extraction
	// above it is one-way, so this tells the new arrival nothing about the
	// epoch they were not in.
	Sealed []byte `json:"sealed"`

	Ed25519 []byte `json:"ed25519"`
	MLDSA   []byte `json:"mldsa"`
}

func (w *Welcome) signed() []byte {
	h := sha256.New()
	for _, f := range [][]byte{[]byte(Version), []byte(w.Group)} {
		_ = binary.Write(h, binary.BigEndian, uint32(len(f)))
		h.Write(f)
	}
	_ = binary.Write(h, binary.BigEndian, w.Epoch)
	_ = binary.Write(h, binary.BigEndian, uint32(w.By))
	_ = binary.Write(h, binary.BigEndian, uint32(w.For))
	_ = binary.Write(h, binary.BigEndian, uint32(w.Slots))
	_ = binary.Write(h, binary.BigEndian, uint32(len(w.Roster)))
	for _, m := range w.Roster {
		_ = binary.Write(h, binary.BigEndian, uint32(m.Index))
		for _, f := range [][]byte{[]byte(m.Name), m.KEM, m.Ed25519,
			m.MLDSA} {
			_ = binary.Write(h, binary.BigEndian, uint32(len(f)))
			h.Write(f)
		}
	}
	h.Write(w.Confirmed)
	h.Write(w.Tag)
	h.Write(w.Sealed)
	return h.Sum(nil)
}

// welcome builds the invitation for one new member, from the group state
// after the commit has been applied.
func (g *Group) welcome(me *Identity, to int, interim,
	rosterHash []byte) (*Welcome, error) {
	m, ok := g.Member(to)
	if !ok {
		return nil, fmt.Errorf("nobody is at index %d", to)
	}
	tag, err := g.confirmationTag()
	if err != nil {
		return nil, err
	}
	w := &Welcome{
		Group: g.ID, Epoch: g.Epoch, By: g.me, For: to,
		Roster: g.Members(), Slots: len(g.roster),
		Confirmed: g.confirmed, Tag: tag,
	}
	info := sealInfo("welcome", g.ID, g.Epoch, rosterHash, interim, g.me, to)
	if w.Sealed, err = seal(m, info, g.keys.joiner); err != nil {
		return nil, err
	}
	if w.Ed25519, w.MLDSA, err = me.sign(w.signed()); err != nil {
		return nil, err
	}
	return w, nil
}

// Join builds a group from a Welcome.
//
// interim is the interim transcript hash of the epoch before this one,
// which the committer used when sealing. A joiner cannot derive it, so it
// travels with the welcome — and because it is inside the signature and
// inside the seal info, a server that changes it produces a welcome that
// does not open.
func Join(w *Welcome, interim []byte, me *Identity) (*Group, error) {
	if w == nil {
		return nil, fmt.Errorf("there is no welcome to join with")
	}
	if strings.TrimSpace(w.Group) == "" {
		return nil, fmt.Errorf("that welcome names no call")
	}
	roster := make([]*Member, w.Slots)
	for _, m := range w.Roster {
		if m.Index < 0 || m.Index >= w.Slots {
			return nil, fmt.Errorf("%s is at index %d of a %d-slot roster",
				m.Name, m.Index, w.Slots)
		}
		if roster[m.Index] != nil {
			return nil, fmt.Errorf("two people are at index %d", m.Index)
		}
		if err := m.Validate(); err != nil {
			return nil, err
		}
		e := m
		roster[m.Index] = &e
	}
	by := roster[safeIndex(w.By, w.Slots)]
	if by == nil {
		return nil, fmt.Errorf("the welcome is signed by index %d, who is "+
			"not in the roster it carries", w.By)
	}
	if err := by.verify(w.signed(), w.Ed25519, w.MLDSA); err != nil {
		return nil, err
	}

	mine := roster[safeIndex(w.For, w.Slots)]
	if mine == nil {
		return nil, fmt.Errorf("the welcome is addressed to index %d, who "+
			"is not in the roster", w.For)
	}
	if want := me.Member(w.For); !mine.Same(want) {
		return nil, fmt.Errorf("the roster lists index %d as %q with a "+
			"different set of keys from %s's. Somebody built this welcome "+
			"around a key that is not yours", w.For, mine.Name, me.Name)
	}

	g := &Group{
		ID: w.Group, Epoch: w.Epoch, roster: roster, me: w.For,
		confirmed: w.Confirmed,
	}
	info := sealInfo("welcome", w.Group, w.Epoch, g.rosterHash(), interim,
		w.By, w.For)
	joiner, err := me.open(info, w.Sealed)
	if err != nil {
		return nil, fmt.Errorf("the welcome does not open: %w", err)
	}
	if g.keys, err = fromJoiner(joiner, g.context()); err != nil {
		return nil, err
	}
	tag, err := g.confirmationTag()
	if err != nil {
		return nil, err
	}
	if !equal(tag, w.Tag) {
		return nil, fmt.Errorf("the confirmation does not match. The "+
			"secret in this welcome does not belong to the roster it "+
			"carries, so %s would be in a call with a different set of "+
			"people from the one it describes", me.Name)
	}
	g.interim = interimHash(g.confirmed, tag)
	return g, nil
}

func safeIndex(i, n int) int {
	if i < 0 || i >= n {
		return 0
	}
	return i
}

// Interim is the transcript hash a joiner needs alongside their welcome.
//
// Exposed because it has to travel, and named so that what it is stays
// visible: it is the hash of everything that has happened in the call so
// far. It is not a secret — everybody in the call has it — and it is not
// optional, because it is what the welcome was sealed against.
func (g *Group) Interim() []byte {
	return append([]byte(nil), g.interim...)
}

// Authenticator is a short string every member of an epoch computes
// identically, and nobody outside it can.
//
// The use is out of band: two people read it to each other, or compare it
// somewhere the call is not, and having matched it they know they are in
// the same call with the same roster — even if the signature keys they
// verified each other with were stolen. It changes every epoch, so it is a
// statement about this moment and not about the call.
func (g *Group) Authenticator() string {
	if len(g.keys.authenticator) == 0 {
		return ""
	}
	h := hex.EncodeToString(g.keys.authenticator)
	var out []string
	for i := 0; i+4 <= 20; i += 4 {
		out = append(out, h[i:i+4])
	}
	return strings.Join(out, "-")
}
