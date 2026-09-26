// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package huddle

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/groupkey"
)

// SecretBits is how much entropy a link carries.
//
// Zoom's meeting identifiers are nine to eleven digits, which is about
// thirty-six bits, and researchers predicted four percent of them by
// guessing. This is 160, which makes guessing arithmetic rather than
// research. It is also the least interesting of the protections here: see
// the package comment on what a valid link actually gets somebody.
const SecretBits = 160

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Invitation is a capability to knock at a call.
//
// It is not a key and it is not a seat. What it authorises is an arrival —
// after which the call's admission rule decides whether that arrival waits
// in the lobby or is committed into the group. The distinction is the whole
// design: a link that leaks buys a knock, not a meeting.
//
// The call keeps only a hash of the secret. Whoever holds the state of a
// call — a server, a backup, somebody reading a log — cannot turn it back
// into a working link, which is the same reason a password file holds
// hashes.
type Invitation struct {
	Call string `json:"call"`
	// ID names the invitation so it can be revoked without naming its
	// secret out loud.
	ID     string    `json:"id"`
	Digest string    `json:"digest"`
	Issued time.Time `json:"issued"`
	By     string    `json:"by"`

	// Expires is required. An invitation with no end is a credential, and
	// the meeting link that still worked a year later is a genre of
	// incident, not an accident.
	Expires time.Time `json:"expires"`
	// Uses left. Zero means spent.
	Uses int `json:"uses"`
	// For binds the invitation to one person. When set, whoever presents it
	// must be that name, so a forwarded link is useless — which is what
	// people already assume a personal invitation means.
	For string `json:"for,omitempty"`
	// Admission overrides the call's rule for this invitation only, which
	// is how "let this one person straight in" stops meaning "unlock the
	// call".
	Admission Admission `json:"admission,omitempty"`

	Revoked bool   `json:"revoked,omitempty"`
	Note    string `json:"note,omitempty"`
}

// MaxLife caps how long an invitation can be valid.
//
// A working day. A link for a recurring meeting is a different object with
// a different set of questions attached, and conflating the two is how the
// one-off call from March is still reachable in December.
const MaxLife = 12 * time.Hour

// Invite issues a link.
//
// The secret is returned once and never stored. Everything after this call
// works from the digest.
func (c *Call) Invite(by int, life time.Duration, at time.Time,
	opts ...InviteOption) (secret string, inv Invitation, err error) {
	m, err := c.moderator(by)
	if err != nil {
		return "", Invitation{}, err
	}
	if life <= 0 {
		return "", Invitation{}, fmt.Errorf(
			"an invitation needs an end; how long is this call?")
	}
	if life > MaxLife {
		return "", Invitation{}, fmt.Errorf(
			"%s is longer than an invitation lasts. The cap is %s, because "+
				"a link that outlives its meeting is a credential nobody "+
				"is managing", plainly(life), plainly(MaxLife))
	}
	raw := make([]byte, SecretBits/8)
	if _, err := rand.Read(raw); err != nil {
		return "", Invitation{}, err
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return "", Invitation{}, err
	}
	secret = encoding.EncodeToString(raw)
	inv = Invitation{
		Call: c.ID, ID: hex.EncodeToString(id), Digest: digest(c.ID, secret),
		Issued: at.UTC(), By: m.Name, Expires: at.UTC().Add(life), Uses: 1,
	}
	for _, o := range opts {
		o(&inv)
	}
	if inv.Uses < 1 {
		return "", Invitation{}, fmt.Errorf(
			"an invitation good for no uses is not an invitation")
	}
	c.Invites = append(c.Invites, inv)
	c.note(m.Index, "invited", m.Name, at)
	return secret, inv, nil
}

// InviteOption narrows an invitation.
type InviteOption func(*Invitation)

// ForPerson binds an invitation to one name, so forwarding it achieves
// nothing.
func ForPerson(name string) InviteOption {
	return func(i *Invitation) { i.For = strings.TrimSpace(name) }
}

// Reusable lets an invitation admit several people, which is what a link
// posted in a channel has to be.
func Reusable(n int) InviteOption {
	return func(i *Invitation) { i.Uses = n }
}

// LetStraightIn skips the lobby for this invitation only.
func LetStraightIn() InviteOption {
	return func(i *Invitation) { i.Admission = Straight }
}

// Because records why an invitation exists.
func Because(note string) InviteOption {
	return func(i *Invitation) { i.Note = strings.TrimSpace(note) }
}

// digest binds a secret to its call, so a secret from one call cannot be
// presented at another even if the same bytes turned up in both.
func digest(call, secret string) string {
	h := sha256.New()
	h.Write([]byte(call))
	h.Write([]byte{0})
	h.Write([]byte(secret))
	return hex.EncodeToString(h.Sum(nil))
}

// Revoke kills an invitation by its identifier.
func (c *Call) Revoke(id string, by int, at time.Time) error {
	m, err := c.moderator(by)
	if err != nil {
		return err
	}
	for i := range c.Invites {
		if c.Invites[i].ID != id {
			continue
		}
		if c.Invites[i].Revoked {
			return nil
		}
		c.Invites[i].Revoked = true
		c.note(m.Index, "revoked an invitation", m.Name, at)
		return nil
	}
	return fmt.Errorf("no invitation %s", id)
}

// Knocking is somebody at the door.
//
// They hold no group secret, so they hear nothing. This is not the server
// declining to forward them media: there is no key with which the media
// would mean anything, which is why the lobby holds whatever the server does.
type Knocking struct {
	Name   string          `json:"name"`
	Member groupkey.Member `json:"member"`
	At     time.Time       `json:"at"`
	Invite string          `json:"invite"`
	Note   string          `json:"note,omitempty"`
	seq    uint64
}

// Present offers an invitation and asks to come in.
//
// straight says no moderator has to decide. It does not say the arrival is
// in the call: either way they are in the lobby holding no group secret
// until somebody commits them, because there is no path to a key that does
// not go through a commit. That is the difference between this lobby and a
// waiting room — a waiting room is the server declining to forward media,
// and this is media that would not mean anything if it arrived.
func (c *Call) Present(secret, name string, who groupkey.Member,
	at time.Time) (straight bool, err error) {
	if strings.TrimSpace(name) == "" {
		return false, fmt.Errorf("an arrival needs a name")
	}
	if err := who.Validate(); err != nil {
		return false, err
	}
	if _, taken := c.Named(name); taken {
		return false, fmt.Errorf("somebody called %s is already in this "+
			"call. Two people under one name is how a moderation decision "+
			"lands on the wrong one", name)
	}
	inv, err := c.match(secret, name, at)
	if err != nil {
		return false, err
	}

	rule := c.Policy.Admission
	if inv.Admission != "" {
		rule = inv.Admission
	}
	if rule == Closed {
		return false, fmt.Errorf("this call is locked")
	}
	inv.Uses--
	for i := range c.Invites {
		if c.Invites[i].ID == inv.ID {
			c.Invites[i].Uses = inv.Uses
		}
	}
	c.Waiting = append(c.Waiting, Knocking{
		Name: name, Member: who, At: at.UTC(), Invite: inv.ID,
		seq: c.next(),
	})
	return rule == Straight, nil
}

// match finds the invitation a secret belongs to, in constant time against
// every live one.
//
// Constant time because the alternative is a timing oracle that tells an
// attacker when they have the first bytes right, and an invitation is
// exactly the kind of thing somebody will try a million times.
func (c *Call) match(secret, name string, at time.Time) (Invitation, error) {
	want := digest(c.ID, secret)
	found := -1
	for i, inv := range c.Invites {
		if subtle.ConstantTimeCompare([]byte(inv.Digest),
			[]byte(want)) == 1 {
			found = i
		}
	}
	if found < 0 {
		return Invitation{}, fmt.Errorf("that invitation is not for this call")
	}
	inv := c.Invites[found]
	switch {
	case inv.Revoked:
		return Invitation{}, fmt.Errorf("that invitation was revoked")
	case !at.Before(inv.Expires):
		return Invitation{}, fmt.Errorf("that invitation expired %s ago",
			plainly(at.Sub(inv.Expires)))
	case inv.Uses < 1:
		return Invitation{}, fmt.Errorf("that invitation has been used")
	case inv.For != "" && inv.For != name:
		return Invitation{}, fmt.Errorf("that invitation is %s's, and "+
			"binding it to them is the only reason forwarding it does "+
			"nothing", inv.For)
	}
	return inv, nil
}

// Admit lets somebody in from the lobby.
//
// Returns the change a host must commit through internal/groupkey. Nothing
// here gives anybody a key: this package decides who should be in the
// group, and the group decides what that is worth.
func (c *Call) Admit(name string, by int, role Role,
	at time.Time) (groupkey.Change, error) {
	m, err := c.moderator(by)
	if err != nil {
		return groupkey.Change{}, err
	}
	if !role.Known() || role == Host {
		return groupkey.Change{}, fmt.Errorf(
			"admit somebody as a cohost, speaker or listener")
	}
	for i, k := range c.Waiting {
		if k.Name != name {
			continue
		}
		c.Waiting = append(c.Waiting[:i], c.Waiting[i+1:]...)
		c.note(m.Index, "admitted "+name, m.Name, at)
		return groupkey.Change{Kind: groupkey.Add, Member: k.Member}, nil
	}
	return groupkey.Change{}, fmt.Errorf("nobody called %s is waiting", name)
}

// Seated records that an admitted arrival came back with an index.
//
// Separate from Admit because the index is the group's to assign: the
// commit decides which slot they land in, and inventing one here would be
// this package guessing at the other's arithmetic.
func (c *Call) Seated(name string, index int, role Role, at time.Time) error {
	if _, taken := c.Seat(index); taken {
		return fmt.Errorf("index %d is already seated", index)
	}
	c.Seats = append(c.Seats, &Seat{
		Index: index, Name: name, Role: role, Joined: at.UTC(),
	})
	return nil
}

// Turn away removes somebody from the lobby without admitting them.
func (c *Call) TurnAway(name string, by int, at time.Time) error {
	m, err := c.moderator(by)
	if err != nil {
		return err
	}
	for i, k := range c.Waiting {
		if k.Name != name {
			continue
		}
		c.Waiting = append(c.Waiting[:i], c.Waiting[i+1:]...)
		c.note(m.Index, "turned away "+name, m.Name, at)
		return nil
	}
	return fmt.Errorf("nobody called %s is waiting", name)
}

// Eject removes somebody from the call.
//
// The only Cryptographic control here. It returns the change to commit, and
// once that commit lands the person is not being kept out by anybody's
// cooperation: the epoch secret was never encapsulated to them.
func (c *Call) Eject(index, by int, at time.Time) (groupkey.Change, error) {
	m, err := c.moderator(by)
	if err != nil {
		return groupkey.Change{}, err
	}
	s, ok := c.Seat(index)
	if !ok {
		return groupkey.Change{}, fmt.Errorf("index %d is not in this call",
			index)
	}
	if s.Role == Host {
		return groupkey.Change{}, fmt.Errorf(
			"%s is the host. Pass the chair first, so the call still has "+
				"somebody who can end it", s.Name)
	}
	if s.Index == m.Index {
		return groupkey.Change{}, fmt.Errorf("leaving is not ejecting " +
			"yourself; the difference matters in the record afterwards")
	}
	for i, e := range c.Seats {
		if e.Index == index {
			c.Seats = append(c.Seats[:i], c.Seats[i+1:]...)
			break
		}
	}
	c.dropShares(index)
	c.note(index, "ejected by "+m.Name, m.Name, at)
	return groupkey.Change{Kind: groupkey.Remove, Index: index}, nil
}

// Lock closes the call to new arrivals.
//
// Cryptographic, because admission needs a commit and a locked call makes
// none. The lobby is emptied rather than left holding people who will never
// be let in.
func (c *Call) Lock(by int, at time.Time) error {
	m, err := c.moderator(by)
	if err != nil {
		return err
	}
	c.Policy.Admission = Closed
	c.Waiting = nil
	c.note(m.Index, "locked the call", m.Name, at)
	return nil
}

// Unlock reopens it under a given rule.
func (c *Call) Unlock(by int, rule Admission, at time.Time) error {
	m, err := c.moderator(by)
	if err != nil {
		return err
	}
	if rule == Closed {
		return fmt.Errorf("unlocking to closed is locking")
	}
	next := c.Policy
	next.Admission = rule
	if err := next.Validate(); err != nil {
		return err
	}
	c.Policy = next
	c.note(m.Index, "unlocked the call", m.Name, at)
	return nil
}

// plainly writes a duration the way somebody would say it.
func plainly(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d second(s)", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s)", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s)", int(d.Hours()))
	}
	return fmt.Sprintf("%d day(s)", int(d.Hours()/24))
}
