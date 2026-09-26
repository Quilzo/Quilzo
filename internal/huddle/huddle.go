// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package huddle is the control plane of a call: who is in it, who may
// speak, who may share, and who decides.
//
// # The one idea
//
// Every product has these controls and every product presents them the same
// way, as a row of buttons that all look equally real. They are not equally
// real. "Remove from meeting" and "mute participant" sit next to each other
// in Zoom's interface and one of them is enforced by arithmetic while the
// other is enforced by the other person's software choosing to cooperate.
// Nothing in the interface says which is which, so when it matters — the
// meeting somebody is disrupting, the call a competitor is sitting in —
// nobody in the room knows what they are actually relying on.
//
// So every control here declares its enforcement, and the three levels are
// the vocabulary of the package:
//
//   - Cryptographic. It holds against a modified client and against a
//     hostile server, because the person it is applied to does not have the
//     key. Removal is the only one, and it is real: internal/groupkey moves
//     the call to an epoch whose secret was never encapsulated to them.
//   - Agreed. Everybody in the call derives the same policy from the same
//     group state, so the server cannot lie about it and every honest
//     client applies it. A modified client can still put bytes on the wire;
//     every honest receiver drops them. Muting and speaking rights are
//     here.
//   - Requested. It is a message to a person. "Please turn your camera on"
//     is not a control and pretending otherwise is how an interface lies.
//
// This is not a smaller claim than the competition makes. It is the same
// claim, made accurately. Zoom cannot hard-mute a modified client either;
// it simply does not say so.
//
// # What a leaked link gets you
//
// Meeting links are the other place the industry is quietly weak. Zoom
// meeting identifiers are nine to eleven digits — about thirty-six bits —
// and researchers predicted four percent of them. An invitation here
// carries 160 bits, which is not the interesting part.
//
// The interesting part is that the link is not the key. Presenting a valid
// invitation puts somebody in the lobby, and the lobby is not a room the
// server keeps them out of: it is a place where they hold no group secret
// and therefore hear nothing, whatever the server does. Getting the key
// requires a host to commit them into the group. So a link that leaks, or
// is forwarded, or outlives its meeting, buys an attacker a knock at a door
// — which is what everybody already believes a waiting room is, and what in
// most products it is not.
package huddle

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Enforcement is what stands behind a control.
type Enforcement string

const (
	// Cryptographic holds against a modified client and a hostile server.
	Cryptographic Enforcement = "cryptographic"
	// Agreed holds against the server and against every honest client.
	Agreed Enforcement = "agreed"
	// Requested is a message to a person.
	Requested Enforcement = "requested"
)

// Why says what a level of enforcement is worth, in the words somebody
// deciding whether to rely on it needs.
func (e Enforcement) Why() string {
	switch e {
	case Cryptographic:
		return "they do not have the key. This holds even if they are " +
			"running software you did not write and the server is against you"
	case Agreed:
		return "everybody in the call derives this from the same group " +
			"state, so the server cannot lie about it and every honest " +
			"client applies it. Somebody running modified software can " +
			"still send; everybody else will drop it"
	case Requested:
		return "this is a message to a person, and they decide. It is in " +
			"the list so that nothing else in the list has to be explained " +
			"away"
	}
	return string(e)
}

// Holds reports whether a control survives a participant who is actively
// working against it.
func (e Enforcement) Holds() bool { return e == Cryptographic }

// Role is what somebody may do without asking.
type Role string

const (
	// Host opened the call and can do anything, including ending it.
	Host Role = "host"
	// Cohost can admit, remove, mute and manage shares. A host's powers
	// without the ability to make another cohost, because a moderation
	// power that can grant itself is not bounded by anything.
	Cohost Role = "cohost"
	// Speaker may talk and share.
	Speaker Role = "speaker"
	// Listener is in the call and not sending.
	Listener Role = "listener"
)

// Roles in order of authority.
var Roles = []Role{Host, Cohost, Speaker, Listener}

func (r Role) rank() int {
	for i, c := range Roles {
		if c == r {
			return len(Roles) - i
		}
	}
	return -1
}

// Known reports whether a role is one of the four.
func (r Role) Known() bool { return r.rank() > 0 }

// AtLeast reports whether a role carries at least another's authority.
func (r Role) AtLeast(o Role) bool { return r.rank() >= o.rank() }

// Moderates reports whether a role may admit, remove and mute.
func (r Role) Moderates() bool { return r.AtLeast(Cohost) }

// Seat is one participant, at the index internal/groupkey gave them.
//
// The index is the join between the two packages and it is not decorative:
// it is what the SFrame KID encodes, so a seat whose index drifted from its
// group member would decrypt somebody else's audio under their name.
type Seat struct {
	Index  int       `json:"index"`
	Name   string    `json:"name"`
	Role   Role      `json:"role"`
	Joined time.Time `json:"joined"`

	// Muted is Agreed, not Cryptographic. See the package comment.
	Muted   bool   `json:"muted,omitempty"`
	MutedBy string `json:"muted_by,omitempty"`
	// Away is the participant's own statement about themselves, which is
	// the only kind of status that is ever accurate.
	Away bool `json:"away,omitempty"`
}

// Admission is how somebody gets in.
type Admission string

const (
	// Knock puts an arrival in the lobby until somebody admits them.
	Knock Admission = "knock"
	// Straight lets a valid invitation in without asking. Convenient, and
	// it means the invitation is the whole of the access control, so it
	// should be used where the link cannot travel.
	Straight Admission = "straight"
	// Closed admits nobody: the call is locked.
	Closed Admission = "closed"
)

// Policy is what the call allows.
type Policy struct {
	Admission Admission `json:"admission"`
	// MaySpeak and MayShare are the lowest role that may do each without
	// being granted it. Agreed, so everybody derives the same answer.
	MaySpeak Role `json:"may_speak"`
	MayShare Role `json:"may_share"`
	// MaxShares caps simultaneous screen shares. Not a technical limit —
	// each share is its own stream under its own key — but a room where
	// nine people are sharing at once is a room where nobody is looking at
	// anything.
	MaxShares int `json:"max_shares"`
}

// DefaultPolicy is what a call gets if nobody says otherwise.
//
// Knocking by default, because the alternative is that a link is the whole
// of the security and links travel. Everybody may speak and share, because
// a working call between colleagues is the common case and a product that
// makes people ask permission to talk has chosen the wrong default for it.
func DefaultPolicy() Policy {
	return Policy{
		Admission: Knock, MaySpeak: Listener, MayShare: Listener,
		MaxShares: 4,
	}
}

// Validate refuses a policy that cannot be applied.
func (p Policy) Validate() error {
	switch p.Admission {
	case Knock, Straight, Closed:
	default:
		return fmt.Errorf("%q is not an admission rule; they are knock, "+
			"straight and closed", p.Admission)
	}
	if !p.MaySpeak.Known() || !p.MayShare.Known() {
		return fmt.Errorf("a policy names roles that exist")
	}
	if p.MaxShares < 1 {
		return fmt.Errorf("a call that allows no shares at all is a policy " +
			"nobody meant to set; set MayShare to host instead")
	}
	return nil
}

// Call is the control state of one call.
//
// It holds no keys and no media. internal/groupkey holds the secrets and
// internal/sframe encrypts with them; this decides who should be in the
// group, and hands back the changes for somebody to commit.
type Call struct {
	ID     string    `json:"id"`
	Topic  string    `json:"topic,omitempty"`
	Opened time.Time `json:"opened"`
	Policy Policy    `json:"policy"`

	Seats   []*Seat      `json:"seats"`
	Waiting []Knocking   `json:"waiting,omitempty"`
	Shares  []Share      `json:"shares,omitempty"`
	Signals []Signal     `json:"signals,omitempty"`
	Invites []Invitation `json:"invites,omitempty"`

	// seq orders everything that happens, so a raised-hand queue is a queue
	// and not a race between clocks.
	seq uint64
}

// Open starts a call with one person in the chair.
func Open(id, topic, host string, at time.Time) (*Call, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("a call needs an identifier")
	}
	if strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("a call needs somebody in it")
	}
	p := DefaultPolicy()
	return &Call{
		ID: id, Topic: strings.TrimSpace(topic), Opened: at.UTC(), Policy: p,
		Seats: []*Seat{{Index: 0, Name: host, Role: Host, Joined: at.UTC()}},
	}, nil
}

func (c *Call) next() uint64 { c.seq++; return c.seq }

// Seat looks somebody up by their group index.
func (c *Call) Seat(index int) (*Seat, bool) {
	for _, s := range c.Seats {
		if s.Index == index {
			return s, true
		}
	}
	return nil, false
}

// Named looks somebody up by name.
func (c *Call) Named(name string) (*Seat, bool) {
	for _, s := range c.Seats {
		if s.Name == name {
			return s, true
		}
	}
	return nil, false
}

// Size is how many people are in the call.
func (c *Call) Size() int { return len(c.Seats) }

// moderator checks that somebody may moderate, and returns them.
func (c *Call) moderator(index int) (*Seat, error) {
	s, ok := c.Seat(index)
	if !ok {
		return nil, fmt.Errorf("index %d is not in this call", index)
	}
	if !s.Role.Moderates() {
		return nil, fmt.Errorf("%s is a %s. Admitting, removing and muting "+
			"are a cohost's, and a call where everybody can remove "+
			"everybody has no moderation, it has a last-writer-wins fight",
			s.Name, s.Role)
	}
	return s, nil
}

// Mute silences somebody.
//
// Agreed, not Cryptographic. Everybody in the call derives the same seat
// state, so the server cannot claim somebody is unmuted who is not, and
// every honest client drops their media. It does not stop a modified client
// putting packets on the wire, and no product's mute does. When that is the
// actual problem, the control that solves it is Eject.
func (c *Call) Mute(target, by int, at time.Time) error {
	m, err := c.moderator(by)
	if err != nil {
		return err
	}
	s, ok := c.Seat(target)
	if !ok {
		return fmt.Errorf("index %d is not in this call", target)
	}
	if s.Role == Host && m.Role != Host {
		return fmt.Errorf("%s is the host; a cohost cannot mute them",
			s.Name)
	}
	if s.Muted {
		return nil
	}
	s.Muted, s.MutedBy = true, m.Name
	c.note(target, "muted", m.Name, at)
	return nil
}

// Unmute is deliberately not the inverse of Mute.
//
// A moderator can silence somebody and cannot make them speak: unmuting is
// the participant's own, always. The alternative is a control that turns on
// a stranger's microphone, and there is no version of that which is not a
// bug waiting to be reported as a feature.
func (c *Call) Unmute(index int, at time.Time) error {
	s, ok := c.Seat(index)
	if !ok {
		return fmt.Errorf("index %d is not in this call", index)
	}
	s.Muted, s.MutedBy = false, ""
	c.note(index, "unmuted", s.Name, at)
	return nil
}

// AskToUnmute is the honest version of the control products fake.
//
// It is Requested. It puts a signal on the other person's screen and that
// is all it does.
func (c *Call) AskToUnmute(target, by int, at time.Time) error {
	m, err := c.moderator(by)
	if err != nil {
		return err
	}
	if _, ok := c.Seat(target); !ok {
		return fmt.Errorf("index %d is not in this call", target)
	}
	c.Signals = append(c.Signals, Signal{
		Seat: target, Kind: AskUnmute, By: m.Name, At: at.UTC(),
		Until: at.UTC().Add(AskLife), seq: c.next(),
	})
	return nil
}

// Promote changes somebody's role.
//
// A cohost cannot make another cohost. A moderation power that can grant
// itself is bounded by nothing, and the failure is not hypothetical: it is
// how one compromised account becomes every account in the call.
func (c *Call) Promote(target, by int, to Role, at time.Time) error {
	m, err := c.moderator(by)
	if err != nil {
		return err
	}
	if !to.Known() {
		return fmt.Errorf("%q is not a role", to)
	}
	s, ok := c.Seat(target)
	if !ok {
		return fmt.Errorf("index %d is not in this call", target)
	}
	if to == Host {
		return fmt.Errorf("use Handover to pass the chair; a call with two " +
			"hosts has nobody who can be overruled")
	}
	if to.Moderates() && m.Role != Host {
		return fmt.Errorf("%s is a cohost, and a cohost cannot make "+
			"another one. Ask %s", m.Name, c.Seats[0].Name)
	}
	if s.Role == Host {
		return fmt.Errorf("%s is the host; pass the chair rather than "+
			"demoting them", s.Name)
	}
	s.Role = to
	c.note(target, "role "+string(to), m.Name, at)
	return nil
}

// Handover passes the chair. There is exactly one host at a time.
func (c *Call) Handover(to, by int, at time.Time) error {
	from, ok := c.Seat(by)
	if !ok || from.Role != Host {
		return fmt.Errorf("only the host passes the chair")
	}
	s, ok := c.Seat(to)
	if !ok {
		return fmt.Errorf("index %d is not in this call", to)
	}
	if s.Index == from.Index {
		return nil
	}
	from.Role, s.Role = Cohost, Host
	c.note(to, "host", from.Name, at)
	return nil
}

// MaySpeak reports whether somebody may currently send audio.
func (c *Call) MaySpeak(index int) (bool, string) {
	s, ok := c.Seat(index)
	if !ok {
		return false, "they are not in this call"
	}
	if s.Muted {
		return false, fmt.Sprintf("%s muted them", s.MutedBy)
	}
	if !s.Role.AtLeast(c.Policy.MaySpeak) {
		return false, fmt.Sprintf("this call lets a %s speak and they are "+
			"a %s", c.Policy.MaySpeak, s.Role)
	}
	return true, ""
}

// note records a control action against the call's ordered log.
func (c *Call) note(seat int, what, by string, at time.Time) {
	c.Signals = append(c.Signals, Signal{
		Seat: seat, Kind: Note, Note: what, By: by, At: at.UTC(),
		seq: c.next(),
	})
}

// Log is every control action that has happened, oldest first.
//
// Ordered by the sequence the call assigned rather than by timestamp.
// Clocks in a call disagree by seconds and a moderation record that reorders
// itself depending on whose laptop was fast is not a record.
func (c *Call) Log() []Signal {
	out := make([]Signal, 0, len(c.Signals))
	for _, s := range c.Signals {
		if s.Kind == Note {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out
}

// Controls lists every control and what actually stands behind it.
//
// Exported because an interface should be able to render the honesty rather
// than reimplement it, and because a table somebody can print is harder to
// quietly stop being true than a paragraph in a manual.
func Controls() []Control {
	return []Control{
		{"remove from the call", Cryptographic,
			"internal/groupkey commits an epoch whose secret was never " +
				"encapsulated to them"},
		{"lock the call", Cryptographic,
			"admission needs a commit, and a locked call makes none"},
		{"mute somebody", Agreed,
			"every honest client drops their media; a modified one can " +
				"still send"},
		{"who may speak", Agreed, "derived from the same group state by " +
			"everybody"},
		{"who may share", Agreed, "the same"},
		{"ask somebody to unmute", Requested,
			"it puts a signal on their screen"},
		{"ask somebody to turn on video", Requested, "the same"},
		{"raise a hand", Requested,
			"it is a request for attention and the queue is its own reward"},
	}
}

// Control is one row of that table.
type Control struct {
	Name        string      `json:"name"`
	Enforcement Enforcement `json:"enforcement"`
	How         string      `json:"how"`
}
