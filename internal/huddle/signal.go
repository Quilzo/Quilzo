// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package huddle

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SignalKind is one of the small things people do in a call that are not
// speaking.
type SignalKind string

const (
	// React is a moment: a thumbs up, a laugh. It goes away by itself.
	React SignalKind = "react"
	// Hand is a request to speak. It stays up until it is taken down,
	// because a raised hand that expired while somebody was mid-sentence is
	// worse than no hand at all.
	Hand SignalKind = "hand"
	// Away says the person has stepped out. Their own statement about
	// themselves, which is the only status that is ever accurate.
	Away SignalKind = "away"
	// AskUnmute is a moderator asking somebody to speak. Requested.
	AskUnmute SignalKind = "ask-unmute"
	// AskVideo is the same for a camera.
	AskVideo SignalKind = "ask-video"
	// Note is a control action, kept in the same ordered list so the record
	// of what happened is one list rather than two that can disagree.
	Note SignalKind = "note"
)

// Sticky reports whether a signal stays until it is taken down.
func (k SignalKind) Sticky() bool {
	switch k {
	case Hand, Away:
		return true
	}
	return false
}

// Enforcement says what a signal is worth, in the same vocabulary as the
// controls.
func (k SignalKind) Enforcement() Enforcement {
	switch k {
	case AskUnmute, AskVideo:
		return Requested
	default:
		return Agreed
	}
}

// ReactLife is how long a reaction stays up.
//
// Long enough to be seen by somebody who was looking elsewhere, short
// enough that a wall of them is not the meeting.
const ReactLife = 6 * time.Second

// AskLife is how long a request to unmute stays on somebody's screen.
const AskLife = 30 * time.Second

// Signal is one of those things, in the call's own order.
type Signal struct {
	Seat  int        `json:"seat"`
	Kind  SignalKind `json:"kind"`
	Emoji string     `json:"emoji,omitempty"`
	Note  string     `json:"note,omitempty"`
	By    string     `json:"by,omitempty"`
	At    time.Time  `json:"at"`
	Until time.Time  `json:"until,omitzero"`

	// seq is the call's own ordering. Not exported and not the timestamp:
	// clocks in a call disagree by seconds, and a hand queue that reorders
	// itself depending on whose laptop was fast is not a queue.
	seq uint64
}

// Order is where a signal sits in the call's sequence.
func (s Signal) Order() uint64 { return s.seq }

// Live reports whether a signal should be on screen at a moment.
func (s Signal) Live(at time.Time) bool {
	if s.Kind == Note {
		return false
	}
	if !s.Until.IsZero() && !at.Before(s.Until) {
		return false
	}
	return !at.Before(s.At)
}

// MaxEmoji caps a reaction.
//
// A reaction is one emoji. Anything longer is a message, and a message
// belongs in the thread where it can be found again rather than floating
// over somebody's face for six seconds.
const MaxEmoji = 8

// Signal raises, reacts or steps away.
func (c *Call) Signal(index int, kind SignalKind, emoji string,
	at time.Time) error {
	s, ok := c.Seat(index)
	if !ok {
		return fmt.Errorf("index %d is not in this call", index)
	}
	switch kind {
	case React:
		if strings.TrimSpace(emoji) == "" {
			return fmt.Errorf("a reaction is an emoji")
		}
		if len([]rune(emoji)) > MaxEmoji {
			return fmt.Errorf("a reaction is one emoji, not %d characters; "+
				"anything longer is a message and belongs in the thread",
				len([]rune(emoji)))
		}
	case Hand, Away:
		if emoji != "" {
			return fmt.Errorf("a %s carries no emoji", kind)
		}
	case AskUnmute, AskVideo, Note:
		return fmt.Errorf("%s is not something you do to yourself", kind)
	default:
		return fmt.Errorf("%q is not a signal", kind)
	}

	if kind.Sticky() {
		for _, e := range c.Signals {
			if e.Seat == index && e.Kind == kind && e.Until.IsZero() {
				return nil // already up; raising twice is once
			}
		}
	}
	sig := Signal{Seat: index, Kind: kind, Emoji: emoji, By: s.Name,
		At: at.UTC(), seq: c.next()}
	if !kind.Sticky() {
		sig.Until = at.UTC().Add(ReactLife)
	}
	if kind == Away {
		s.Away = true
	}
	c.Signals = append(c.Signals, sig)
	return nil
}

// Lower takes a sticky signal down.
func (c *Call) Lower(index int, kind SignalKind, at time.Time) error {
	s, ok := c.Seat(index)
	if !ok {
		return fmt.Errorf("index %d is not in this call", index)
	}
	if !kind.Sticky() {
		return fmt.Errorf("a %s comes down by itself", kind)
	}
	for i := range c.Signals {
		e := &c.Signals[i]
		if e.Seat == index && e.Kind == kind && e.Until.IsZero() {
			e.Until = at.UTC()
			if kind == Away {
				s.Away = false
			}
			return nil
		}
	}
	return fmt.Errorf("%s has no %s up", s.Name, kind)
}

// Queue is who has their hand up, in the order they raised it.
//
// In the call's own sequence, not by timestamp. This is the small thing
// every product gets slightly wrong and everybody in a large call notices:
// two people raise a hand within the same second and the order shown
// depends on whose clock was ahead, so the person running the meeting picks
// whoever the interface happened to list first and somebody quietly
// concludes they were skipped.
func (c *Call) Queue(at time.Time) []Signal {
	var out []Signal
	for _, s := range c.Signals {
		if s.Kind == Hand && s.Live(at) {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out
}

// Live is every signal that should currently be on screen.
func (c *Call) Live(at time.Time) []Signal {
	var out []Signal
	for _, s := range c.Signals {
		if s.Live(at) {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out
}

// What is being shared.
type What string

const (
	// Screen is a whole display.
	Screen What = "screen"
	// Window is one application, which is the safer choice and not the
	// default anywhere, which is why so many demonstrations include
	// somebody's inbox.
	Window What = "window"
	// Camera is a person.
	Camera What = "camera"
)

// Share is one outbound media stream.
//
// Several at once, from several people, is the ordinary case: two people
// comparing a design against the code that implements it need both on
// screen, and a product that allows one share at a time turns that into
// taking turns describing what the other cannot see.
//
// The mechanism is already in the specification. RFC 9605 gives the SFrame
// key identifier a context field, in its own words "to allow a single sender
// to send multiple, uncoordinated outbound media streams". Each share takes
// a context, so each stream has its own key and salt and no two streams
// share a nonce — which is what makes several simultaneous shares a matter
// of allocating a number rather than a second key exchange.
type Share struct {
	Seat    int       `json:"seat"`
	What    What      `json:"what"`
	Context uint64    `json:"context"`
	Title   string    `json:"title,omitempty"`
	Started time.Time `json:"started"`
	seq     uint64
}

// StartShare opens a stream and allocates its key context.
func (c *Call) StartShare(index int, what What, title string,
	at time.Time) (Share, error) {
	s, ok := c.Seat(index)
	if !ok {
		return Share{}, fmt.Errorf("index %d is not in this call", index)
	}
	switch what {
	case Screen, Window, Camera:
	default:
		return Share{}, fmt.Errorf("%q is not something to share", what)
	}
	if !s.Role.AtLeast(c.Policy.MayShare) {
		return Share{}, fmt.Errorf("this call lets a %s share and %s is a "+
			"%s", c.Policy.MayShare, s.Name, s.Role)
	}
	live := 0
	for _, e := range c.Shares {
		if e.What != Camera {
			live++
		}
	}
	if what != Camera && live >= c.Policy.MaxShares {
		return Share{}, fmt.Errorf("%d screen(s) are already being shared "+
			"and this call allows %d. Not a technical limit — each stream "+
			"has its own key — but a call where everybody is sharing is a "+
			"call where nobody is looking at anything", live,
			c.Policy.MaxShares)
	}
	for _, e := range c.Shares {
		if e.Seat == index && e.What == what && what != Window {
			return Share{}, fmt.Errorf("%s is already sharing their %s",
				s.Name, what)
		}
	}

	sh := Share{
		Seat: index, What: what, Context: c.nextContext(index),
		Title: strings.TrimSpace(title), Started: at.UTC(), seq: c.next(),
	}
	c.Shares = append(c.Shares, sh)
	c.note(index, "started sharing a "+string(what), s.Name, at)
	return sh, nil
}

// nextContext picks a key context this seat is not already using.
//
// Per seat rather than per call, because the KID already carries the sender
// index: two people may both use context 0 and still hold different keys.
// Keeping the numbers small keeps the encoded KID short, which is a header
// on every frame.
func (c *Call) nextContext(index int) uint64 {
	used := map[uint64]bool{}
	for _, s := range c.Shares {
		if s.Seat == index {
			used[s.Context] = true
		}
	}
	for n := uint64(0); ; n++ {
		if !used[n] {
			return n
		}
	}
}

// StopShare closes a stream.
func (c *Call) StopShare(index int, context uint64, at time.Time) error {
	for i, s := range c.Shares {
		if s.Seat == index && s.Context == context {
			c.Shares = append(c.Shares[:i], c.Shares[i+1:]...)
			if seat, ok := c.Seat(index); ok {
				c.note(index, "stopped sharing", seat.Name, at)
			}
			return nil
		}
	}
	return fmt.Errorf("index %d is not sharing a stream with context %d",
		index, context)
}

// StopTheirShare is a moderator ending somebody else's share.
//
// Agreed, like muting. Everybody drops the stream; the sender's software
// could keep emitting it and nobody will render it. When that is genuinely
// the problem, the control is Eject.
func (c *Call) StopTheirShare(index int, context uint64, by int,
	at time.Time) error {
	m, err := c.moderator(by)
	if err != nil {
		return err
	}
	if err := c.StopShare(index, context, at); err != nil {
		return err
	}
	c.note(index, "share stopped by "+m.Name, m.Name, at)
	return nil
}

// dropShares ends every stream from a seat, used when somebody leaves.
func (c *Call) dropShares(index int) {
	kept := c.Shares[:0]
	for _, s := range c.Shares {
		if s.Seat != index {
			kept = append(kept, s)
		}
	}
	c.Shares = kept
}

// Sharing is every live stream, oldest first.
func (c *Call) Sharing() []Share {
	out := append([]Share(nil), c.Shares...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out
}
