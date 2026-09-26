// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package groupkey

import (
	"crypto/sha256"
	"fmt"
	"math/bits"

	"github.com/quilzo/quilzo/internal/sframe"
)

// Exporter derives a secret for something outside this package.
//
// The shape is RFC 9420's MLS-Exporter: a per-purpose secret derived from
// the epoch's exporter secret, then expanded with the caller's context. Two
// purposes cannot collide, and an exported value is bound to the epoch it
// came from, so it changes the moment somebody joins or leaves.
func (g *Group) Exporter(label string, context []byte,
	length int) ([]byte, error) {
	if len(g.keys.exporter) == 0 {
		return nil, fmt.Errorf("this call has no epoch secret yet")
	}
	if label == "" {
		return nil, fmt.Errorf("an exported secret needs a label saying " +
			"what it is for; without one the same bytes end up in two " +
			"places and neither knows about the other")
	}
	if length <= 0 || length > 255*Nh {
		return nil, fmt.Errorf("%d is not a length HKDF will expand to",
			length)
	}
	per, err := deriveSecret(g.keys.exporter, label)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(context)
	return expandWithLabel(per, "exported", sum[:], length)
}

// SFrameLabel is the exporter label RFC 9605 Section 5.2 specifies.
//
// Exactly as the RFC writes it, because the label is the interface: an
// implementation that spells it differently derives a different key and
// fails at the first frame, with nothing on either side to say why.
const SFrameLabel = "SFrame 1.0 Base Key"

// EpochBits is how many low-order bits of the epoch number the KID carries.
//
// RFC 9605 leaves this to the application. It is the reordering window: no
// more than 2^EpochBits epochs can be in flight, and a receiver MUST drop
// an old epoch when a new one arrives with the same low bits. Eight is
// generous for a call — 256 membership changes would have to be in flight
// at once — and costs one byte in the header.
const EpochBits = 8

// BaseKey is the SFrame base key for this epoch.
//
// Shared by everybody in the call. It is not what anybody encrypts with:
// SFrame derives a separate key and salt per KID, and the KID carries the
// sender's index, so no two senders ever hold the same key and salt. That
// matters more than it sounds. SFrame's nonce is the salt XORed with a
// counter that each sender starts at zero, so two senders sharing a salt
// would produce the same nonce under the same key on their first frame,
// which is the failure that takes an AEAD apart completely.
func (g *Group) BaseKey(suite sframe.Suite) ([]byte, error) {
	if !suite.Known() {
		return nil, fmt.Errorf("%s is not a registered SFrame cipher suite",
			suite)
	}
	return g.Exporter(SFrameLabel, nil, suite.KeyBytes())
}

// IndexBits is how many bits the KID needs for a member index, which RFC
// 9605 calls S: the smallest value such that the group fits.
//
// It is derived from the number of slots rather than the number of people,
// because a slot somebody has left still holds an index nobody else may
// take. It can only change at an epoch boundary, which is the moment
// everybody re-derives anyway.
func (g *Group) IndexBits() int {
	n := g.Slots()
	if n <= 1 {
		return 1
	}
	return bits.Len(uint(n - 1))
}

// KID builds the SFrame key identifier for one sender in this epoch.
//
//	KID = (context << (S + E)) + (sender_index << E) + (epoch % (1 << E))
//
// which is Figure 8 of RFC 9605. The context field is the sender's to
// choose: it is what lets one person send two streams — a camera and a
// shared screen — under keys that are not the same, without coordinating
// with anybody.
func (g *Group) KID(sender int, context uint64) (uint64, error) {
	if _, ok := g.Member(sender); !ok {
		return 0, fmt.Errorf("nobody is at index %d of this call", sender)
	}
	s := g.IndexBits()
	if s+EpochBits >= 64 {
		return 0, fmt.Errorf("this call is too large for a 64-bit KID")
	}
	if context >= 1<<(64-s-EpochBits) {
		return 0, fmt.Errorf("a context of %d does not fit in the %d bits "+
			"left over once the index and epoch are in", context,
			64-s-EpochBits)
	}
	return context<<(s+EpochBits) |
		uint64(sender)<<EpochBits |
		g.Epoch%(1<<EpochBits), nil
}

// SenderKey is the key this member encrypts with.
func (g *Group) SenderKey(suite sframe.Suite, context uint64) (sframe.Key,
	error) {
	return g.KeyFor(suite, g.me, context)
}

// KeyFor is the key a given member encrypts with, which is what a receiver
// needs to decrypt them.
func (g *Group) KeyFor(suite sframe.Suite, sender int,
	context uint64) (sframe.Key, error) {
	base, err := g.BaseKey(suite)
	if err != nil {
		return sframe.Key{}, err
	}
	kid, err := g.KID(sender, context)
	if err != nil {
		return sframe.Key{}, err
	}
	return sframe.Derive(suite, kid, base)
}

// Stale reports whether an epoch number would collide with this one in the
// low bits the KID carries.
//
// RFC 9605 requires a receiver to remove an old epoch when a new one with
// the same low-order bits arrives. This is how a caller asks.
func (g *Group) Stale(epoch uint64) bool {
	return epoch != g.Epoch && epoch%(1<<EpochBits) == g.Epoch%(1<<EpochBits)
}

// Cost is what a membership change costs on the wire.
//
// Measured from a real commit rather than asserted, because the number is
// the argument for not having a tree and an argument made of an estimate is
// not an argument.
type Cost struct {
	Members   int `json:"members"`
	Bytes     int `json:"bytes"`
	PerMember int `json:"per_member"`
}

// Size is what a commit actually weighs.
func (c *Commit) Size() int {
	n := len(c.Ed25519) + len(c.MLDSA) + len(c.Confirmation)
	for _, w := range c.Sealed {
		n += len(w.Sealed) + 4
	}
	for _, ch := range c.Changes {
		n += len(ch.Kind) + 8 + len(ch.Member.Name) + len(ch.Member.KEM) +
			len(ch.Member.Ed25519) + len(ch.Member.MLDSA)
	}
	return n
}

// Cost measures a commit against the group it was made in.
func (c *Commit) Cost() Cost {
	out := Cost{Members: len(c.Sealed), Bytes: c.Size()}
	if out.Members > 0 {
		out.PerMember = out.Bytes / out.Members
	}
	return out
}

// Tree is what the same commit would weigh with a ratchet tree, which
// encapsulates to the copath rather than to everybody.
//
// Here so the trade is checkable rather than claimed. It is the honest
// comparison and it is not flattering at every size: past a few hundred
// members the tree is plainly right, and the reason this does not have one
// is that a call is not that, not that the saving is imaginary.
func (c Cost) Tree() int {
	if c.Members <= 1 {
		return c.Bytes
	}
	depth := bits.Len(uint(c.Members - 1))
	return depth*c.PerMember + (c.Bytes - c.Members*c.PerMember)
}
