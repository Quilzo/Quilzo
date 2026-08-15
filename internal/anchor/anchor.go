// Package anchor commits a publication to a public blockchain.
//
// # What this is for, and the one thing it proves
//
// A timestamp from an authority proves when something existed, and its proof
// rests on that authority's certificate. When the certificate expires the token
// has to be re-stamped; if the authority folds, every token it issued lands in a
// legal grey area. An anchor has the opposite shape: there is no authority to
// expire, so the proof does not decay — but until recently it had no formal
// standing anywhere.
//
// That second half changed. eIDAS 2 (Regulation (EU) 2024/1183) introduces
// qualified electronic ledgers, which carry a presumption of uniqueness,
// authenticity, accurate date and time, and sequential ordering; implementing
// acts run through 2026. Italy's Law 12/2019, Vermont and Arizona already give
// blockchain records legal effect. So the layered answer — a signed token for
// the lawyer today, an anchor for the decade — is now better on both sides than
// it was.
//
// # What is anchored, and why nothing else can be
//
// One hash: the fingerprint of the whole published site. Not a page, not a
// field, not anything about a person.
//
// This is not a design preference. The EDPB's guidelines on blockchain and
// personal data (02/2025, version 2.0, adopted July 2026) recommend not
// registering clear text, encrypted *or hashed* personal data on a blockchain,
// because the ledger is immutable and Article 17 erasure has to remain possible.
// The pattern they endorse instead is exactly this one: keep the data off-chain
// and put only a commitment on it, so that deleting the data renders the
// on-chain record unlinkable.
//
// A root hash over an entire site satisfies that. Delete the content and the
// anchor still proves a site existed on a date, and proves nothing about who was
// in it. Publishing content itself to a permanent store — Arweave's pay-once
// model most obviously — is the case the guidelines rule out, and this package
// does not offer it.
//
// # Pending is not anchored, and says so
//
// A calendar server returns a proof immediately, and that proof commits to
// nothing yet: it says "this server has your hash and will include it in the
// next Bitcoin commitment", which takes hours. Reporting that as anchored would
// be the same class of lie as a sitemap claiming content changed when it did
// not. Every proof here carries its state, and the state is derived from the
// attestations in the proof rather than from how long ago it was submitted.
//
// # What is verified here, and what is not
//
// The operation chain is walked and the commitment recomputed, so a proof that
// does not actually commit to the digest it claims is rejected here. Whether a
// Bitcoin attestation names a real block containing that merkle root requires
// block headers, and this has none — that check is delegated to the
// `ots` client, which has them. A verifier that is subtly wrong is worse than
// none, because its output is believed.
package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Calendars are the public aggregators.
//
// More than one, because they are independent operators and a proof from a
// single calendar is a proof that depends on that calendar still existing when
// somebody comes to upgrade it. Submitting to several costs one request each.
var Calendars = []string{
	"https://alice.btc.calendar.opentimestamps.org",
	"https://bob.btc.calendar.opentimestamps.org",
	"https://finney.calendar.eternitywall.com",
}

// State is how far along a proof is.
type State string

const (
	// Pending means a calendar has the hash and has not yet committed it. This
	// is not an anchor.
	Pending State = "pending"
	// Anchored means the proof carries a Bitcoin attestation.
	Anchored State = "anchored"
	// Unknown means the proof carries no attestation this understands.
	Unknown State = "unknown"
)

// Proof is one calendar's answer.
type Proof struct {
	// Digest is what was submitted: the site fingerprint.
	Digest string `json:"digest"`
	// Calendar is who produced it.
	Calendar string `json:"calendar"`
	// Body is the raw proof bytes, stored verbatim. Re-encoding a proof would
	// mean this program's serialiser had to agree with every other
	// implementation's parser forever.
	Body []byte `json:"body"`
	// State is derived from the attestations, never from elapsed time.
	State State `json:"state"`
	// Height is the Bitcoin block, once there is one.
	Height uint64 `json:"height,omitempty"`
	// PendingAt names the calendar to ask for an upgrade.
	PendingAt   string `json:"pending_at,omitempty"`
	SubmittedAt string `json:"submitted_at"`
	UpgradedAt  string `json:"upgraded_at,omitempty"`
}

// Anchored reports whether this proof is actually committed to a chain.
func (p Proof) Anchored() bool { return p.State == Anchored }

// -- the OpenTimestamps proof format ----------------------------------------
//
// A proof is a tree of operations applied to a digest, with attestations at the
// leaves. Walking it produces the commitments a calendar or a blockchain knows
// about. The opcodes are a closed set; anything outside it stops the walk
// rather than being skipped, because an operation this does not understand
// changes the value in a way that makes everything after it meaningless.

const (
	opAttestation = 0x00
	opFork        = 0xff
	opAppend      = 0xf0
	opPrepend     = 0xf1
	opReverse     = 0xf2
	opHexlify     = 0xf3
	opSHA1        = 0x02
	opRIPEMD160   = 0x03
	opSHA256      = 0x08
	opKeccak256   = 0x67
)

var (
	magicPending = []byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
	magicBitcoin = []byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
)

// MaxProofBytes bounds a proof. A calendar's answer is a few hundred bytes; a
// megabyte of it is somebody feeding this a parser bomb.
const MaxProofBytes = 1 << 20

// maxOps bounds the walk. The format is a tree and a malicious one can fork
// endlessly, so the work is capped rather than trusted to terminate.
const maxOps = 10000

// maxValue bounds the value being carried through the walk, which is a separate
// thing from bounding the proof and bounding the operation count, and omitting
// it made both of those useless.
//
// hexlify doubles its input and costs one byte of proof. So does the operation
// budget's accounting: one operation, one unit. Forty bytes of 0xf3 therefore
// asks for 32 × 2⁴⁰ bytes — thirty-five terabytes from a forty byte input, well
// inside the megabyte the proof size allows and well inside the ten thousand
// operations the budget allows. Both existing limits are satisfied while the
// process dies.
//
// A real proof carries a 32 byte digest, prepends and appends 32 byte merkle
// siblings, and hashes back down to 32. The largest legitimate intermediate is
// around a hundred bytes, so four kilobytes is generous by a factor of forty and
// still refuses the bomb at the third doubling.
const maxValue = 4096

// maxDepth bounds fork nesting. The operation budget technically bounds it too,
// but at ten thousand frames, and a limit that only stops something after ten
// thousand stack frames of recursion is not the limit anybody thinks it is. A
// real proof forks once or twice.
const maxDepth = 64

// Attestation is a commitment found in a proof.
type Attestation struct {
	Kind string
	// Commitment is the value at that point in the tree — for Bitcoin, the
	// merkle root that must appear in the named block.
	//
	// Not necessarily 32 bytes, which is the natural assumption and is wrong. A
	// real calendar proof ends `prepend 4, append 8` with no closing hash, so
	// the value the calendar files it under is 44 bytes. Asserting a length
	// here would reject every genuine proof.
	Commitment []byte
	URI        string
	Height     uint64
}

// Walk applies a proof's operations to a digest and returns the attestations
// reached.
//
// This is the part that can be checked without block headers: a proof that does
// not actually derive from the digest it claims to be about is rejected here,
// which catches a proof pasted from somewhere else or edited.
func Walk(digest, proof []byte) ([]Attestation, error) {
	if len(proof) > MaxProofBytes {
		return nil, fmt.Errorf("the proof is %d bytes, which is not a proof",
			len(proof))
	}
	r := &reader{b: proof}
	var out []Attestation
	if len(digest) > maxValue {
		return nil, fmt.Errorf("the digest is %d bytes", len(digest))
	}
	budget := maxOps
	if err := walk(r, digest, &out, &budget, 0); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the proof reaches no attestation, so it commits " +
			"to nothing")
	}
	return out, nil
}

func walk(r *reader, current []byte, out *[]Attestation, budget *int, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("the proof forks %d deep; no real one nests past a "+
			"handful", depth)
	}
	for {
		if *budget <= 0 {
			return fmt.Errorf("the proof has more operations than any real one " +
				"does; refusing to keep walking")
		}
		*budget--

		op, err := r.byte()
		if err != nil {
			return nil // end of this branch
		}

		switch op {
		case opAttestation:
			att, err := readAttestation(r, current)
			if err != nil {
				return err
			}
			*out = append(*out, att)
			return nil

		case opFork:
			// Both branches continue from the value here. The left is walked
			// with a copy, because an operation on one branch must not alter
			// what the other sees — sharing the slice was the first bug in this
			// function and it produced proofs that verified against the wrong
			// value.
			left := append([]byte(nil), current...)
			if err := walk(r, left, out, budget, depth+1); err != nil {
				return err
			}
			continue

		default:
			next, err := apply(op, current, r)
			if err != nil {
				return err
			}
			// Checked after every operation rather than only after the ones
			// that look expensive, because the point of a limit is that it
			// does not depend on somebody having correctly guessed which
			// operations grow.
			if len(next) > maxValue {
				return fmt.Errorf("an operation in this proof produces a %d "+
					"byte value; a real proof carries about a hundred",
					len(next))
			}
			current = next
		}
	}
}

func apply(op byte, current []byte, r *reader) ([]byte, error) {
	switch op {
	case opAppend:
		arg, err := r.bytes()
		if err != nil {
			return nil, err
		}
		return append(append([]byte(nil), current...), arg...), nil
	case opPrepend:
		arg, err := r.bytes()
		if err != nil {
			return nil, err
		}
		return append(append([]byte(nil), arg...), current...), nil
	case opReverse:
		out := make([]byte, len(current))
		for i := range current {
			out[len(current)-1-i] = current[i]
		}
		return out, nil
	case opHexlify:
		return []byte(hex.EncodeToString(current)), nil
	case opSHA256:
		sum := sha256.Sum256(current)
		return sum[:], nil
	case opSHA1, opRIPEMD160, opKeccak256:
		// Present in the format, deliberately not implemented, and this is a
		// judgement worth stating rather than hiding.
		//
		// A Bitcoin timestamp proof is append, prepend and SHA-256 — that is
		// what a calendar produces and what a Bitcoin merkle path needs. SHA-1
		// is broken, Keccak appears only in Ethereum proofs this does not make,
		// and RIPEMD-160 belongs to address derivation rather than to
		// timestamping. Implementing them would mean either a dependency in a
		// program that has none, or hand-rolled hash code carrying real weight.
		//
		// Refusing is the safe half of the trade. Skipping an operation would
		// carry a value forward that is not what the proof describes, and every
		// attestation after it would be checked against the wrong number while
		// appearing to succeed.
		return nil, fmt.Errorf(
			"this proof uses operation %#02x, which is not implemented here. "+
				"Bitcoin timestamp proofs use append, prepend and SHA-256; a "+
				"proof needing anything else is one to verify with the `ots` "+
				"client rather than to guess at", op)
	}
	return nil, fmt.Errorf("unknown operation %#02x", op)
}

func readAttestation(r *reader, current []byte) (Attestation, error) {
	magic, err := r.take(8)
	if err != nil {
		return Attestation{}, err
	}
	payload, err := r.bytes()
	if err != nil {
		return Attestation{}, err
	}
	att := Attestation{Commitment: append([]byte(nil), current...)}

	switch {
	case bytes.Equal(magic, magicBitcoin):
		att.Kind = "bitcoin"
		h, err := (&reader{b: payload}).varint()
		if err != nil {
			return Attestation{}, fmt.Errorf("the block height is malformed: %w", err)
		}
		att.Height = h
	case bytes.Equal(magic, magicPending):
		att.Kind = "pending"
		uri, err := (&reader{b: payload}).bytes()
		if err != nil {
			return Attestation{}, err
		}
		att.URI = string(uri)
		// A pending attestation names a URL that this program will later fetch,
		// so it is somebody else's string arriving in a place that makes a
		// request. Checked here rather than at fetch time, so a hostile proof
		// is refused when it is stored rather than when it is upgraded.
		if !strings.HasPrefix(att.URI, "https://") {
			return Attestation{}, fmt.Errorf(
				"the proof names %q as its calendar, which is not an https URL. "+
					"This value becomes a request later", att.URI)
		}
	default:
		att.Kind = "unknown:" + hex.EncodeToString(magic)
	}
	return att, nil
}

// -- reading -----------------------------------------------------------------

type reader struct {
	b []byte
	i int
}

func (r *reader) byte() (byte, error) {
	if r.i >= len(r.b) {
		return 0, fmt.Errorf("end of proof")
	}
	c := r.b[r.i]
	r.i++
	return c, nil
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.i+n > len(r.b) {
		return nil, fmt.Errorf("the proof claims %d more bytes than it has", n)
	}
	out := r.b[r.i : r.i+n]
	r.i += n
	return out, nil
}

// varint is the format's length encoding: seven bits at a time, high bit set
// to continue.
func (r *reader) varint() (uint64, error) {
	var v uint64
	var shift uint
	for {
		c, err := r.byte()
		if err != nil {
			return 0, err
		}
		// Bounded at ten groups. Without this a crafted proof of all-0xff bytes
		// spins until the slice runs out, and on a longer input it overflows
		// silently into a small number.
		if shift > 63 {
			return 0, fmt.Errorf("a length in this proof does not terminate")
		}
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, nil
		}
		shift += 7
	}
}

func (r *reader) bytes() ([]byte, error) {
	n, err := r.varint()
	if err != nil {
		return nil, err
	}
	if n > MaxProofBytes {
		return nil, fmt.Errorf("the proof claims a %d byte field", n)
	}
	return r.take(int(n))
}

// -- classifying a proof -----------------------------------------------------

// Classify derives a proof's state from its attestations.
//
// From the attestations, never from how long ago it was submitted. A proof
// submitted a year ago that nobody upgraded is still pending, and reporting it
// as anchored because time has passed would be a claim about Bitcoin made by
// looking at a clock.
func Classify(digest, body []byte) (State, uint64, string, error) {
	atts, err := Walk(digest, body)
	if err != nil {
		return Unknown, 0, "", err
	}
	var pendingAt string
	for _, a := range atts {
		if a.Kind == "bitcoin" {
			return Anchored, a.Height, "", nil
		}
		if a.Kind == "pending" && pendingAt == "" {
			pendingAt = a.URI
		}
	}
	if pendingAt != "" {
		return Pending, 0, pendingAt, nil
	}
	return Unknown, 0, "", nil
}

// Describe says what a proof establishes and what it does not.
func Describe(p Proof) string {
	var b strings.Builder
	switch p.State {
	case Anchored:
		fmt.Fprintf(&b, "anchored in Bitcoin block %d\n", p.Height)
		fmt.Fprintf(&b, "  the commitment is in a block, so the date is as hard "+
			"as the chain\n")
		fmt.Fprintf(&b, "  verify independently:  ots verify anchor.ots\n")
	case Pending:
		fmt.Fprintf(&b, "pending at %s\n", p.PendingAt)
		fmt.Fprintf(&b, "  this is NOT an anchor yet. The calendar has the hash "+
			"and will\n  include it in its next commitment, which takes hours.\n")
		fmt.Fprintf(&b, "  run `scrivet anchor upgrade` after that\n")
	default:
		fmt.Fprintf(&b, "the proof carries no attestation this understands\n")
	}
	if !p.Anchored() {
		fmt.Fprintf(&b, "  submitted %s\n", p.SubmittedAt)
	}
	return b.String()
}

// Age reports how long a proof has been pending, for the case where a calendar
// has quietly stopped upgrading.
func Age(p Proof, now time.Time) time.Duration {
	t, err := time.Parse(time.RFC3339, p.SubmittedAt)
	if err != nil {
		return 0
	}
	return now.Sub(t)
}

// -- talking to calendars ----------------------------------------------------

// Submitter sends digests to calendars. Separated from the walk so the parsing
// can be tested without a network and the network without a parser.
type Submitter interface {
	Post(ctx context.Context, url string, body []byte) ([]byte, error)
	Get(ctx context.Context, url string) ([]byte, error)
}

// Submit sends a digest to every calendar and returns the proofs.
//
// Failures are collected rather than fatal: one calendar being down is not a
// reason to have no anchor, and a proof from two of three is a proof from two
// independent operators. Returning an error only when all fail is the honest
// line — that is the case where nothing was recorded anywhere.
func Submit(ctx context.Context, s Submitter, digest []byte, calendars []string,
	now time.Time) ([]Proof, []error) {

	if len(digest) != sha256.Size {
		return nil, []error{fmt.Errorf(
			"a digest must be %d bytes, this is %d", sha256.Size, len(digest))}
	}
	if len(calendars) == 0 {
		calendars = Calendars
	}

	var proofs []Proof
	var errs []error
	for _, c := range calendars {
		body, err := s.Post(ctx, strings.TrimSuffix(c, "/")+"/digest", digest)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c, err))
			continue
		}
		// Walked before it is stored. A calendar returning something that does
		// not commit to the digest just submitted is either broken or hostile,
		// and storing it would mean discovering that at the moment somebody
		// needs the proof.
		state, height, pendingAt, err := Classify(digest, body)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"%s returned something that does not commit to this digest: %w",
				c, err))
			continue
		}
		proofs = append(proofs, Proof{
			Digest: hex.EncodeToString(digest), Calendar: c, Body: body,
			State: state, Height: height, PendingAt: pendingAt,
			SubmittedAt: now.UTC().Format(time.RFC3339),
		})
	}
	return proofs, errs
}

// ErrNotYet means the calendar has the hash and has not yet committed it.
//
// A distinct value rather than a message, so a caller can tell "waiting" from
// "broken" without matching on text.
var ErrNotYet = errors.New("not yet committed to a block")

// Upgrade asks a calendar for the Bitcoin attestation, once there is one.
func Upgrade(ctx context.Context, s Submitter, p Proof, now time.Time) (Proof, error) {
	if p.Anchored() {
		return p, nil
	}
	digest, err := hex.DecodeString(p.Digest)
	if err != nil {
		return p, fmt.Errorf("the stored digest is not hex: %w", err)
	}

	// The commitment the calendar files this under is what the walk produced,
	// not the digest — asking for the digest returns nothing, which looks like
	// the calendar has lost the proof.
	atts, err := Walk(digest, p.Body)
	if err != nil {
		return p, err
	}
	var commitment []byte
	base := p.PendingAt
	for _, a := range atts {
		if a.Kind == "pending" {
			commitment, base = a.Commitment, a.URI
			break
		}
	}
	if commitment == nil {
		return p, fmt.Errorf("this proof has no pending attestation to upgrade")
	}

	body, err := s.Get(ctx,
		strings.TrimSuffix(base, "/")+"/timestamp/"+hex.EncodeToString(commitment))
	if err != nil {
		// A 404 is the ordinary case, not a failure: the calendar has the hash
		// and has not yet put it in a block. Reporting it as an error trains
		// people to ignore the output of this command, which is the one place
		// a genuine failure would show up.
		if strings.Contains(err.Error(), "404") {
			return p, ErrNotYet
		}
		return p, err
	}

	// The calendar returns the continuation from the commitment onward, so the
	// upgraded proof is the original with the tail replaced.
	merged := append(append([]byte(nil), trimPending(p.Body)...), body...)
	state, height, pendingAt, err := Classify(digest, merged)
	if err != nil {
		return p, fmt.Errorf("the upgraded proof does not verify: %w", err)
	}
	out := p
	out.Body, out.State, out.Height, out.PendingAt = merged, state, height, pendingAt
	out.UpgradedAt = now.UTC().Format(time.RFC3339)
	return out, nil
}

// trimPending removes a trailing pending attestation, so an upgrade replaces it
// rather than leaving both in the proof.
func trimPending(body []byte) []byte {
	for i := len(body) - 9; i >= 0; i-- {
		if body[i] == opAttestation && bytes.Equal(body[i+1:i+9], magicPending) {
			return body[:i]
		}
	}
	return body
}
