package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// build assembles a proof by hand, so the tests can produce the malformed ones a
// calendar never would.
type build struct{ b []byte }

func (x *build) op(c byte) *build { x.b = append(x.b, c); return x }
func (x *build) varint(n uint64) *build {
	for {
		c := byte(n & 0x7f)
		n >>= 7
		if n > 0 {
			c |= 0x80
		}
		x.b = append(x.b, c)
		if n == 0 {
			return x
		}
	}
}
func (x *build) arg(v []byte) *build { x.varint(uint64(len(v))); x.b = append(x.b, v...); return x }
func (x *build) bitcoin(height uint64) *build {
	x.op(opAttestation)
	x.b = append(x.b, magicBitcoin...)
	var h build
	h.varint(height)
	return x.arg(h.b)
}
func (x *build) pending(uri string) *build {
	x.op(opAttestation)
	x.b = append(x.b, magicPending...)
	var u build
	u.arg([]byte(uri))
	return x.arg(u.b)
}

func digest(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }

// -- the walk ----------------------------------------------------------------

func TestTheWalkComputesTheCommitment(t *testing.T) {
	d := digest("a site")
	// append "xy", then sha256, then attest.
	var x build
	x.op(opAppend).arg([]byte("xy")).op(opSHA256).bitcoin(800000)

	atts, err := Walk(d, x.b)
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) != 1 || atts[0].Kind != "bitcoin" || atts[0].Height != 800000 {
		t.Fatalf("got %#v", atts)
	}
	want := sha256.Sum256(append(append([]byte(nil), d...), []byte("xy")...))
	if !bytes.Equal(atts[0].Commitment, want[:]) {
		t.Errorf("the commitment is %x, expected %x", atts[0].Commitment, want)
	}
}

// A proof that does not derive from the digest it claims to be about is the
// case somebody pastes a proof from somewhere else.
func TestADifferentDigestProducesADifferentCommitment(t *testing.T) {
	var x build
	x.op(opSHA256).bitcoin(800000)

	a, err := Walk(digest("site A"), x.b)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Walk(digest("site B"), x.b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a[0].Commitment, b[0].Commitment) {
		t.Fatal("two different digests reached the same commitment, so the " +
			"proof establishes nothing about which one it covers")
	}
}

// A fork walks both branches from the same value. Sharing the slice was the
// first bug in this function: an append on one branch altered what the other
// saw, and both branches then verified against a value neither described.
func TestAForkGivesEachBranchItsOwnValue(t *testing.T) {
	d := digest("a site")
	var x build
	x.op(opFork).
		op(opAppend).arg([]byte("left")).op(opSHA256).bitcoin(1).
		op(opAppend).arg([]byte("right")).op(opSHA256).bitcoin(2)

	atts, err := Walk(d, x.b)
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) != 2 {
		t.Fatalf("got %d attestations from a fork", len(atts))
	}
	wantLeft := sha256.Sum256(append(append([]byte(nil), d...), []byte("left")...))
	wantRight := sha256.Sum256(append(append([]byte(nil), d...), []byte("right")...))
	if !bytes.Equal(atts[0].Commitment, wantLeft[:]) {
		t.Errorf("the left branch computed %x", atts[0].Commitment)
	}
	if !bytes.Equal(atts[1].Commitment, wantRight[:]) {
		t.Errorf("the right branch saw the left branch's changes: %x",
			atts[1].Commitment)
	}
}

// -- hostile input -----------------------------------------------------------

// The format is a tree and a crafted one can fork endlessly, so the work is
// capped rather than trusted to terminate.
func TestAnEndlesslyForkingProofIsRefused(t *testing.T) {
	var x build
	for range maxOps + 100 {
		x.op(opFork)
	}
	done := make(chan struct{})
	go func() {
		_, _ = Walk(digest("x"), x.b)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("still walking after five seconds")
	}
}

// A varint of all continuation bytes spins until the slice runs out, and on a
// longer input overflows silently into a small number.
func TestANonTerminatingLengthIsRefused(t *testing.T) {
	var x build
	x.op(opAppend)
	for range 20 {
		x.b = append(x.b, 0xff)
	}
	if _, err := Walk(digest("x"), x.b); err == nil {
		t.Fatal("a length that does not terminate was accepted")
	}
}

func TestALengthLongerThanTheProofIsRefused(t *testing.T) {
	var x build
	x.op(opAppend).varint(1 << 20)
	if _, err := Walk(digest("x"), x.b); err == nil {
		t.Fatal("a field claiming more bytes than exist was accepted")
	}
}

// Skipping an operation carries a value forward that is not what the proof
// describes, and every attestation after it is then checked against the wrong
// number while appearing to succeed.
func TestAnUnimplementedOperationStopsTheWalk(t *testing.T) {
	for _, op := range []byte{opSHA1, opRIPEMD160, opKeccak256, 0x99} {
		var x build
		x.op(op).bitcoin(1)
		if _, err := Walk(digest("x"), x.b); err == nil {
			t.Errorf("operation %#02x was walked past", op)
		}
	}
}

// A proof reaching no attestation commits to nothing, and reporting it as valid
// would make an empty file a timestamp.
func TestAProofWithNoAttestationIsRefused(t *testing.T) {
	var x build
	x.op(opAppend).arg([]byte("xy")).op(opSHA256)
	if _, err := Walk(digest("x"), x.b); err == nil {
		t.Fatal("a proof reaching no attestation was accepted")
	}
	if _, err := Walk(digest("x"), nil); err == nil {
		t.Fatal("an empty proof was accepted")
	}
}

// A pending attestation names a URL this program will later fetch, so it is
// somebody else's string arriving somewhere that makes a request.
func TestAPendingURLThatIsNotHTTPSIsRefused(t *testing.T) {
	for _, uri := range []string{
		"http://calendar.example", "file:///etc/passwd",
		"gopher://x", "https://ok.example",
	} {
		var x build
		x.pending(uri)
		_, err := Walk(digest("x"), x.b)
		if uri == "https://ok.example" {
			if err != nil {
				t.Errorf("a valid calendar URL was refused: %v", err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%q was accepted as a calendar URL", uri)
		}
	}
}

// -- classification ----------------------------------------------------------

// From the attestations, never from elapsed time. A proof submitted a year ago
// that nobody upgraded is still pending, and calling it anchored because time
// has passed would be a claim about Bitcoin made by looking at a clock.
func TestStateComesFromTheProofNotTheClock(t *testing.T) {
	d := digest("a site")

	var p build
	p.pending("https://alice.example")
	state, height, at, err := Classify(d, p.b)
	if err != nil {
		t.Fatal(err)
	}
	if state != Pending || at != "https://alice.example" || height != 0 {
		t.Errorf("got %s %d %q", state, height, at)
	}

	var b build
	b.bitcoin(812345)
	state, height, _, err = Classify(d, b.b)
	if err != nil {
		t.Fatal(err)
	}
	if state != Anchored || height != 812345 {
		t.Errorf("got %s at %d", state, height)
	}

	// A year-old pending proof is still pending.
	old := Proof{State: Pending,
		SubmittedAt: time.Now().Add(-365 * 24 * time.Hour).Format(time.RFC3339)}
	if old.Anchored() {
		t.Error("a year-old pending proof reported itself as anchored")
	}
	if Age(old, time.Now()) < 300*24*time.Hour {
		t.Error("Age does not report how long it has been waiting")
	}
}

// Reporting pending as anchored would be the same class of lie as a sitemap
// claiming content changed when it did not.
func TestDescribeDoesNotCallPendingAnchored(t *testing.T) {
	p := Proof{State: Pending, PendingAt: "https://alice.example",
		SubmittedAt: time.Now().Format(time.RFC3339)}
	out := Describe(p)
	if !strings.Contains(out, "NOT an anchor") {
		t.Errorf("the description does not say pending is not anchored: %s", out)
	}

	a := Describe(Proof{State: Anchored, Height: 800000})
	if !strings.Contains(a, "800000") {
		t.Errorf("the block is not named: %s", a)
	}
	// And it must point at independent verification rather than implying this
	// program checked the chain.
	if !strings.Contains(a, "ots verify") {
		t.Errorf("the description does not point at independent verification: %s", a)
	}
}

// -- a real calendar's answer ------------------------------------------------

// The fixture is an actual response from alice.btc.calendar.opentimestamps.org.
// Hand-built proofs test the parser against what the format allows; this tests
// it against what a calendar actually sends, which is the thing that has to
// work.
func TestARealCalendarProofParses(t *testing.T) {
	body, err := testdata()
	if err != nil {
		t.Skip("no fixture")
	}
	// The digest that produced it was random and is not recorded; the walk
	// still has to complete and reach a pending attestation naming a calendar.
	atts, err := Walk(make([]byte, 32), body)
	if err != nil {
		t.Fatalf("a real calendar proof does not parse: %v", err)
	}
	var pending bool
	for _, a := range atts {
		if a.Kind == "pending" {
			pending = true
			if !strings.HasPrefix(a.URI, "https://") {
				t.Errorf("the calendar URL is %q", a.URI)
			}
			// Deliberately not asserting 32. A real proof ends
			// `prepend 4, append 8` with no closing hash, so the calendar's
			// key is 44 bytes — the natural assumption is wrong and this test
			// found it.
			if len(a.Commitment) == 0 {
				t.Error("the commitment is empty")
			}
			t.Logf("calendar %s, commitment %s", a.URI,
				hex.EncodeToString(a.Commitment)[:16])
		}
	}
	if !pending {
		t.Error("no pending attestation in a fresh calendar proof")
	}
}

// A 404 from a calendar is the ordinary case — the hash is queued and not yet
// in a block. Reporting it as an error trains people to ignore this command's
// output, which is the one place a genuine failure would appear.
func TestWaitingIsDistinguishableFromBroken(t *testing.T) {
	var p build
	p.pending("https://alice.example")
	proof := Proof{
		Digest: hex.EncodeToString(digest("site")), Body: p.b, State: Pending,
		PendingAt: "https://alice.example",
	}

	_, err := Upgrade(context.Background(), stub{err: errors.New(
		"https://alice.example/timestamp/abc returned 404")}, proof, time.Now())
	if !errors.Is(err, ErrNotYet) {
		t.Errorf("a 404 was reported as %v rather than as waiting", err)
	}

	_, err = Upgrade(context.Background(), stub{err: errors.New(
		"connection refused")}, proof, time.Now())
	if errors.Is(err, ErrNotYet) {
		t.Error("a real failure was reported as waiting")
	}
}

// An upgrade must not accept a continuation that does not extend this proof —
// otherwise a hostile calendar could hand back an attestation for somebody
// else's content and it would be stored as this site's anchor.
func TestAnUpgradeThatDoesNotVerifyIsRefused(t *testing.T) {
	var p build
	p.pending("https://alice.example")
	proof := Proof{
		Digest: hex.EncodeToString(digest("site")), Body: p.b, State: Pending,
		PendingAt: "https://alice.example",
	}
	_, err := Upgrade(context.Background(),
		stub{body: []byte{0x99, 0x99, 0x99}}, proof, time.Now())
	if err == nil {
		t.Fatal("a continuation that does not parse was accepted")
	}
}

type stub struct {
	body []byte
	err  error
}

func (s stub) Post(ctx context.Context, url string, b []byte) ([]byte, error) {
	return s.body, s.err
}
func (s stub) Get(ctx context.Context, url string) ([]byte, error) {
	return s.body, s.err
}
