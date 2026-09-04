// Package timestamp proves when something was published.
//
// # Why two mechanisms, not one
//
// A CMS that can prove what it said on a date is useful to anyone publishing
// regulated claims, press statements, prices or terms. There are two ways to do
// it and the research is clear that neither is sufficient alone, because they
// fail in different directions.
//
// **RFC 3161** asks a Time Stamping Authority to sign a hash with the current
// time. Combined with ETSI EN 319 421/422/401 it reaches qualified status under
// eIDAS, which is what gives a timestamp recognised evidential value in an EU
// legal context. Its weakness is that the proof rests on the TSA's certificate
// chain: when that certificate expires the token has to be re-stamped or
// counter-signed, and if the TSA goes out of business every token it ever issued
// lands in a legal grey area.
//
// **Blockchain anchoring** — OpenTimestamps being the usual form — commits a
// hash into a public chain. There is no authority to expire or fold, so the
// proof does not decay. What it lacks is formal legal recognition.
//
// So: legal weight that decays, or durability with no standing. The layered
// approach is the answer the sources converge on, and it is what this is built
// for — a token for the lawyer and an anchor for the decade.
//
// # What is stamped
//
// The publication root, not a page. Content is content-addressed, so the root
// commits to every page at once: one stamp proves the state of the whole site at
// a moment, and any individual page's presence in it is provable from the tree.
// Stamping pages separately would mean n stamps proving less.
//
// # What this verifies, and what it does not
//
// Requesting and storing a token is implemented here. Cryptographically
// verifying one is not, and the honesty matters: an RFC 3161 token is a CMS
// (PKCS#7) signed structure, Go's standard library has no CMS parser, and a
// hand-rolled partial verifier is precisely the kind of thing that looks correct
// and accepts a forgery. A timestamp verifier that is subtly wrong is worse than
// none, because its output is believed.
//
// So tokens are stored intact and exported in the form `openssl ts -verify`
// expects. Verification is delegated to a tool that has been getting this right
// for twenty years.
package timestamp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/quilzo/quilzo/internal/egress"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// The OID for SHA-256, and the one for the id-ct-TSTInfo content type. Named
// rather than inlined because an OID typo produces a request a TSA rejects with
// a message that explains nothing.
var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// messageImprint is the hash being stamped.
type messageImprint struct {
	HashAlgorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	HashedMessage []byte
}

// timeStampReq is RFC 3161 section 2.4.1.
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
}

// pkiStatusInfo is the status half of a response.
type pkiStatusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// timeStampResp is RFC 3161 section 2.4.2. The token is kept raw: parsing a CMS
// structure correctly is a job for a CMS library, and there is not one here.
type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// Stamp is a stored proof about one publication.
type Stamp struct {
	// Root is what was stamped: the fingerprint of the published site.
	Root string `json:"root"`
	// Hash is the SHA-256 actually submitted, hex encoded.
	Hash string `json:"hash"`
	// Authority is the TSA that issued it.
	Authority string `json:"authority"`
	// Token is the raw RFC 3161 token, base64 in JSON.
	Token []byte `json:"token"`
	// RequestedAt is our clock, and is not evidence — the trustworthy time is
	// inside the token. Kept because a mismatch between the two is itself worth
	// noticing.
	RequestedAt string `json:"requested_at"`
	// Anchor holds a blockchain commitment, when one has been made.
	Anchor *Anchor `json:"anchor,omitempty"`
}

// Anchor is a commitment in a public chain.
//
// Deliberately a record of a submission rather than an implementation of one.
// Anchoring properly means talking to calendar servers and later upgrading the
// proof once a block confirms, and a half-built version that reports success
// before confirmation would be claiming durability it has not got.
type Anchor struct {
	Method      string `json:"method"`
	Reference   string `json:"reference"`
	SubmittedAt string `json:"submitted_at"`
	Confirmed   bool   `json:"confirmed"`
	Note        string `json:"note,omitempty"`
}

// Store holds stamps, newest last.
type Store struct {
	Stamps []Stamp `json:"stamps"`
}

// Latest returns the most recent stamp for a root, if there is one.
func (s *Store) Latest(root string) (Stamp, bool) {
	for i := len(s.Stamps) - 1; i >= 0; i-- {
		if s.Stamps[i].Root == root {
			return s.Stamps[i], true
		}
	}
	return Stamp{}, false
}

// DefaultTSA is a free, publicly available authority.
//
// Not qualified under eIDAS. Fine for proving the mechanism and for internal
// evidence; an organisation that needs legal weight configures a qualified TSA,
// and the README says so rather than letting the default imply standing it does
// not have.
const DefaultTSA = "https://freetsa.org/tsr"

// Request asks a TSA to stamp a root and returns the stored proof.
func Request(client *http.Client, tsaURL, root string) (Stamp, error) {
	if strings.TrimSpace(root) == "" {
		return Stamp{}, fmt.Errorf("nothing to stamp: the site has no published root")
	}
	if tsaURL == "" {
		tsaURL = DefaultTSA
	}
	if client == nil {
		client = egress.Client("timestamp", 30*time.Second)
	}

	sum := sha256.Sum256([]byte(root))

	// A nonce ties this response to this request. Without one a TSA — or anyone
	// between — can replay an older token, and the proof would be of a moment
	// nobody asked about.
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return Stamp{}, err
	}

	var req timeStampReq
	req.Version = 1
	req.MessageImprint.HashAlgorithm.Algorithm = oidSHA256
	req.MessageImprint.HashAlgorithm.Parameters = asn1.RawValue{Tag: asn1.TagNull}
	req.MessageImprint.HashedMessage = sum[:]
	req.Nonce = nonce
	// Ask for the signing certificate, or verifying later needs it fetched from
	// somewhere that may not still exist.
	req.CertReq = true

	body, err := asn1.Marshal(req)
	if err != nil {
		return Stamp{}, fmt.Errorf("cannot encode the request: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, tsaURL, bytes.NewReader(body))
	if err != nil {
		return Stamp{}, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")

	resp, err := client.Do(httpReq)
	if err != nil {
		return Stamp{}, fmt.Errorf("the timestamp authority did not answer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Stamp{}, fmt.Errorf("the authority returned %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Stamp{}, err
	}

	var parsed timeStampResp
	if _, err := asn1.Unmarshal(raw, &parsed); err != nil {
		return Stamp{}, fmt.Errorf("the authority's reply is not a timestamp response: %w", err)
	}
	// 0 granted, 1 granted with modifications. Anything else is a refusal, and
	// storing a refused response as a proof would be the worst outcome here.
	if parsed.Status.Status != 0 && parsed.Status.Status != 1 {
		return Stamp{}, fmt.Errorf(
			"the authority refused to stamp this (status %d)", parsed.Status.Status)
	}
	if len(parsed.TimeStampToken.FullBytes) == 0 {
		return Stamp{}, fmt.Errorf("the authority returned no token")
	}

	return Stamp{
		Root:        root,
		Hash:        hex.EncodeToString(sum[:]),
		Authority:   tsaURL,
		Token:       parsed.TimeStampToken.FullBytes,
		RequestedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// WriteToken writes a token in the form `openssl ts -verify` expects.
//
// Exported rather than verified in process, and that is the honest boundary. An
// RFC 3161 token is a CMS signed structure; Go's standard library has no CMS
// parser, and a partial hand-rolled verifier is exactly the sort of code that
// looks right and accepts a forgery. Verification goes to a tool that has been
// doing it correctly for two decades:
//
//	openssl ts -verify -in stamp.tsr -data root.txt -CAfile tsa-chain.pem
func WriteToken(s Stamp, path string) error {
	return os.WriteFile(path, s.Token, 0o644)
}

// WriteStampedData writes the exact bytes the token commits to, so the two can
// be checked together. Verifying a token against the wrong data is the most
// common way a verification "succeeds" while proving nothing.
func WriteStampedData(s Stamp, path string) error {
	return os.WriteFile(path, []byte(s.Root), 0o644)
}

// Describe summarises what a stamp does and does not establish.
func Describe(s Stamp) string {
	var b strings.Builder
	fmt.Fprintf(&b, "root %s stamped by %s\n", short(s.Root), s.Authority)
	fmt.Fprintf(&b, "  requested at %s (our clock, not evidence)\n", s.RequestedAt)
	fmt.Fprintf(&b, "  token %d bytes; the authoritative time is inside it\n", len(s.Token))
	if s.Anchor != nil {
		state := "submitted, not yet confirmed"
		if s.Anchor.Confirmed {
			state = "confirmed"
		}
		fmt.Fprintf(&b, "  anchored via %s: %s\n", s.Anchor.Method, state)
	} else {
		fmt.Fprintf(&b, "  no blockchain anchor: this proof depends on the "+
			"authority's certificate remaining valid\n")
	}
	return b.String()
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

// MarshalStore and UnmarshalStore keep the on-disk shape in one place.
func MarshalStore(s *Store) ([]byte, error) { return json.MarshalIndent(s, "", "  ") }

func UnmarshalStore(b []byte, s *Store) error {
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, s)
}
