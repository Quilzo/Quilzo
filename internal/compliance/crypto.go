// Package compliance produces the evidence an enterprise buyer asks for.
//
// # Why this is generated rather than written
//
// Every claim here is derived from the program itself: the dependency list from
// the build, the algorithm inventory from what the source imports, the control
// coverage from the posture rules. A compliance document maintained by hand is
// a document that was true when somebody wrote it, and the gap between it and
// the software is invisible until an auditor finds it.
//
// A test asserts that the declared algorithm inventory matches what the source
// actually imports, so the document cannot drift from the program without the
// build failing.
//
// # What is deliberately not claimed
//
// Nothing here is a certification. An SBOM is not a SOC 2 report, a control
// mapping is not an assessment, and a cryptographic inventory is not a
// migration. What these are is the evidence somebody needs before any of that
// is worth starting, produced accurately rather than approximately.
package compliance

import (
	"fmt"
	"sort"
	"strings"
)

// Quantum is what a quantum computer does to an algorithm.
type Quantum string

const (
	// Safe means no known quantum attack changes the practical security.
	Safe Quantum = "safe"
	// Reduced means Grover's algorithm halves the effective strength, which at
	// these sizes still leaves an acceptable margin.
	Reduced Quantum = "reduced"
	// Broken means Shor's algorithm defeats it outright.
	Broken Quantum = "broken"
)

// Use is how an algorithm is used here, which decides how much its being broken
// would matter.
type Use string

const (
	// Generated means this program creates material with it, so its weakness
	// would be this program's problem.
	Generated Use = "generated"
	// Verified means this program only checks material somebody else made, so
	// the choice of algorithm is theirs and the migration is theirs to lead.
	Verified Use = "verified"
)

// Algorithm is one cryptographic primitive in use.
type Algorithm struct {
	Name string `json:"name"`
	// Package is the import that provides it, which is what the test checks
	// against so this list cannot drift from the source.
	Package string  `json:"package"`
	Purpose string  `json:"purpose"`
	Where   string  `json:"where"`
	Use     Use     `json:"use"`
	Quantum Quantum `json:"quantum"`
	Note    string  `json:"note,omitempty"`
}

// Inventory is every algorithm this program uses.
//
// NIST's guidance is that a post-quantum migration begins with an inventory,
// and this is that inventory rather than a plan built on top of one somebody
// has not made yet.
func Inventory() []Algorithm {
	return []Algorithm{
		{
			Name: "SHA-256", Package: "crypto/sha256",
			Purpose: "content addressing, the audit chain, the Merkle log, " +
				"timestamp digests",
			Where: "store, audit, translog, anchor, timestamp",
			Use:   Generated, Quantum: Reduced,
			Note: "Grover reduces preimage resistance to 128 bits, which is " +
				"still beyond reach. Collision resistance falls to about 85 " +
				"bits under a birthday attack with quantum speedup, and the " +
				"consensus is that this remains adequate; SHA-384 is the " +
				"upgrade if that changes.",
		},
		{
			Name: "SHA-384 / SHA-512", Package: "crypto/sha512",
			Purpose: "ID token signatures at the larger sizes",
			Where:   "oidc", Use: Verified, Quantum: Safe,
		},
		{
			Name: "HMAC-SHA256", Package: "crypto/hmac",
			Purpose: "pseudonymising identifiers in the audit log, webhook " +
				"signatures",
			Where: "audit, webhook", Use: Generated, Quantum: Reduced,
			Note: "A 256-bit key gives 128 bits against Grover, which is the " +
				"target strength.",
		},
		{
			Name: "AES-256-GCM", Package: "crypto/aes, crypto/cipher",
			Purpose: "encrypting objects at rest and wrapping data keys",
			Where:   "vault", Use: Generated, Quantum: Reduced,
			Note: "256 bits becomes 128 against Grover, which is why the key " +
				"size is 256 rather than 128.",
		},
		{
			Name: "RSA PKCS#1 v1.5 and PSS", Package: "crypto/rsa",
			Purpose: "signing federated deliveries under RFC 9421, and " +
				"verifying ID token signatures from an identity provider",
			Where: "public, httpsig, oidc", Use: Generated, Quantum: Broken,
			Note: "Shor's algorithm defeats RSA. This entry said the program " +
				"never generated an RSA signature, and that stopped being " +
				"true when federation landed: `quilzo fediverse` generates a " +
				"2048-bit key and every delivery to a follower's inbox is " +
				"signed with it. RSA rather than Ed25519 because that is what " +
				"the installed fediverse verifies. The migration is this " +
				"project's, and it is bounded by what other servers accept: " +
				"a key nobody can verify is a delivery nobody receives.",
		},
		{
			Name: "ECDSA over P-256/384/521", Package: "crypto/ecdsa, crypto/elliptic",
			Purpose: "verifying ID token signatures from an identity provider",
			Where:   "oidc", Use: Verified, Quantum: Broken,
			Note: "Same position as RSA: verified, never generated.",
		},
		{
			Name: "Ed25519", Package: "crypto/ed25519",
			Purpose: "verifying interaction signatures from Discord, and " +
				"HTTP message signatures under RFC 9421",
			Where: "discord, httpsig, crawl", Use: Generated, Quantum: Broken,
			Note: "Signed and verified. internal/httpsig signs Ed25519 for " +
				"any caller that asks — that is what Web Bot Auth uses — and " +
				"no shipped call site passes it yet: the fediverse deliveries " +
				"sign RSA because that is what the installed base verifies. " +
				"Listed as generated anyway, because a signing implementation " +
				"is part of this program's cryptographic surface and a " +
				"document about that surface should overstate it rather than " +
				"understate it. Verification is the older half: Discord signs " +
				"and this holds only the public key, which is the reason to " +
				"prefer a key pair to a shared secret — a public key cannot " +
				"sign anything, so losing it costs nothing, whereas a leaked " +
				"HMAC secret lets somebody forge in both directions.",
		},
		{
			Name: "ML-DSA-65 (FIPS 204)", Package: "crypto/mldsa",
			Purpose: "the second signature on an audit head, so a published " +
				"commitment stays unforgeable after a quantum computer exists",
			Where: "audit", Use: Generated, Quantum: Safe,
			Note: "Alongside Ed25519, not instead of it: a head verifies only " +
				"if both signatures do, so a break in either one forges " +
				"nothing. This is the case where the threat is real rather " +
				"than notional — an audit head is evidence, and evidence is " +
				"looked at years later, so a signature only has to be " +
				"forgeable by the time somebody checks it. Both ends of this " +
				"one are this program, which is why it could be done here and " +
				"not yet for federation.",
		},
		{
			Name: "X.509 / PKIX key parsing", Package: "crypto/x509",
			Purpose: "reading a remote server's published public key out of " +
				"its ActivityPub actor document",
			Where: "httpsig, public, c2pa", Use: Generated, Quantum: Safe,
			Note: "Mostly parsing: it decodes a key somebody else published " +
				"so a signature can be checked against it. RSA keys under " +
				"2048 bits are refused, because below that a signature proves " +
				"less than it appears to. It also issues one certificate -- " +
				"the self-signed identity a C2PA manifest is signed with -- " +
				"which is why this says generated. Quantum computing does not " +
				"weaken a parser; what it weakens is the RSA and Ed25519 " +
				"entries above.",
		},
		{
			Name: "X.509 subject names", Package: "crypto/x509/pkix",
			Purpose: "naming the signer in a C2PA provenance certificate",
			Where:   "c2pa signing identity", Use: Generated, Quantum: Safe,
			Note: "Not cryptography at all: it is the structure holding a " +
				"common name. Listed because the inventory is answered from " +
				"imports, and an import nobody wrote down is the reason an " +
				"inventory drifts from the program.",
		},
		{
			Name: "crypto/rand", Package: "crypto/rand",
			Purpose: "keys, nonces, tokens, state and nonce values, data keys",
			Where:   "auth, vault, oidc, anchor, webhook",
			Use:     Generated, Quantum: Safe,
			Note: "The operating system's CSPRNG. Quantum computing does not " +
				"weaken it; the failure mode is an entropy source that is not " +
				"what it claims, which is a different problem.",
		},
		{
			Name: "constant-time comparison", Package: "crypto/subtle",
			Purpose: "comparing tokens, signatures and nonces",
			Where:   "auth, oidc, webhook, collab",
			Use:     Generated, Quantum: Safe,
			Note: "Not an algorithm; listed because an inventory that omits it " +
				"invites somebody to replace a comparison with ==.",
		},
	}
}

// Posture summarises the inventory in the terms a questionnaire asks.
func Posture() string {
	var b strings.Builder
	inv := Inventory()

	var brokenGenerated, brokenVerified []string
	for _, a := range inv {
		if a.Quantum != Broken {
			continue
		}
		if a.Use == Generated {
			brokenGenerated = append(brokenGenerated, a.Name)
		} else {
			brokenVerified = append(brokenVerified, a.Name)
		}
	}

	if len(brokenGenerated) == 0 {
		b.WriteString("This program generates no material with an algorithm " +
			"a quantum computer defeats.\n\n")
		b.WriteString("Everything it produces — content addresses, the audit " +
			"chain, the Merkle log,\npseudonyms, encryption at rest, webhook " +
			"signatures — rests on hashes and\nsymmetric ciphers, whose " +
			"post-quantum weakening is a halving that the key\nand digest " +
			"sizes here already account for.\n\n")
	} else {
		fmt.Fprintf(&b, "This program generates material with %s, which "+
			"quantum computers defeat.\nThat is a migration this project owns.\n\n",
			strings.Join(brokenGenerated, " and "))
	}

	if len(brokenVerified) > 0 {
		fmt.Fprintf(&b, "It verifies %s, which quantum computers defeat. "+
			"Those signatures\nare made by an identity provider, so the "+
			"algorithm is their choice and the\nmigration is theirs to lead; "+
			"this follows whatever their discovery document\nadvertises and "+
			"will accept a post-quantum algorithm when they publish one.\n\n",
			strings.Join(brokenVerified, " and "))
	}

	b.WriteString("What that means practically: there is no harvest-now, " +
		"decrypt-later exposure,\nbecause nothing confidential is protected by " +
		"an algorithm Shor's algorithm\nbreaks — encryption at rest is " +
		"AES-256 and the store rests on hashes.\n\n")
	if len(brokenGenerated) > 0 {
		b.WriteString("The exposure that does exist is forgery rather than " +
			"disclosure. A signature\nmade today with a broken algorithm can " +
			"be forged once that algorithm falls,\nso a captured delivery " +
			"could be reissued as this site. Rotating the key ends\nthat for " +
			"future deliveries and does not undo it for past ones, which is " +
			"why\nthe migration is worth starting before it is urgent.\n\n")
		b.WriteString("It has started where this program controls both ends. " +
			"An audit head is\nsigned twice, with Ed25519 and with ML-DSA-65, " +
			"and verifies only if both\nsignatures do — so the published " +
			"commitment survives a break in either\nalgorithm. crypto/mldsa " +
			"is in the standard library this program is built\nwith, so that " +
			"cost no dependency. What is left is the traffic with somebody " +
			"else\non the other end — federation, HTTP signatures — where " +
			"the move needs them\nto accept it, and is not this project's " +
			"alone to make.\n")
	}
	return b.String()
}

// Concerns returns the algorithms worth acting on, worst first.
func Concerns() []Algorithm {
	inv := Inventory()
	var out []Algorithm
	for _, a := range inv {
		if a.Quantum == Broken {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		// Generated before verified: one is this project's problem and the
		// other is somebody else's, and a list that mixes them makes the
		// urgent one look the same as the inherited one.
		if out[i].Use != out[j].Use {
			return out[i].Use == Generated
		}
		return out[i].Name < out[j].Name
	})
	return out
}
