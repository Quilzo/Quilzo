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
			Purpose: "verifying ID token signatures from an identity provider",
			Where:   "oidc", Use: Verified, Quantum: Broken,
			Note: "Shor's algorithm defeats RSA. This program never generates " +
				"an RSA signature; it verifies ones an identity provider made, " +
				"so the migration is the provider's to lead and this follows " +
				"whatever they advertise in their discovery document.",
		},
		{
			Name: "ECDSA over P-256/384/521", Package: "crypto/ecdsa, crypto/elliptic",
			Purpose: "verifying ID token signatures from an identity provider",
			Where:   "oidc", Use: Verified, Quantum: Broken,
			Note: "Same position as RSA: verified, never generated.",
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
		"decrypt-later exposure\nhere, because nothing long-lived is protected " +
		"by an algorithm Shor's\nalgorithm breaks. The migration work is at " +
		"the identity provider and the\ntimestamp authority, not in this " +
		"program.\n")
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
