package c2pa

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"time"
)

// A C2PA manifest: what it claims, and what makes the claim about this file
// rather than about a file.
//
// # The hard binding
//
// The claim holds a c2pa.hash.data assertion: a SHA-256 over the file's bytes
// with the manifest's own bytes excluded. The exclusion is unavoidable --
// embedding a manifest changes the file, so a hash over everything could never
// be computed by the signer or reproduced by a verifier. It is also the part
// most easily got wrong in a way that still validates: an exclusion range
// wider than the manifest hides real bytes from the hash, and a manifest can
// then travel onto content it never described.
//
// So the range is written by the embedder, which is the only code that knows
// where it put the manifest, and the verifier recomputes over the same range
// and compares. Nothing here trusts the range it was handed to be honest about
// its own size: hashing skips exactly the bytes the manifest occupies, and any
// difference shows up as a hash that does not match.
//
// # What it asserts
//
// One action, with a digitalSourceType from the IPTC vocabulary. That is the
// machine-readable half of the EU AI Act Article 50 marking obligation, and it
// is the same vocabulary internal/provenance already records, so a page's
// disclosure and its images say the same thing by construction rather than by
// two people remembering to.

// Claim is what a manifest asserts about one file.
type Claim struct {
	// Title is the file's name as a person would say it.
	Title string
	// Format is the media type of the file this describes.
	Format string
	// DigitalSourceType is an IPTC vocabulary term, matching what
	// internal/provenance records for the page.
	DigitalSourceType string
	// SoftwareAgent names what produced the file.
	SoftwareAgent string
	// Author is the person accountable.
	Author string
	// Model, when a model was involved, and Instruction, which is what
	// somebody actually asked it for.
	Model       string
	Instruction string
	// When the claim was made.
	When time.Time
}

// label is the manifest's identifier inside the store. C2PA wants it unique
// per manifest; a URN with the claim's own digest makes it unique without a
// random source, so two runs over the same input produce the same manifest.
func (c Claim) label(binding []byte) string {
	sum := sha256.Sum256(binding)
	return "urn:uuid:" + hexUUID(sum[:16])
}

func hexUUID(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, v := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hex[v>>4], hex[v&0x0f])
	}
	return string(out)
}

// exclusion is a byte range in the file that the data hash skips.
type exclusion struct {
	start  int
	length int
}

// hashAssertion builds c2pa.hash.data: the hard binding.
//
// original is the file before anything was inserted; declare is where the
// manifest will sit in the file after. Those are two different files, and the
// hash has to be the one a verifier computes over the second.
//
// It works out to a hash of the first. A verifier hashes the finished file
// skipping exactly the inserted range, and skipping exactly what was inserted
// leaves the bytes that were there before -- so the signer can hash the
// original directly rather than assembling a file it has not built yet. That
// identity is the whole reason this is expressible at all, and it holds only
// because the one excluded range is precisely the one insertion. An exclusion
// covering anything else would break it silently, which is why the verifier
// refuses a range that is not where the manifest sits.
func hashAssertion(original []byte, declare []exclusion) (Value, error) {
	sum := sha256.Sum256(original)
	ranges := make(Array, 0, len(declare))
	for _, e := range declare {
		if e.start < 0 || e.length <= 0 {
			return nil, fmt.Errorf("an exclusion range is not a range")
		}
		if e.start > len(original) {
			return nil, fmt.Errorf(
				"an exclusion starts at byte %d and the file is %d bytes long "+
					"before insertion", e.start, len(original))
		}
		ranges = append(ranges, Map{
			"start":  Uint(e.start),
			"length": Uint(e.length),
		})
	}
	return Map{
		"exclusions": ranges,
		"alg":        Text("sha256"),
		"hash":       Bytes(sum[:]),
		"name":       Text("jumbf manifest"),
	}, nil
}

// hashExcluding hashes a file with ranges skipped.
//
// Ranges are sorted and checked for overlap before anything is hashed. Two
// overlapping exclusions would make the hashed byte count depend on the order
// they were applied in, and a signer and a verifier disagreeing about that is
// a valid manifest that fails to validate -- or worse, one that validates over
// fewer bytes than anybody intended.
func hashExcluding(file []byte, skip []exclusion) ([]byte, error) {
	ranges := make([]exclusion, len(skip))
	copy(ranges, skip)
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })

	h := sha256.New()
	at := 0
	for _, e := range ranges {
		if e.length < 0 || e.start < 0 {
			return nil, fmt.Errorf("an exclusion range is negative")
		}
		if e.start < at {
			return nil, fmt.Errorf(
				"exclusion ranges overlap at byte %d, so how many bytes are "+
					"hashed depends on the order they are applied in", e.start)
		}
		if e.start+e.length > len(file) {
			return nil, fmt.Errorf(
				"an exclusion covers bytes %d-%d of a %d-byte file",
				e.start, e.start+e.length, len(file))
		}
		h.Write(file[at:e.start])
		at = e.start + e.length
	}
	h.Write(file[at:])
	return h.Sum(nil), nil
}

// assertionLabels are the labels this writes, in the order the claim lists
// them. C2PA requires the claim's list to match the store.
const (
	labelHash    = "c2pa.hash.data"
	labelActions = "c2pa.actions.v2"
)

// build assembles a signed manifest store for a file.
//
// placeholder is how many bytes the embedder will reserve for the store. The
// store has to be a fixed size before it is built, because the data hash
// excludes it and the exclusion range is part of what gets hashed and signed:
// build, measure, and rebuild would change the hash each time. So the store is
// padded to a size chosen up front, and the padding is inside the excluded
// range where it cannot affect anything.
func (c Claim) build(file []byte, skip []exclusion, chain [][]byte,
	key ed25519.PrivateKey, pad int) ([]byte, error) {

	hash, err := hashAssertion(file, skip)
	if err != nil {
		return nil, err
	}
	hashBytes, err := Encode(hash)
	if err != nil {
		return nil, err
	}

	actions, err := Encode(c.actions())
	if err != nil {
		return nil, err
	}

	// A claim refers to each assertion by a JUMBF URI and the hash of the
	// assertion's own encoded bytes. Referring by URI alone would let the
	// assertion be swapped for another under the same label.
	claim, err := Encode(Map{
		"claim_generator":      Text(c.SoftwareAgent),
		"claim_generator_info": Array{Map{"name": Text(c.SoftwareAgent)}},
		"format":               Text(c.Format),
		"title":                Text(c.Title),
		"alg":                  Text("sha256"),
		"assertions": Array{
			assertionRef(labelHash, hashBytes),
			assertionRef(labelActions, actions),
		},
	})
	if err != nil {
		return nil, err
	}

	signature, err := Sign1(claim, chain, key)
	if err != nil {
		return nil, err
	}

	hashBox, err := cborBox(labelHash, hashBytes)
	if err != nil {
		return nil, err
	}
	actionsBox, err := cborBox(labelActions, actions)
	if err != nil {
		return nil, err
	}
	store, err := superbox(uuidAssertionStore, "c2pa.assertions",
		hashBox, actionsBox)
	if err != nil {
		return nil, err
	}
	claimBox, err := superbox(uuidClaim, "c2pa.claim",
		box{kind: "cbor", payload: claim}.payload8())
	if err != nil {
		return nil, err
	}
	sigBox, err := superbox(uuidSignature, "c2pa.signature",
		box{kind: "cbor", payload: signature}.payload8())
	if err != nil {
		return nil, err
	}
	manifest, err := superbox(uuidManifest, c.label(claim),
		store, claimBox, sigBox)
	if err != nil {
		return nil, err
	}
	contents := [][]byte{manifest}
	if pad > 0 {
		// Padding goes inside the store, so the store's own length field
		// covers it. Outside, the length says less than the container holds,
		// and a JPEG APP11 reader checking one against the other rejects the
		// whole segment -- which is how this was found, since a reader written
		// alongside the writer repeats its mistakes.
		filler, ferr := box{kind: paddingKind, payload: make([]byte, pad)}.bytes()
		if ferr != nil {
			return nil, ferr
		}
		contents = append(contents, filler)
	}
	return superbox(uuidManifestStore, "c2pa", contents...)
}

// actions is the c2pa.actions.v2 assertion.
func (c Claim) actions() Value {
	action := Map{
		"action":            Text(actionFor(c.DigitalSourceType)),
		"when":              Text(c.When.UTC().Format(time.RFC3339)),
		"softwareAgent":     Map{"name": Text(c.SoftwareAgent)},
		"digitalSourceType": Text(iptcURI(c.DigitalSourceType)),
	}
	if c.Author != "" {
		action["author"] = Map{"name": Text(c.Author)}
	}
	if c.Model != "" {
		// The model and the prompt, where C2PA puts the detail behind an
		// action. A model name without the instruction answers a question
		// nobody asks; "why does this image show that" needs both.
		params := Map{"com.quilzo.model": Text(c.Model)}
		if c.Instruction != "" {
			params["com.quilzo.instruction"] = Text(c.Instruction)
		}
		action["parameters"] = params
	}
	return Map{"actions": Array{action}}
}

// actionFor maps a source type to a C2PA action.
//
// Created versus placed matters to a reader: one says this software made the
// pixels, the other says it took them from somewhere.
func actionFor(sourceType string) string {
	switch sourceType {
	case "trainedAlgorithmicMedia", "algorithmicMedia":
		return "c2pa.created"
	case "compositeWithTrainedAlgorithmicMedia":
		return "c2pa.edited"
	default:
		return "c2pa.placed"
	}
}

// iptcURI expands a source type to the IPTC vocabulary URI C2PA requires.
// The bare term is what this program stores; the URI is what the standard
// puts in the assertion.
func iptcURI(sourceType string) string {
	if sourceType == "" {
		return "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
	}
	return "http://cv.iptc.org/newscodes/digitalsourcetype/" + sourceType
}

// assertionRef is one entry in the claim's assertion list.
func assertionRef(label string, body []byte) Value {
	sum := sha256.Sum256(body)
	return Map{
		"url":  Text("self#jumbf=c2pa.assertions/" + label),
		"hash": Bytes(sum[:]),
		"alg":  Text("sha256"),
	}
}

// base64 is used only in error text, where a raw digest would be unreadable.
func shortDigest(b []byte) string {
	s := base64.RawStdEncoding.EncodeToString(b)
	if len(s) > 12 {
		s = s[:12]
	}
	return s
}
