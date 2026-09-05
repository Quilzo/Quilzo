package c2pa

import (
	"crypto/ed25519"
	"fmt"
)

// COSE_Sign1, which is how a C2PA claim is signed.
//
// The structure on the wire is a four-element array -- protected headers as a
// byte string, unprotected headers as a map, the payload, the signature --
// carried under tag 18. What is actually signed is none of those directly but
// a separate structure built from them:
//
//	Sig_structure = ["Signature1", protected, external_aad, payload]
//
// The indirection is the point. Signing the payload alone would leave the
// headers unauthenticated, and the headers say which algorithm and which
// certificate -- so an attacker who could rewrite them could describe the same
// signature bytes as something they are not. RFC 9052 §4.4.
//
// Only EdDSA over Ed25519 is implemented. C2PA's list is longer, but a second
// algorithm here would be a second way to be wrong about which one a signature
// was made with, and Ed25519 is in the standard library.

// COSE header labels. Small integers, from the IANA registry.
const (
	headerAlg     = 1  // which algorithm signed
	headerX5Chain = 33 // the signer's certificate chain
)

// algEdDSA is -8 in the COSE algorithm registry.
const algEdDSA = -8

// Sign1 builds a COSE_Sign1 over payload.
//
// chain is the signer's certificates in DER, leaf first. C2PA requires one: a
// bare public key would make the manifest self-referential, saying only that
// whoever made it had a key.
func Sign1(payload []byte, chain [][]byte, key ed25519.PrivateKey) ([]byte, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("a claim signature needs a certificate chain; " +
			"a signature that names no signer identifies nobody")
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("the signing key is %d bytes, not an Ed25519 key",
			len(key))
	}

	// Header labels are integers, and this encoder's maps are text-keyed --
	// deliberately, since every C2PA structure above this one uses text keys.
	// So the protected header is built as an explicit key/value array rather
	// than pretending an integer key is a string.
	protectedBytes, err := encodeIntMap([]intEntry{
		{key: headerAlg, value: Int(algEdDSA)},
		{key: headerX5Chain, value: chainValue(chain)},
	})
	if err != nil {
		return nil, fmt.Errorf("cannot encode the protected headers: %w", err)
	}

	toSign, err := sigStructure(protectedBytes, payload)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, toSign)

	body, err := encodeArrayWithIntMap(protectedBytes, payload, sig)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// Verify1 checks a COSE_Sign1 and returns the payload it covers.
//
// The public key is supplied by the caller rather than read from the x5chain
// in the message. A signature verified against a key the message chose is a
// signature that verifies against whatever key the attacker attached.
func Verify1(msg []byte, key ed25519.PublicKey) ([]byte, error) {
	v, err := Decode(msg)
	if err != nil {
		return nil, fmt.Errorf("the claim signature is not CBOR: %w", err)
	}
	if t, ok := v.(Tagged); ok {
		if t.Tag != 18 {
			return nil, fmt.Errorf("the claim signature carries tag %d, and "+
				"COSE_Sign1 is 18", t.Tag)
		}
		v = t.Value
	}
	arr, ok := v.(Array)
	if !ok || len(arr) != 4 {
		return nil, fmt.Errorf("a COSE_Sign1 is a four-element array")
	}
	protected, ok := arr[0].(Bytes)
	if !ok {
		return nil, fmt.Errorf("the protected headers are not a byte string")
	}
	payload, ok := arr[2].(Bytes)
	if !ok {
		return nil, fmt.Errorf("the payload is not a byte string")
	}
	sig, ok := arr[3].(Bytes)
	if !ok {
		return nil, fmt.Errorf("the signature is not a byte string")
	}

	// The algorithm comes from the protected headers, and has to be the one
	// this key is. Reading it to decide how to verify would let the message
	// pick the check applied to it.
	alg, err := algorithmOf(protected)
	if err != nil {
		return nil, err
	}
	if alg != algEdDSA {
		return nil, fmt.Errorf("the claim is signed with COSE algorithm %d, "+
			"and this verifies EdDSA (%d) only", alg, algEdDSA)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the verifying key is not an Ed25519 key")
	}

	toSign, err := sigStructure(protected, payload)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, toSign, sig) {
		return nil, fmt.Errorf("the claim signature does not verify, so " +
			"nothing this manifest says about the file is evidence")
	}
	return payload, nil
}

// sigStructure builds the bytes a COSE_Sign1 signature is actually over.
//
// external_aad is empty for C2PA: there is no context outside the manifest
// that both sides already agree on.
func sigStructure(protected, payload []byte) ([]byte, error) {
	return Encode(Array{
		Text("Signature1"),
		Bytes(protected),
		Bytes(nil),
		Bytes(payload),
	})
}

// -- integer-keyed maps -------------------------------------------------------
//
// COSE headers are keyed by small integers. The rest of C2PA is text-keyed, so
// rather than widen Map's key type -- which would make every text-keyed map in
// this package able to hold something it must never hold -- integer maps are
// built here, in the one place that needs them.

type intEntry struct {
	key   int64
	value Value
}

func encodeIntMap(entries []intEntry) ([]byte, error) {
	e := &encoder{}
	e.head(5, uint64(len(entries)))
	for _, ent := range entries {
		if err := Int(ent.key).encode(e); err != nil {
			return nil, err
		}
		if ent.value == nil {
			return nil, fmt.Errorf("header %d holds nothing", ent.key)
		}
		if err := ent.value.encode(e); err != nil {
			return nil, err
		}
	}
	return e.out, nil
}

// algorithmOf reads label 1 out of an encoded protected header map.
//
// Decoded by hand because the general decoder refuses non-text map keys, which
// is the right rule everywhere else in a C2PA manifest.
func algorithmOf(protected []byte) (int64, error) {
	d := &decoder{in: protected}
	if d.at >= len(d.in) {
		return 0, fmt.Errorf("the protected headers are empty")
	}
	b := d.in[d.at]
	if b>>5 != 5 {
		return 0, fmt.Errorf("the protected headers are not a map")
	}
	d.at++
	n, err := d.argument(b & 0x1f)
	if err != nil {
		return 0, err
	}
	for i := uint64(0); i < n; i++ {
		k, kerr := d.intKey()
		if kerr != nil {
			return 0, kerr
		}
		v, verr := d.value(1)
		if verr != nil {
			return 0, verr
		}
		if k == headerAlg {
			switch a := v.(type) {
			case Int:
				return int64(a), nil
			case Uint:
				return int64(a), nil
			}
			return 0, fmt.Errorf("the algorithm header is not an integer")
		}
	}
	return 0, fmt.Errorf("the protected headers name no algorithm")
}

func (d *decoder) intKey() (int64, error) {
	if d.at >= len(d.in) {
		return 0, fmt.Errorf("a header key runs past the end")
	}
	b := d.in[d.at]
	major := b >> 5
	if major != 0 && major != 1 {
		return 0, fmt.Errorf("a COSE header key is not an integer")
	}
	d.at++
	arg, err := d.argument(b & 0x1f)
	if err != nil {
		return 0, err
	}
	if major == 0 {
		return int64(arg), nil
	}
	return -1 - int64(arg), nil
}

// chainValue renders x5chain: one certificate is its bytes, several are an
// array of them. The single-certificate shortcut is in RFC 9360 §2, and
// verifiers reject the wrong shape.
func chainValue(chain [][]byte) Value {
	if len(chain) == 1 {
		return Bytes(chain[0])
	}
	out := make(Array, 0, len(chain))
	for _, c := range chain {
		out = append(out, Bytes(c))
	}
	return out
}

// encodeArrayWithIntMap writes the COSE_Sign1 array under tag 18.
//
// The unprotected header map is empty. Everything this manifest asserts is
// covered by the signature, and a header outside it is a place to put something
// a reader might believe and a signer never said.
func encodeArrayWithIntMap(protected, payload, sig []byte) ([]byte, error) {
	e := &encoder{}
	e.head(6, 18) // COSE_Sign1
	e.head(4, 4)  // four elements
	if err := (Bytes(protected)).encode(e); err != nil {
		return nil, err
	}
	e.head(5, 0) // unprotected: {}
	if err := (Bytes(payload)).encode(e); err != nil {
		return nil, err
	}
	if err := (Bytes(sig)).encode(e); err != nil {
		return nil, err
	}
	return e.out, nil
}
