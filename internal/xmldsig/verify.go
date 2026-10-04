// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package xmldsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

// The algorithms, by the URI a signature names them with. The allow-list is
// the whole of the choice: a signature naming anything else is refused
// before any key is tried, so the document never decides how it is checked.
const (
	NSDSig       = "http://www.w3.org/2000/09/xmldsig#"
	nsExcC14N    = "http://www.w3.org/2001/10/xml-exc-c14n#"
	AlgExcC14N   = "http://www.w3.org/2001/10/xml-exc-c14n#"
	AlgEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

	AlgRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgRSASHA384   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	AlgRSASHA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	AlgECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	AlgECDSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	AlgECDSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"

	AlgSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	AlgSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	AlgSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
)

// MinRSABits is the smallest RSA key a signature is checked with.
const MinRSABits = 2048

type sigAlg struct {
	hash  crypto.Hash
	ecdsa bool
}

var signatureAlgs = map[string]sigAlg{
	AlgRSASHA256:   {crypto.SHA256, false},
	AlgRSASHA384:   {crypto.SHA384, false},
	AlgRSASHA512:   {crypto.SHA512, false},
	AlgECDSASHA256: {crypto.SHA256, true},
	AlgECDSASHA384: {crypto.SHA384, true},
	AlgECDSASHA512: {crypto.SHA512, true},
}

var digestAlgs = map[string]crypto.Hash{
	AlgSHA256: crypto.SHA256,
	AlgSHA384: crypto.SHA384,
	AlgSHA512: crypto.SHA512,
}

func newHash(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA256:
		return sha256.New()
	case crypto.SHA384:
		return sha512.New384()
	default:
		return sha512.New()
	}
}

// ErrUnsigned means the element carries no signature at all, as distinct
// from one that is wrong.
var ErrUnsigned = errors.New("not signed")

// Verified is a signed element as the signature covered it.
type Verified struct {
	// Element is the signed element read again from Canonical: the only
	// tree a caller should read from. It has no parent and no signature.
	Element *Element
	// Doc is the document Element belongs to, for identifier lookups.
	Doc *Document
	// Canonical is the bytes the digest was computed over.
	Canonical []byte
	// SignatureAlgorithm and Key say how it was signed and which of the
	// trusted keys verified it.
	SignatureAlgorithm string
	Key                int
}

// signature is a parsed ds:Signature, every part of which was required to be
// where it is.
type signature struct {
	el          *Element
	signedInfo  *Element
	siInclusive []string
	sigAlg      string
	refURI      string
	refInclude  []string
	digestAlg   string
	digest      []byte
	value       []byte
}

// VerifyEnveloped checks the one signature that is a direct child of e,
// against the keys trusted for whoever should have signed it, and returns e
// as read from the bytes the signature covers.
//
// keys are *rsa.PublicKey or *ecdsa.PublicKey. Anything in the document's
// own KeyInfo is ignored: a key that arrives with a signature proves only
// that somebody had a key.
func VerifyEnveloped(e *Element, keys []crypto.PublicKey) (*Verified, error) {
	var sigs []*Element
	kids, _ := e.Elements()
	for _, k := range kids {
		if k.Is(NSDSig, "Signature") {
			sigs = append(sigs, k)
		}
	}
	switch len(sigs) {
	case 0:
		return nil, ErrUnsigned
	case 1:
	default:
		return nil, refuse("<%s> carries %d signatures", e.Local, len(sigs))
	}
	if len(keys) == 0 {
		return nil, refuse("no key is trusted for this signer")
	}
	s, err := parseSignature(sigs[0])
	if err != nil {
		return nil, err
	}

	// The reference must name the element the signature sits in. Signature
	// wrapping works by signing one element and presenting another; tying the
	// two together structurally leaves nothing to move.
	id, ok := e.Attr("ID")
	if !ok || id == "" {
		return nil, refuse("<%s> is signed but has no ID", e.Local)
	}
	if s.refURI != "#"+id {
		return nil, refuse("the signature in <%s> refers to %q, not to the element it is in",
			e.Local, s.refURI)
	}

	signedInfo, err := Canonical(s.signedInfo, s.siInclusive, nil)
	if err != nil {
		return nil, err
	}
	alg := signatureAlgs[s.sigAlg]
	h := newHash(alg.hash)
	h.Write(signedInfo)
	sum := h.Sum(nil)
	which := -1
	for i, k := range keys {
		if verifyWith(k, alg, sum, s.value) {
			which = i
			break
		}
	}
	if which < 0 {
		return nil, refuse("the signature does not verify with any trusted key")
	}

	content, err := Canonical(e, s.refInclude, s.el)
	if err != nil {
		return nil, err
	}
	d := newHash(digestAlgs[s.digestAlg])
	d.Write(content)
	if subtle.ConstantTimeCompare(d.Sum(nil), s.digest) != 1 {
		return nil, refuse("the signed content has changed since it was signed")
	}

	// The fixed point. The bytes just hashed are read again, and that tree is
	// what the caller gets. If canonicalising it does not give the same bytes
	// back, the document has two readings, and neither is trusted.
	doc, err := Read(content)
	if err != nil {
		return nil, fmt.Errorf("the signed content does not read back: %w", err)
	}
	again, err := Canonical(doc.Root, s.refInclude, nil)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, content) {
		return nil, refuse("the signed content reads two ways")
	}
	if !doc.Root.Is(e.Space, e.Local) {
		return nil, refuse("the signed content is not the element that was signed")
	}
	if got, _ := doc.Root.Attr("ID"); got != id {
		return nil, refuse("the signed content is not the element that was signed")
	}
	return &Verified{Element: doc.Root, Doc: doc, Canonical: content,
		SignatureAlgorithm: s.sigAlg, Key: which}, nil
}

func verifyWith(k crypto.PublicKey, alg sigAlg, sum, sig []byte) bool {
	switch pub := k.(type) {
	case *rsa.PublicKey:
		if alg.ecdsa || pub.N.BitLen() < MinRSABits {
			return false
		}
		return rsa.VerifyPKCS1v15(pub, alg.hash, sum, sig) == nil
	case *ecdsa.PublicKey:
		if !alg.ecdsa {
			return false
		}
		// XML-DSig writes an ECDSA signature as r then s, each the curve's
		// size, not as the DER sequence crypto/ecdsa reads.
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return false
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(pub, sum, r, s)
	}
	return false
}

// parseSignature reads a ds:Signature, refusing every optional part of the
// standard that SAML does not use. XPath and XSLT transforms, several
// references, manifests, objects and HMAC are all ways a signature can be
// made to cover something other than what it appears to.
func parseSignature(sig *Element) (*signature, error) {
	s := &signature{el: sig}
	parts, mixed := sig.Elements()
	if mixed {
		return nil, refuse("the signature contains stray text")
	}
	if len(parts) < 2 || len(parts) > 3 ||
		!parts[0].Is(NSDSig, "SignedInfo") || !parts[1].Is(NSDSig, "SignatureValue") ||
		(len(parts) == 3 && !parts[2].Is(NSDSig, "KeyInfo")) {
		return nil, refuse("the signature is not SignedInfo, SignatureValue and an optional KeyInfo")
	}
	s.signedInfo = parts[0]
	v, err := b64(parts[1])
	if err != nil {
		return nil, err
	}
	s.value = v

	si, mixed := s.signedInfo.Elements()
	if mixed {
		return nil, refuse("SignedInfo contains stray text")
	}
	if len(si) != 3 || !si[0].Is(NSDSig, "CanonicalizationMethod") ||
		!si[1].Is(NSDSig, "SignatureMethod") || !si[2].Is(NSDSig, "Reference") {
		return nil, refuse("SignedInfo must hold exactly a canonicalisation method, " +
			"a signature method and one reference")
	}
	if s.siInclusive, err = c14nMethod(si[0]); err != nil {
		return nil, err
	}
	alg, err := onlyAlgorithm(si[1])
	if err != nil {
		return nil, err
	}
	if _, ok := signatureAlgs[alg]; !ok {
		return nil, refuse("the signature algorithm %q is not accepted", alg)
	}
	if kids, _ := si[1].Elements(); len(kids) > 0 {
		return nil, refuse("the signature method has parameters")
	}
	s.sigAlg = alg

	ref := si[2]
	for _, a := range ref.Attrs {
		if a.Prefix != "" || (a.Local != "URI" && a.Local != "Id" && a.Local != "Type") {
			return nil, refuse("the reference carries an unexpected attribute %s", a.Local)
		}
	}
	uri, ok := ref.Attr("URI")
	if !ok || !strings.HasPrefix(uri, "#") || len(uri) < 2 {
		return nil, refuse("the reference must name one element by its identifier")
	}
	s.refURI = uri
	rp, mixed := ref.Elements()
	if mixed {
		return nil, refuse("the reference contains stray text")
	}
	if len(rp) != 3 || !rp[0].Is(NSDSig, "Transforms") || !rp[1].Is(NSDSig, "DigestMethod") ||
		!rp[2].Is(NSDSig, "DigestValue") {
		return nil, refuse("the reference must hold transforms, a digest method and a digest")
	}
	tr, mixed := rp[0].Elements()
	if mixed {
		return nil, refuse("the transforms contain stray text")
	}
	if len(tr) != 2 || !tr[0].Is(NSDSig, "Transform") || !tr[1].Is(NSDSig, "Transform") {
		return nil, refuse("the transforms must be exactly enveloped-signature then " +
			"exclusive canonicalisation")
	}
	first, err := onlyAlgorithm(tr[0])
	if err != nil {
		return nil, err
	}
	if first != AlgEnveloped {
		return nil, refuse("the first transform is %q, not enveloped-signature", first)
	}
	if kids, _ := tr[0].Elements(); len(kids) > 0 {
		return nil, refuse("the enveloped-signature transform has parameters")
	}
	if s.refInclude, err = c14nMethod(tr[1]); err != nil {
		return nil, err
	}
	dalg, err := onlyAlgorithm(rp[1])
	if err != nil {
		return nil, err
	}
	if _, ok := digestAlgs[dalg]; !ok {
		return nil, refuse("the digest algorithm %q is not accepted", dalg)
	}
	if kids, _ := rp[1].Elements(); len(kids) > 0 {
		return nil, refuse("the digest method has parameters")
	}
	s.digestAlg = dalg
	if s.digest, err = b64(rp[2]); err != nil {
		return nil, err
	}
	if len(s.digest) != digestAlgs[dalg].Size() {
		return nil, refuse("the digest is the wrong length for its algorithm")
	}
	return s, nil
}

// c14nMethod accepts exclusive canonicalisation without comments, with an
// optional InclusiveNamespaces PrefixList, and nothing else.
func c14nMethod(e *Element) ([]string, error) {
	alg, err := onlyAlgorithm(e)
	if err != nil {
		return nil, err
	}
	if alg != AlgExcC14N {
		return nil, refuse("the canonicalisation %q is not accepted; only exclusive "+
			"canonicalisation without comments is", alg)
	}
	kids, mixed := e.Elements()
	if mixed {
		return nil, refuse("the canonicalisation method contains stray text")
	}
	switch len(kids) {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, refuse("the canonicalisation method has unexpected parameters")
	}
	in := kids[0]
	if !in.Is(nsExcC14N, "InclusiveNamespaces") || len(in.Children) > 0 {
		return nil, refuse("the canonicalisation method has unexpected parameters")
	}
	var list string
	for _, a := range in.Attrs {
		if a.Prefix != "" || a.Local != "PrefixList" {
			return nil, refuse("InclusiveNamespaces carries an unexpected attribute")
		}
		list = a.Value
	}
	out := strings.Fields(list)
	// Every element consults the list, so its length multiplies the cost of
	// canonicalising. Real ones name one to three prefixes.
	if len(out) > 16 {
		return nil, refuse("the PrefixList names %d prefixes", len(out))
	}
	for _, p := range out {
		// "#default" is the one entry implementations disagree about:
		// libxml2 leaves the default namespace off a prefixed element that
		// the standard's wording puts it on. No identity provider sends it,
		// and a construct with two readings is refused rather than guessed.
		if p == "#default" {
			return nil, refuse("the PrefixList names #default, which canonicalisers " +
				"disagree about")
		}
		if !isNCName(p) {
			return nil, refuse("%q in the PrefixList is not a prefix", p)
		}
	}
	return out, nil
}

// onlyAlgorithm is the Algorithm attribute of an element that may carry
// nothing else.
func onlyAlgorithm(e *Element) (string, error) {
	if len(e.Attrs) != 1 || e.Attrs[0].Prefix != "" || e.Attrs[0].Local != "Algorithm" {
		return "", refuse("<%s> must carry exactly one Algorithm attribute", e.Local)
	}
	return e.Attrs[0].Value, nil
}

// b64 decodes an element's base64 text, which may be wrapped onto lines.
func b64(e *Element) ([]byte, error) {
	t, err := e.Text()
	if err != nil {
		return nil, err
	}
	t = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, t)
	out, err := base64.StdEncoding.Strict().DecodeString(t)
	if err != nil || len(out) == 0 {
		return nil, refuse("<%s> is not base64", e.Local)
	}
	return out, nil
}
