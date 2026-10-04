// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/xmldsig"
)

// IdPMetadata is what an identity provider's metadata says about signing
// people in. Nothing in it is trusted until a person has looked at the
// certificate fingerprints and said yes.
type IdPMetadata struct {
	EntityID string
	SSOURL   string
	Certs    []*x509.Certificate
	// WantsSignedRequests is the provider asking for signed requests, which
	// Quilzo does not send.
	WantsSignedRequests bool
}

// Fingerprint is a certificate's SHA-256, as identity providers show it.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// SigningKey is a certificate's public key, if it is one signatures are
// checked with: RSA of 2048 bits or more, or ECDSA on P-256, P-384 or P-521.
func SigningKey(c *x509.Certificate) (crypto.PublicKey, error) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < xmldsig.MinRSABits {
			return nil, fmt.Errorf("the certificate's RSA key is %d bits; at least %d are needed",
				k.N.BitLen(), xmldsig.MinRSABits)
		}
		return k, nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return k, nil
		}
	}
	return nil, fmt.Errorf("the certificate's key is not RSA or ECDSA on a NIST curve")
}

// ParseMetadata reads an identity provider's metadata with the same strict
// reader responses get. Its signature, if any, is not what makes it trusted:
// the fingerprints shown to a person are.
func ParseMetadata(b []byte) (*IdPMetadata, error) {
	doc, err := xmldsig.Read(b)
	if err != nil {
		return nil, err
	}
	ed := doc.Root
	if ed.Is(NSMetadata, "EntitiesDescriptor") {
		var found *xmldsig.Element
		for _, k := range mustElements(ed) {
			if k.Is(NSMetadata, "EntityDescriptor") && idpDescriptor(k) != nil {
				if found != nil {
					return nil, fmt.Errorf("the file describes more than one identity provider; use the one for this application")
				}
				found = k
			}
		}
		ed = found
	}
	if ed == nil || !ed.Is(NSMetadata, "EntityDescriptor") {
		return nil, fmt.Errorf("this is not SAML metadata for an identity provider")
	}
	m := &IdPMetadata{}
	m.EntityID, _ = ed.Attr("entityID")
	if m.EntityID == "" {
		return nil, fmt.Errorf("the metadata has no entityID")
	}
	idp := idpDescriptor(ed)
	if idp == nil {
		return nil, fmt.Errorf("the metadata describes no SAML 2.0 identity provider")
	}
	if v, _ := idp.Attr("WantAuthnRequestsSigned"); v == "true" || v == "1" {
		m.WantsSignedRequests = true
	}
	for _, k := range mustElements(idp) {
		switch {
		case k.Is(NSMetadata, "KeyDescriptor"):
			if use, ok := k.Attr("use"); ok && use != "signing" {
				continue
			}
			for _, ki := range mustElements(k) {
				for _, xd := range mustElements(ki) {
					for _, xc := range mustElements(xd) {
						if !xc.Is(xmldsig.NSDSig, "X509Certificate") {
							continue
						}
						t, err := xc.Text()
						if err != nil {
							return nil, err
						}
						der, err := base64.StdEncoding.DecodeString(strings.Map(dropSpace, t))
						if err != nil {
							return nil, fmt.Errorf("a certificate in the metadata is not base64")
						}
						c, err := x509.ParseCertificate(der)
						if err != nil {
							return nil, fmt.Errorf("a certificate in the metadata does not parse: %v", err)
						}
						m.Certs = append(m.Certs, c)
					}
				}
			}
		case k.Is(NSMetadata, "SingleSignOnService"):
			if b, _ := k.Attr("Binding"); b == BindingRedirect && m.SSOURL == "" {
				m.SSOURL, _ = k.Attr("Location")
			}
		}
	}
	if m.SSOURL == "" {
		return nil, fmt.Errorf("the identity provider offers no HTTP-Redirect sign-in address")
	}
	if u, err := url.Parse(m.SSOURL); err != nil || (u.Scheme != "https" && !loopback(u)) {
		return nil, fmt.Errorf("the sign-in address %q is not https", m.SSOURL)
	}
	if len(m.Certs) == 0 {
		return nil, fmt.Errorf("the metadata has no signing certificate")
	}
	return m, nil
}

func idpDescriptor(ed *xmldsig.Element) *xmldsig.Element {
	for _, k := range mustElements(ed) {
		if k.Is(NSMetadata, "IDPSSODescriptor") {
			if p, _ := k.Attr("protocolSupportEnumeration"); strings.Contains(p, NSProtocol) {
				return k
			}
		}
	}
	return nil
}

// ServiceMetadata is this service's metadata for one provider: its entity
// ID, where responses go, and that assertions must be signed.
func ServiceMetadata(entityID, acs string, validUntil time.Time) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<md:EntityDescriptor xmlns:md="` + NSMetadata + `"`)
	attr(&b, "entityID", entityID)
	attr(&b, "validUntil", validUntil.UTC().Format("2006-01-02T15:04:05Z"))
	b.WriteString(">\n  <md:SPSSODescriptor")
	attr(&b, "AuthnRequestsSigned", "false")
	attr(&b, "WantAssertionsSigned", "true")
	attr(&b, "protocolSupportEnumeration", NSProtocol)
	b.WriteString(">\n    <md:NameIDFormat>" + FormatEmail + "</md:NameIDFormat>\n")
	b.WriteString(`    <md:AssertionConsumerService`)
	attr(&b, "Binding", BindingPOST)
	attr(&b, "Location", acs)
	attr(&b, "index", "0")
	attr(&b, "isDefault", "true")
	b.WriteString("/>\n  </md:SPSSODescriptor>\n</md:EntityDescriptor>\n")
	return []byte(b.String())
}
