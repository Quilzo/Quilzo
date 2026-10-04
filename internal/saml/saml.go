// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package saml signs people in with SAML 2.0, as a service provider, on the
// Web Browser SSO profile: the request goes to the identity provider by
// redirect, the response comes back by POST.
//
// # Where the hard part is
//
// The XML is read by internal/xmldsig, which hands back only what a
// signature covered, read again from the canonical bytes. This package
// applies SAML's rules to that tree and nothing else. It never reads a value
// from the document as received. A Response element is read for its
// Destination, Status and InResponseTo only to refuse more, never to decide
// who somebody is.
//
// # What is checked
//
//	exactly one assertion   anywhere in the document, a direct child of the
//	                        response; no encrypted assertion, no Advice
//	                        (crewjam CVE-2022-41912, Authentik CVE-2026-25922)
//	signed                  the assertion, or a response holding exactly it;
//	                        a signature present and wrong is a refusal even
//	                        when the other one is good
//	issuer                  the response's, when present, and the
//	                        assertion's, which is required, are exactly the
//	                        identity provider's entity ID
//	audience                every AudienceRestriction names this service
//	recipient, destination  exactly this service's assertion consumer URL
//	in response to          the request this browser started; there is no
//	                        unsolicited sign-in (Keycloak CVE-2026-3047)
//	time                    NotBefore and NotOnOrAfter on the conditions and
//	                        the bearer confirmation, with 60 seconds of skew;
//	                        a session the provider ended is not started
//	conditions              one the standard defines that is not understood
//	                        makes the assertion invalid, so unknown ones are
//	                        refused rather than ignored
//	replay                  an assertion is used once (Jenkins CVE-2025-64131)
//
// # What is not here, on purpose
//
// Encrypted assertions (XML Encryption's CBC mode has a padding oracle and
// TLS already protects the response), single logout (SCIM and Shared
// Signals end sessions more reliably), the artifact and SOAP bindings, and
// acting as an identity provider. Inflate is never used on input: responses
// arrive by POST, base64 only, so there is no decompression bomb to defuse
// (gosaml2 CVE-2023-26483).
package saml

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/xmldsig"
)

// Namespaces and fixed values from the SAML 2.0 core and bindings.
const (
	NSProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	NSAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	NSMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"

	BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
	MethodBearer  = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	FormatEntity  = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	FormatEmail   = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
)

// Skew is how far apart this server's clock and the provider's may be.
const Skew = 60 * time.Second

// ErrRefused is every refusal: the response is not acceptable.
var ErrRefused = xmldsig.ErrRefused

// ErrUnsolicited means a response that answers no request this browser
// made. It never signs anybody in; the caller starts a sign-in instead, so
// the tile on an identity provider's dashboard still works, one hop longer.
var ErrUnsolicited = errors.New("unsolicited response")

// StatusError is the identity provider saying no, as distinct from a
// response that is not acceptable.
type StatusError struct{ Code, Second, Message string }

func (e *StatusError) Error() string {
	s := "the identity provider did not sign this person in (" + e.Code
	if e.Second != "" {
		s += ", " + e.Second
	}
	s += ")"
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// Provider is one identity provider and this service as it knows it.
type Provider struct {
	// EntityID is the identity provider's: what Issuer must say.
	EntityID string
	// SSOURL is where requests go, by redirect.
	SSOURL string
	// Keys verify its signatures. Two during a key rollover.
	Keys []crypto.PublicKey

	// ServiceEntityID and ACS are this service: what Audience, Recipient and
	// Destination must say.
	ServiceEntityID, ACS string

	// NameIDFormat, when set, is asked for in the request.
	NameIDFormat string
	// ForceAuthn asks the provider to sign the person in again rather than
	// reuse its own session.
	ForceAuthn bool
	// AuthnContexts, when set, are asked for in the request
	// (Comparison="minimum"); whether the answer satisfied them is the
	// caller's to check against Assertion.AuthnContext.
	AuthnContexts []string
}

// Assertion is what a verified assertion says.
type Assertion struct {
	ID, Issuer           string
	NameID, NameIDFormat string
	SessionIndex         string
	AuthnInstant         time.Time
	AuthnContext         string
	// SessionNotOnOrAfter is when the provider says this session ends;
	// zero when it does not say.
	SessionNotOnOrAfter time.Time
	// Until is the latest moment any part of the assertion is valid, which
	// is how long its ID must be remembered against replay.
	Until time.Time
	// Attributes by Name, and by FriendlyName where one is given.
	Attributes         map[string][]string
	FriendlyAttributes map[string][]string
	// ResponseSigned and AssertionSigned say which signatures there were.
	ResponseSigned, AssertionSigned bool
}

// Attribute is the first value of an attribute, by Name or FriendlyName.
func (a *Assertion) Attribute(name string) string {
	if v := a.Attributes[name]; len(v) > 0 {
		return v[0]
	}
	if v := a.FriendlyAttributes[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}
