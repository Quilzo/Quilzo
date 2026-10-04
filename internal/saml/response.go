// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package saml

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/xmldsig"
)

// Limits on what an assertion may carry. Generous for any directory; small
// enough that a response cannot be made into a memory problem.
const (
	maxAttributes = 200
	maxValues     = 100
	maxValue      = 4096
	maxNameID     = 256
)

// ParseResponse checks the base64 SAMLResponse posted to the assertion
// consumer service. requestID is the ID of the request this browser started,
// held server-side and bound to the browser; empty means there was none, and
// the answer is ErrUnsolicited whatever the response says.
func (p *Provider) ParseResponse(samlResponse, requestID string, now time.Time) (*Assertion, error) {
	if len(p.Keys) == 0 || p.EntityID == "" || p.ACS == "" || p.ServiceEntityID == "" {
		return nil, errors.New("this identity provider is not fully configured")
	}
	if len(samlResponse) > base64.StdEncoding.EncodedLen(xmldsig.MaxDocument)+4096 {
		return nil, refuse("the response is larger than any identity provider sends")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Map(dropSpace, samlResponse))
	if err != nil {
		return nil, refuse("the response is not base64")
	}
	doc, err := xmldsig.Read(raw)
	if err != nil {
		return nil, err
	}
	root := doc.Root
	if !root.Is(NSProtocol, "Response") {
		return nil, refuse("the message is a %s, not a Response", root.Local)
	}

	// One assertion in the whole document, as a direct child of the
	// response. Counted over every element, under any namespace, so a second
	// one cannot hide in Extensions, in a signature's Object, or inside the
	// first.
	var assertion *xmldsig.Element
	count := 0
	var walk func(e *xmldsig.Element)
	walk = func(e *xmldsig.Element) {
		if e.Local == "Assertion" || e.Local == "EncryptedAssertion" || e.Local == "Advice" {
			count++
			if e.Is(NSAssertion, "Assertion") && e.Parent == root {
				assertion = e
			}
		}
		kids, _ := e.Elements()
		for _, k := range kids {
			walk(k)
		}
	}
	walk(root)
	for _, k := range mustElements(root) {
		if k.Is(NSAssertion, "EncryptedAssertion") {
			return nil, refuse("the assertion is encrypted. Turn assertion encryption off " +
				"for this application at the identity provider: TLS protects the response, " +
				"and XML Encryption is attack surface Quilzo does not take on")
		}
	}
	if count != 1 || assertion == nil {
		return nil, refuse("a response must hold exactly one assertion; this one has %d", count)
	}

	// Signatures. One that is present and wrong is a refusal, even if the
	// other is good: a signature that fails is somebody's mistake or
	// somebody's attempt, and neither should sign anyone in.
	respV, err := xmldsig.VerifyEnveloped(root, p.Keys)
	respSigned := err == nil
	if err != nil && !errors.Is(err, xmldsig.ErrUnsigned) {
		return nil, err
	}
	asV, err := xmldsig.VerifyEnveloped(assertion, p.Keys)
	asSigned := err == nil
	if err != nil && !errors.Is(err, xmldsig.ErrUnsigned) {
		return nil, err
	}
	if !respSigned && !asSigned {
		return nil, refuse("neither the response nor its assertion is signed")
	}

	// What is read, from here on, is only what a signature covered.
	var a *xmldsig.Element
	if asSigned {
		a = asV.Element
	} else {
		for _, k := range mustElements(respV.Element) {
			if k.Is(NSAssertion, "Assertion") {
				a = k
			}
		}
		if a == nil {
			return nil, refuse("the signed response holds no assertion")
		}
	}
	// The response's own fields: from the signed response when it is
	// signed, otherwise from the document, and then only to refuse more.
	r := root
	if respSigned {
		r = respV.Element
	}
	if err := p.checkResponse(r, respSigned, requestID); err != nil {
		return nil, err
	}
	out, err := p.checkAssertion(a, requestID, now)
	if err != nil {
		return nil, err
	}
	out.ResponseSigned, out.AssertionSigned = respSigned, asSigned
	return out, nil
}

func dropSpace(r rune) rune {
	if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
		return -1
	}
	return r
}

func mustElements(e *xmldsig.Element) []*xmldsig.Element {
	kids, _ := e.Elements()
	return kids
}

func (p *Provider) checkResponse(r *xmldsig.Element, signed bool, requestID string) error {
	if v, _ := r.Attr("Version"); v != "2.0" {
		return refuse("the response is SAML version %q, not 2.0", v)
	}
	dest, has := r.Attr("Destination")
	if has && dest != p.ACS {
		return refuse("the response was sent to %q, not to this service", dest)
	}
	if signed && !has {
		return refuse("a signed response must say where it was sent")
	}
	var status *xmldsig.Element
	for _, k := range mustElements(r) {
		switch {
		case k.Is(NSAssertion, "Issuer"):
			v, err := text(k)
			if err != nil {
				return err
			}
			if v != p.EntityID {
				return refuse("the response is from %q, not %q", v, p.EntityID)
			}
		case k.Is(NSProtocol, "Status"):
			status = k
		}
	}
	if status == nil {
		return refuse("the response has no status")
	}
	if err := statusOf(status); err != nil {
		return err
	}
	if requestID == "" {
		return ErrUnsolicited
	}
	if irt, ok := r.Attr("InResponseTo"); !ok {
		return ErrUnsolicited
	} else if irt != requestID {
		return refuse("the response answers another request")
	}
	return nil
}

func statusOf(status *xmldsig.Element) error {
	var code, second, msg string
	for _, k := range mustElements(status) {
		switch {
		case k.Is(NSProtocol, "StatusCode"):
			code, _ = k.Attr("Value")
			for _, k2 := range mustElements(k) {
				if k2.Is(NSProtocol, "StatusCode") {
					second, _ = k2.Attr("Value")
				}
			}
		case k.Is(NSProtocol, "StatusMessage"):
			msg, _ = k.Text()
		}
	}
	if code == StatusSuccess {
		return nil
	}
	short := func(s string) string { return s[strings.LastIndexByte(s, ':')+1:] }
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return &StatusError{Code: short(code), Second: short(second), Message: strings.TrimSpace(msg)}
}

func text(e *xmldsig.Element) (string, error) {
	t, err := e.Text()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(t), nil
}

func instant(e *xmldsig.Element, name string, required bool) (time.Time, error) {
	v, ok := e.Attr(name)
	if !ok {
		if required {
			return time.Time{}, refuse("<%s> has no %s", e.Local, name)
		}
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, refuse("<%s> %s %q is not a time", e.Local, name, v)
	}
	return t, nil
}

func (p *Provider) checkAssertion(a *xmldsig.Element, requestID string, now time.Time) (*Assertion, error) {
	out := &Assertion{Attributes: map[string][]string{}, FriendlyAttributes: map[string][]string{}}
	if v, _ := a.Attr("Version"); v != "2.0" {
		return nil, refuse("the assertion is SAML version %q, not 2.0", v)
	}
	out.ID, _ = a.Attr("ID")
	issued, err := instant(a, "IssueInstant", true)
	if err != nil {
		return nil, err
	}
	if issued.After(now.Add(Skew)) {
		return nil, refuse("the assertion was issued in the future")
	}
	kids, mixed := a.Elements()
	if mixed {
		return nil, refuse("the assertion contains stray text")
	}
	var subject, conditions *xmldsig.Element
	var authn []*xmldsig.Element
	for i, k := range kids {
		switch {
		case k.Is(NSAssertion, "Issuer"):
			if i != 0 {
				return nil, refuse("the assertion's issuer is not where the schema puts it")
			}
			if f, ok := k.Attr("Format"); ok && f != FormatEntity {
				return nil, refuse("the assertion's issuer is not an entity")
			}
			if out.Issuer, err = text(k); err != nil {
				return nil, err
			}
		case k.Is(NSAssertion, "Subject"):
			if subject != nil {
				return nil, refuse("the assertion has two subjects")
			}
			subject = k
		case k.Is(NSAssertion, "Conditions"):
			if conditions != nil {
				return nil, refuse("the assertion has two sets of conditions")
			}
			conditions = k
		case k.Is(NSAssertion, "AuthnStatement"):
			authn = append(authn, k)
		case k.Is(NSAssertion, "AttributeStatement"):
			if err := attributes(k, out); err != nil {
				return nil, err
			}
		case k.Is(NSAssertion, "AuthzDecisionStatement"), k.Is(NSAssertion, "Statement"):
			// Defined, and never acted on here.
		default:
			return nil, refuse("the assertion holds <%s>, which is not accepted", k.Local)
		}
	}
	if out.Issuer != p.EntityID {
		return nil, refuse("the assertion is from %q, not %q", out.Issuer, p.EntityID)
	}
	if subject == nil {
		return nil, refuse("the assertion names nobody")
	}
	if conditions == nil {
		return nil, refuse("the assertion has no conditions, so no audience")
	}
	if len(authn) == 0 {
		return nil, refuse("the assertion does not say anybody signed in")
	}
	until, err := p.checkSubject(subject, requestID, now, out)
	if err != nil {
		return nil, err
	}
	condUntil, err := p.checkConditions(conditions, now)
	if err != nil {
		return nil, err
	}
	out.Until = until
	if condUntil.After(out.Until) {
		out.Until = condUntil
	}
	if err := authnStatement(authn[0], now, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *Provider) checkSubject(s *xmldsig.Element, requestID string, now time.Time, out *Assertion) (time.Time, error) {
	var until time.Time
	confirmed := false
	var why error
	for _, k := range mustElements(s) {
		switch {
		case k.Is(NSAssertion, "NameID"):
			if out.NameID != "" {
				return until, refuse("the subject has two names")
			}
			v, err := text(k)
			if err != nil {
				return until, err
			}
			if v == "" || len(v) > maxNameID || strings.ContainsAny(v, "\x00\r\n\t") {
				return until, refuse("the subject's name is empty, too long or has control characters")
			}
			out.NameID = v
			out.NameIDFormat, _ = k.Attr("Format")
		case k.Is(NSAssertion, "EncryptedID"), k.Is(NSAssertion, "BaseID"):
			return until, refuse("the subject is named in a way Quilzo does not read (%s)", k.Local)
		case k.Is(NSAssertion, "SubjectConfirmation"):
			if m, _ := k.Attr("Method"); m != MethodBearer {
				continue
			}
			u, err := p.bearer(k, requestID, now)
			if err != nil {
				why = err
				continue
			}
			confirmed = true
			if u.After(until) {
				until = u
			}
		}
	}
	if out.NameID == "" {
		return until, refuse("the subject has no name")
	}
	if !confirmed {
		if why != nil {
			return until, why
		}
		return until, refuse("the subject has no bearer confirmation")
	}
	return until, nil
}

// bearer checks one bearer confirmation: for this service, for this
// request, and not yet expired.
func (p *Provider) bearer(sc *xmldsig.Element, requestID string, now time.Time) (time.Time, error) {
	var data *xmldsig.Element
	for _, k := range mustElements(sc) {
		if k.Is(NSAssertion, "SubjectConfirmationData") {
			if data != nil {
				return time.Time{}, refuse("a confirmation has two sets of data")
			}
			data = k
		}
	}
	if data == nil {
		return time.Time{}, refuse("the bearer confirmation has no data")
	}
	if r, _ := data.Attr("Recipient"); r != p.ACS {
		return time.Time{}, refuse("the assertion is for %q, not this service", r)
	}
	irt, has := data.Attr("InResponseTo")
	if requestID == "" || !has {
		return time.Time{}, ErrUnsolicited
	}
	if irt != requestID {
		return time.Time{}, refuse("the assertion answers another request")
	}
	end, err := instant(data, "NotOnOrAfter", true)
	if err != nil {
		return time.Time{}, err
	}
	if !now.Before(end.Add(Skew)) {
		return time.Time{}, refuse("the assertion expired at %s", end.UTC().Format(time.RFC3339))
	}
	start, err := instant(data, "NotBefore", false)
	if err != nil {
		return time.Time{}, err
	}
	if !start.IsZero() && now.Add(Skew).Before(start) {
		return time.Time{}, refuse("the assertion is not valid until %s", start.UTC().Format(time.RFC3339))
	}
	return end, nil
}

func (p *Provider) checkConditions(c *xmldsig.Element, now time.Time) (time.Time, error) {
	start, err := instant(c, "NotBefore", false)
	if err != nil {
		return time.Time{}, err
	}
	if !start.IsZero() && now.Add(Skew).Before(start) {
		return time.Time{}, refuse("the assertion is not valid until %s", start.UTC().Format(time.RFC3339))
	}
	end, err := instant(c, "NotOnOrAfter", false)
	if err != nil {
		return time.Time{}, err
	}
	if !end.IsZero() && !now.Before(end.Add(Skew)) {
		return time.Time{}, refuse("the assertion expired at %s", end.UTC().Format(time.RFC3339))
	}
	restrictions := 0
	for _, k := range mustElements(c) {
		switch {
		case k.Is(NSAssertion, "AudienceRestriction"):
			restrictions++
			ok := false
			for _, au := range mustElements(k) {
				if !au.Is(NSAssertion, "Audience") {
					return time.Time{}, refuse("an audience restriction holds <%s>", au.Local)
				}
				if v, err := text(au); err == nil && v == p.ServiceEntityID {
					ok = true
				}
			}
			if !ok {
				return time.Time{}, refuse("the assertion is meant for another service")
			}
		case k.Is(NSAssertion, "OneTimeUse"), k.Is(NSAssertion, "ProxyRestriction"):
			// Every assertion is used once here anyway; proxying is not done.
		default:
			return time.Time{}, refuse("the assertion has a condition Quilzo does not understand (%s), "+
				"and the standard says such an assertion is not valid", k.Local)
		}
	}
	if restrictions == 0 {
		return time.Time{}, refuse("the assertion does not say which service it is for")
	}
	return end, nil
}

func authnStatement(s *xmldsig.Element, now time.Time, out *Assertion) error {
	var err error
	if out.AuthnInstant, err = instant(s, "AuthnInstant", true); err != nil {
		return err
	}
	if out.AuthnInstant.After(now.Add(Skew)) {
		return refuse("the sign-in happened in the future")
	}
	out.SessionIndex, _ = s.Attr("SessionIndex")
	if out.SessionNotOnOrAfter, err = instant(s, "SessionNotOnOrAfter", false); err != nil {
		return err
	}
	if !out.SessionNotOnOrAfter.IsZero() && !now.Before(out.SessionNotOnOrAfter) {
		return refuse("the identity provider's session has already ended")
	}
	for _, k := range mustElements(s) {
		if !k.Is(NSAssertion, "AuthnContext") {
			continue
		}
		for _, c := range mustElements(k) {
			if c.Is(NSAssertion, "AuthnContextClassRef") {
				if out.AuthnContext, err = text(c); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func attributes(st *xmldsig.Element, out *Assertion) error {
	for _, at := range mustElements(st) {
		if !at.Is(NSAssertion, "Attribute") {
			if at.Is(NSAssertion, "EncryptedAttribute") {
				continue // never decrypted, never read
			}
			return refuse("an attribute statement holds <%s>", at.Local)
		}
		name, _ := at.Attr("Name")
		if name == "" {
			return refuse("an attribute has no name")
		}
		if len(out.Attributes) >= maxAttributes {
			return refuse("more than %d attributes", maxAttributes)
		}
		friendly, _ := at.Attr("FriendlyName")
		for _, v := range mustElements(at) {
			if !v.Is(NSAssertion, "AttributeValue") {
				continue
			}
			t, err := v.Text()
			if err != nil {
				continue // a structured value is not a string, and is not guessed at
			}
			if len(t) > maxValue || len(out.Attributes[name]) >= maxValues {
				return refuse("the attribute %q is larger than any directory sends", name)
			}
			t = strings.TrimSpace(t)
			out.Attributes[name] = append(out.Attributes[name], t)
			if friendly != "" {
				out.FriendlyAttributes[friendly] = append(out.FriendlyAttributes[friendly], t)
			}
		}
	}
	return nil
}
