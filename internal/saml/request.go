// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"
)

// NewRequestID is a fresh request identifier: 128 random bits, with the
// leading underscore an xs:ID needs.
func NewRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "_" + hex.EncodeToString(b), nil
}

// AuthnRequestURL is where to send the browser to sign in: the provider's
// SSO URL with the request deflated and encoded as the Redirect binding
// says, and the relay state, which is an opaque key and never a URL.
//
// The request is not signed. A changed request can only ask for a sign-in
// whose answer is checked against what this server stored for the browser,
// so a signature would protect nothing the response checks do not.
func (p *Provider) AuthnRequestURL(id, relayState string, now time.Time) (string, error) {
	if p.SSOURL == "" || p.ACS == "" || p.ServiceEntityID == "" {
		return "", errors.New("this identity provider is not fully configured")
	}
	u, err := url.Parse(p.SSOURL)
	if err != nil || (u.Scheme != "https" && !loopback(u)) {
		return "", errors.New("the identity provider's sign-in address must be https")
	}
	var x strings.Builder
	x.WriteString(`<samlp:AuthnRequest xmlns:samlp="` + NSProtocol + `" xmlns:saml="` + NSAssertion + `"`)
	attr(&x, "ID", id)
	attr(&x, "Version", "2.0")
	attr(&x, "IssueInstant", now.UTC().Format("2006-01-02T15:04:05Z"))
	attr(&x, "Destination", p.SSOURL)
	attr(&x, "AssertionConsumerServiceURL", p.ACS)
	attr(&x, "ProtocolBinding", BindingPOST)
	if p.ForceAuthn {
		attr(&x, "ForceAuthn", "true")
	}
	x.WriteString(`><saml:Issuer>`)
	x.WriteString(escape(p.ServiceEntityID))
	x.WriteString(`</saml:Issuer>`)
	if p.NameIDFormat != "" {
		x.WriteString(`<samlp:NameIDPolicy`)
		attr(&x, "Format", p.NameIDFormat)
		attr(&x, "AllowCreate", "true")
		x.WriteString(`/>`)
	}
	if len(p.AuthnContexts) > 0 {
		x.WriteString(`<samlp:RequestedAuthnContext Comparison="minimum">`)
		for _, c := range p.AuthnContexts {
			x.WriteString(`<saml:AuthnContextClassRef>` + escape(c) + `</saml:AuthnContextClassRef>`)
		}
		x.WriteString(`</samlp:RequestedAuthnContext>`)
	}
	x.WriteString(`</samlp:AuthnRequest>`)

	var z bytes.Buffer
	w, _ := flate.NewWriter(&z, flate.BestCompression)
	_, _ = w.Write([]byte(x.String()))
	_ = w.Close()

	q := u.Query()
	q.Set("SAMLRequest", base64.StdEncoding.EncodeToString(z.Bytes()))
	q.Set("RelayState", relayState)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// loopback allows plain http to a provider on this machine, for a
// development identity provider; nowhere else.
func loopback(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;",
	"\t", "&#x9;", "\n", "&#xA;", "\r", "&#xD;")

func escape(s string) string { return xmlEscaper.Replace(s) }

func attr(b *strings.Builder, name, value string) {
	b.WriteString(" " + name + `="` + escape(value) + `"`)
}
