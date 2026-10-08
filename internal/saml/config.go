// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package saml

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Config is one identity provider as an operator set it up, stored as
// saml/NAME.json. The certificates in it are the trust: they were shown to a
// person as fingerprints and confirmed before being written here.
type Config struct {
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
	// URL is this admin's address as the identity provider and browsers
	// reach it. The service's entity ID and assertion consumer URL derive
	// from it, so they cannot be set to anything but this server.
	URL      string   `json:"url"`
	EntityID string   `json:"idp_entity_id"`
	SSOURL   string   `json:"sso_url"`
	Certs    []string `json:"certs"`
	// Principal is what becomes the name the access policy knows: "nameid"
	// (the default) or "attribute:NAME".
	Principal string `json:"principal,omitempty"`
	// Domains are the organisation's: a sign-in name must be in one, and a
	// work address in one is sent here from the sign-in page.
	Domains []string `json:"domains,omitempty"`
	// Required means people in Domains must sign in this way; a pasted
	// token or a passkey is refused for them, except for BreakGlass.
	Required   bool     `json:"required,omitempty"`
	BreakGlass []string `json:"break_glass,omitempty"`
	// RequireMFA refuses a sign-in the provider does not say used more
	// than one factor: an AuthnContext in MFAContexts, or MFAAttribute
	// holding one of MFAValues.
	RequireMFA   bool     `json:"require_mfa,omitempty"`
	MFAContexts  []string `json:"mfa_contexts,omitempty"`
	MFAAttribute string   `json:"mfa_attribute,omitempty"`
	MFAValues    []string `json:"mfa_values,omitempty"`

	NameIDFormat string `json:"name_id_format,omitempty"`
	ForceAuthn   bool   `json:"force_authn,omitempty"`
	Preset       string `json:"preset,omitempty"`
	Added        int64  `json:"added,omitempty"`
	AddedBy      string `json:"added_by,omitempty"`
}

// Preset is what is known about a kind of identity provider: its name, the
// attribute that proves more than one factor, and where to set Quilzo up.
type Preset struct {
	Label        string
	MFAContexts  []string
	MFAAttribute string
	MFAValues    []string
	NameIDFormat string
	Where        string
}

const (
	refedsMFA      = "https://refeds.org/profile/mfa"
	msAuthnMethods = "http://schemas.microsoft.com/claims/authnmethodsreferences"
	msMultipleAuth = "http://schemas.microsoft.com/claims/multipleauthn"
)

// PresetOrder is the presets by how widely they are used.
var PresetOrder = []string{"okta", "entra", "google", "jumpcloud", "onelogin", "pingone", "adfs", "keycloak"}

// Presets are the identity providers people use, by key.
var Presets = map[string]Preset{
	"okta": {Label: "Okta", MFAContexts: []string{refedsMFA}, NameIDFormat: FormatEmail,
		Where: "Applications > Create App Integration > SAML 2.0"},
	"entra": {Label: "Microsoft Entra ID", MFAAttribute: msAuthnMethods, MFAValues: []string{msMultipleAuth},
		Where: "Enterprise applications > New application > Create your own > SAML"},
	"google": {Label: "Google Workspace", NameIDFormat: FormatEmail,
		Where: "Admin console > Apps > Web and mobile apps > Add custom SAML app"},
	"jumpcloud": {Label: "JumpCloud", MFAContexts: []string{refedsMFA}, NameIDFormat: FormatEmail,
		Where: "SSO Applications > Add New Application > Custom SAML App"},
	"onelogin": {Label: "OneLogin", MFAContexts: []string{refedsMFA}, NameIDFormat: FormatEmail,
		Where: "Applications > Add App > SAML Custom Connector (Advanced)"},
	"pingone": {Label: "PingOne", MFAContexts: []string{refedsMFA}, NameIDFormat: FormatEmail,
		Where: "Applications > Add Application > SAML Application"},
	"adfs": {Label: "AD FS", MFAAttribute: msAuthnMethods, MFAValues: []string{msMultipleAuth},
		NameIDFormat: FormatEmail, Where: "Relying Party Trusts > Add Relying Party Trust"},
	"keycloak": {Label: "Keycloak", MFAContexts: []string{refedsMFA}, NameIDFormat: FormatEmail,
		Where: "Clients > Create client > SAML"},
}

var reName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

// ServiceEntityID is this service's entity ID for the provider.
func (c *Config) ServiceEntityID() string { return strings.TrimRight(c.URL, "/") + "/saml/" + c.Name }

// ACS is where the provider posts responses.
func (c *Config) ACS() string { return c.ServiceEntityID() + "/acs" }

// MetadataURL is where the provider can read this service's metadata.
func (c *Config) MetadataURL() string { return c.ServiceEntityID() + "/metadata" }

// Validate checks everything a person could have got wrong, before saving.
func (c *Config) Validate() error {
	if !reName.MatchString(c.Name) {
		return errors.New("the name must be lower-case letters, digits and hyphens, starting with a letter")
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" ||
		(u.Scheme != "https" && !loopback(u)) {
		return errors.New("the admin's address must be https://host, with no path, as the identity provider reaches it")
	}
	if c.EntityID == "" || c.SSOURL == "" {
		return errors.New("the identity provider's entity ID and sign-in address are required")
	}
	if s, err := url.Parse(c.SSOURL); err != nil || (s.Scheme != "https" && !loopback(s)) {
		return errors.New("the identity provider's sign-in address must be https")
	}
	if len(c.Certs) == 0 || len(c.Certs) > 3 {
		return errors.New("one to three signing certificates are trusted at a time")
	}
	if _, err := c.Keys(); err != nil {
		return err
	}
	if c.Principal != "" && c.Principal != "nameid" && !strings.HasPrefix(c.Principal, "attribute:") {
		return errors.New(`the principal is "nameid" or "attribute:NAME"`)
	}
	for _, d := range c.Domains {
		if !reDomain.MatchString(d) {
			return fmt.Errorf("%q is not a domain", d)
		}
	}
	if c.Required && len(c.Domains) == 0 {
		return errors.New("requiring single sign-on needs the domains it applies to")
	}
	if c.RequireMFA && len(c.MFAContexts) == 0 && (c.MFAAttribute == "" || len(c.MFAValues) == 0) {
		return errors.New("requiring more than one factor needs the authentication contexts, " +
			"or the attribute and values, that say so")
	}
	return nil
}

var reDomain = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// Certificates are the trusted certificates, parsed.
func (c *Config) Certificates() ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, s := range c.Certs {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, errors.New("a stored certificate is not base64")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("a stored certificate does not parse: %v", err)
		}
		out = append(out, cert)
	}
	return out, nil
}

// Keys are the public keys signatures are checked with.
func (c *Config) Keys() ([]crypto.PublicKey, error) {
	certs, err := c.Certificates()
	if err != nil {
		return nil, err
	}
	var out []crypto.PublicKey
	for _, cert := range certs {
		k, err := SigningKey(cert)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// Provider is the configuration as the protocol code needs it.
func (c *Config) Provider() (*Provider, error) {
	keys, err := c.Keys()
	if err != nil {
		return nil, err
	}
	var contexts []string
	if c.RequireMFA {
		contexts = c.MFAContexts
	}
	return &Provider{EntityID: c.EntityID, SSOURL: c.SSOURL, Keys: keys,
		ServiceEntityID: c.ServiceEntityID(), ACS: c.ACS(), NameIDFormat: c.NameIDFormat,
		ForceAuthn: c.ForceAuthn, AuthnContexts: contexts}, nil
}

// PrincipalOf is the name the access policy knows this person by: the
// NameID or the configured attribute, lower-cased, and in one of the
// organisation's domains when it has named them.
func (c *Config) PrincipalOf(a *Assertion) (string, error) {
	v := a.NameID
	if attr, ok := strings.CutPrefix(c.Principal, "attribute:"); ok {
		v = a.Attribute(attr)
		if v == "" {
			return "", fmt.Errorf("the identity provider did not send the attribute %q", attr)
		}
	}
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || len(v) > 254 || strings.ContainsAny(v, " \t\r\n\x00<>\"") {
		return "", errors.New("the identity provider sent a name that cannot be anybody's")
	}
	if len(c.Domains) > 0 {
		local, domain, ok := strings.Cut(v, "@")
		if !ok || local == "" || strings.Contains(domain, "@") {
			return "", fmt.Errorf("%s is not an address in %s", v, strings.Join(c.Domains, " or "))
		}
		in := false
		for _, d := range c.Domains {
			in = in || domain == d
		}
		if !in {
			return "", fmt.Errorf("%s is not in %s", v, strings.Join(c.Domains, " or "))
		}
	}
	return v, nil
}

// MFA reports whether the assertion says more than one factor was used,
// in a way this provider was configured to say it.
func (c *Config) MFA(a *Assertion) bool {
	for _, want := range c.MFAContexts {
		if a.AuthnContext == want {
			return true
		}
	}
	if c.MFAAttribute != "" {
		for _, got := range a.Attributes[c.MFAAttribute] {
			for _, want := range c.MFAValues {
				if got == want {
					return true
				}
			}
		}
	}
	return false
}

// Owns reports whether a work address is in this provider's domains.
func (c *Config) Owns(address string) bool {
	_, domain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(address)), "@")
	if !ok {
		return false
	}
	for _, d := range c.Domains {
		if domain == d {
			return true
		}
	}
	return false
}

// SessionTTL is how long a session from this assertion may last: the
// default, or less when the provider says its own session ends sooner.
func SessionTTL(a *Assertion, def time.Duration, now time.Time) time.Duration {
	if a.SessionNotOnOrAfter.IsZero() {
		return def
	}
	if left := a.SessionNotOnOrAfter.Sub(now); left < def {
		return left
	}
	return def
}

// Expiring are the trusted certificates that end within the window, for a
// warning before a provider's key change becomes an outage.
func (c *Config) Expiring(now time.Time, window time.Duration) []*x509.Certificate {
	certs, _ := c.Certificates()
	var out []*x509.Certificate
	for _, cert := range certs {
		if cert.NotAfter.Before(now.Add(window)) {
			out = append(out, cert)
		}
	}
	return out
}
