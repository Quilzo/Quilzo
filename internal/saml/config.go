// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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
	// MFAContexts, or MFAAttribute holding one of MFAValues, is how this
	// provider says a sign-in used more than one factor. A sign-in it does
	// not say that about is one factor, and the person confirms it with
	// their passkey. The contexts are read, never asked for: a provider
	// that cannot meet a requested context refuses the sign-in.
	MFAContexts  []string `json:"mfa_contexts,omitempty"`
	MFAAttribute string   `json:"mfa_attribute,omitempty"`
	MFAValues    []string `json:"mfa_values,omitempty"`
	// VerifiedAttribute names the attribute in which this provider says it
	// verified the address it signs somebody in as, the counterpart of
	// OIDC's email_verified; a sign-in as an address it does not say "true"
	// about is refused. Without one, an email_verified attribute saying
	// anything but true is still believed. SAML has no such notion of its
	// own, and the NameID was taken as sent: a Keycloak user who set their
	// own address, unverified, to a colleague's signed in here as that
	// colleague while OIDC refused them. AllowUnverified takes the address
	// as sent, as oidc configure --allow-unverified-email does: an
	// operator's decision.
	VerifiedAttribute string `json:"verified_attribute,omitempty"`
	AllowUnverified   bool   `json:"allow_unverified,omitempty"`

	NameIDFormat string `json:"name_id_format,omitempty"`
	ForceAuthn   bool   `json:"force_authn,omitempty"`
	Preset       string `json:"preset,omitempty"`
	Added        int64  `json:"added,omitempty"`
	AddedBy      string `json:"added_by,omitempty"`
}

// Preset is what is known about a kind of identity provider: its name, the
// attribute that proves more than one factor, the one that says an address
// was verified, and where to set Quilzo up.
type Preset struct {
	Label        string
	MFAContexts  []string
	MFAAttribute string
	MFAValues    []string
	NameIDFormat string
	// VerifiedAttribute is set for a provider whose people can change
	// their own address and leave it unverified.
	VerifiedAttribute string
	Where             string
}

// UsePreset takes what a preset knows. One place for the command line and
// the admin's form, so a field a preset gains reaches both.
func (c *Config) UsePreset(p Preset) {
	c.Label, c.MFAContexts, c.MFAAttribute, c.MFAValues, c.NameIDFormat, c.VerifiedAttribute =
		p.Label, p.MFAContexts, p.MFAAttribute, p.MFAValues, p.NameIDFormat, p.VerifiedAttribute
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
	// Okta sends no multi-factor context, but sends session.amr (pwd, mfa,
	// ...) as an attribute statement named amr.
	"okta": {Label: "Okta", MFAAttribute: "amr", MFAValues: []string{"mfa"}, NameIDFormat: FormatEmail,
		Where: "Applications > Create App Integration > SAML 2.0; add the attribute statement amr = session.amr"},
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
	// Keycloak lets a person change their own address in the account
	// console, unverified unless the realm verifies email, and signs them in
	// as it; it says whether it verified the address only when a mapper
	// sends it.
	"keycloak": {Label: "Keycloak", MFAContexts: []string{refedsMFA}, NameIDFormat: FormatEmail,
		VerifiedAttribute: "email_verified",
		Where: "Clients > Create client > SAML; add a User Property mapper, property emailVerified, " +
			"SAML attribute name email_verified"},
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
	return &Provider{EntityID: c.EntityID, SSOURL: c.SSOURL, Keys: keys,
		ServiceEntityID: c.ServiceEntityID(), ACS: c.ACS(), NameIDFormat: c.NameIDFormat,
		ForceAuthn: c.ForceAuthn}, nil
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
	// Only an address is what a provider verifies. A username or an opaque
	// NameID is not what email_verified speaks of, and OIDC asks it only of
	// the email claim: a provider set up with --principal attribute:uid
	// refused everybody whose address it had not verified, though the
	// address was not who they became here.
	if strings.Contains(v, "@") {
		if err := c.verified(a, v); err != nil {
			return "", err
		}
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

// Called is what this provider is called to the people who sign in through
// it and to whoever reads a refusal: its label, or the name it was added
// under. A provider added without a preset or a label was "the identity
// provider" on its sign-in button and in every refusal, so two of them
// read the same, and a sentence that began with it began in lower case.
func (c *Config) Called() string {
	switch {
	case c.Label != "":
		return c.Label
	case c.Name != "":
		return c.Name
	}
	return "the identity provider"
}

// VerifiedUnasked is the attribute this kind of provider says it verified
// an address in, when this one was set up without it and nobody decided to
// take addresses as sent; empty otherwise.
//
// A preset is copied when a provider is added, so a Keycloak added before
// its preset asked for email_verified still signs in an address it has not
// verified, as long as it says nothing either way. Asking for the attribute
// now would refuse everybody until the realm sends it, so this is reported
// (the posture scan's sso.unverified-addresses) rather than imposed.
func (c *Config) VerifiedUnasked() string {
	if c.AllowUnverified || c.VerifiedAttribute != "" {
		return ""
	}
	return Presets[c.Preset].VerifiedAttribute
}

// verified refuses an address the provider has not said it verified, when
// it was set up to say so, and one it says it has not, whatever it was set
// up with; see VerifiedAttribute.
func (c *Config) verified(a *Assertion, who string) error {
	if c.AllowUnverified {
		return nil
	}
	name := c.VerifiedAttribute
	if name == "" {
		name = "email_verified"
	}
	said := strings.TrimSpace(a.Attribute(name))
	if strings.EqualFold(said, "true") || said == "1" || (said == "" && c.VerifiedAttribute == "") {
		return nil
	}
	by := c.Called()
	if said == "" {
		return fmt.Errorf("%s did not say whether it verified %s. It is set up to say so in the "+
			"attribute %s; an unverified address is a claim by whoever set it, and honouring it would "+
			"let somebody choose which principal to be", by, who, name)
	}
	return fmt.Errorf("%s has not verified %s (%s is %q). An unverified address is a claim by "+
		"whoever set it, and honouring it would let somebody choose which principal to be", by, who, name, said)
}

// SaysMFA reports whether this provider has a way to say a sign-in used
// more than one factor.
func (c *Config) SaysMFA() bool {
	return len(c.MFAContexts) > 0 || (c.MFAAttribute != "" && len(c.MFAValues) > 0)
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
