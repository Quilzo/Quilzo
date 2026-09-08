// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package httpsig

import (
	"crypto"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// The signature the fediverse actually sends.
//
// # Why this exists at all
//
// RFC 9421 is the standard, and this program signs and verifies it. Almost
// nothing on the fediverse speaks it. Mastodon gained RFC 9421 verification in
// June 2025; Pleroma, Akkoma, Misskey, GoToSocial and every Mastodon before
// that send draft-cavage-http-signatures-12 -- an expired Internet-Draft that
// became the de facto protocol because ActivityPub shipped on it.
//
// So an inbox that speaks only RFC 9421 refuses essentially every real
// delivery, and does it with a message about halves of signatures that tells
// the sender nothing they can act on. That was the state of this program: a
// federation feature that could not receive.
//
// # Why the two cannot simply both be sent
//
// They collide. RFC 9421 puts a structured-field dictionary in `Signature`
// (`sig1=:base64:`) and cavage puts a comma-separated parameter list in the
// same header. A receiver has to pick, and it picks by looking for
// `Signature-Input`: present means RFC 9421, absent means cavage. That is the
// rule Mastodon implements and it is the rule here.
//
// # What is not relaxed
//
// The covered-component names are translated into the RFC 9421 vocabulary as
// they are parsed -- (request-target) becomes @method and @path, host becomes
// @authority -- so every coverage rule the inbox already enforces applies
// unchanged to a cavage signature. There is one policy, not two, and a
// verifier cannot be talked into a weaker one by choosing an older format.
//
// The algorithm still comes from the key. Cavage carries an `algorithm`
// parameter and it is advisory here for exactly the reason the RFC 9421 path
// ignores its `alg`: a sender who picks how their signature is checked picks a
// way it succeeds.

// cavageSignature is the parsed Signature header.
type cavageSignature struct {
	keyID     string
	algorithm string
	headers   []string
	signature string
	created   string
	expires   string
}

// looksLikeCavage reports whether a Signature header is the draft form.
//
// keyId is required by the draft and has no counterpart in the RFC 9421
// dictionary, so its presence separates the two without guessing.
func looksLikeCavage(sig string) bool {
	return strings.Contains(sig, "keyId=")
}

// parseCavage reads the comma-separated parameter list.
//
// Split outside quotes, because keyId is a URL and a URL may contain a comma.
// Splitting on every comma is the parser bug that turns a valid signature into
// "malformed" for one sender in a thousand, which is the hardest kind to
// diagnose from the other end.
func parseCavage(header string) (cavageSignature, error) {
	var out cavageSignature
	for _, part := range splitOutsideQuotes(header) {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "keyid":
			out.keyID = value
		case "algorithm":
			out.algorithm = value
		case "headers":
			out.headers = strings.Fields(strings.ToLower(value))
		case "signature":
			out.signature = value
		case "created":
			out.created = value
		case "expires":
			out.expires = value
		}
	}
	if out.keyID == "" {
		return out, fmt.Errorf("this signature names no keyId, so there is " +
			"nothing to check it against")
	}
	if out.signature == "" {
		return out, fmt.Errorf("this signature header carries no signature")
	}
	if len(out.headers) == 0 {
		// The draft's default is the Date header alone. Refused rather than
		// applied: a signature over a date and nothing else authenticates no
		// request, and every real implementation sends an explicit list.
		return out, fmt.Errorf(
			"this signature lists no headers. The draft defaults to the date " +
				"alone, which authenticates a clock rather than a request")
	}
	return out, nil
}

func splitOutsideQuotes(s string) []string {
	var out []string
	var current strings.Builder
	inQuotes := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case r == ',' && !inQuotes:
			out = append(out, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}

// cavageBase rebuilds the bytes that were signed.
//
// One line per listed header, joined with newlines and with no trailing one.
// The order is the order in the headers list, not the order they appear in the
// request: the list is part of what was signed.
func cavageBase(r *http.Request, c cavageSignature, origin string) (string, []string, error) {
	var lines []string
	var covered []string

	for _, name := range c.headers {
		switch name {
		case "(request-target)":
			target := r.URL.RequestURI()
			if r.URL.IsAbs() {
				// An outbound request being signed, where the URL is absolute.
				target = r.URL.EscapedPath()
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
			}
			lines = append(lines,
				"(request-target): "+strings.ToLower(r.Method)+" "+target)
			// One component covering two things, so it is recorded as both.
			// Everything downstream asks about @method and @path.
			covered = append(covered, "@method", "@path")
		case "(created)":
			if c.created == "" {
				return "", nil, fmt.Errorf(
					"this signature covers (created) and carries no created " +
						"parameter")
			}
			lines = append(lines, "(created): "+c.created)
			covered = append(covered, "(created)")
		case "(expires)":
			if c.expires == "" {
				return "", nil, fmt.Errorf(
					"this signature covers (expires) and carries no expires " +
						"parameter")
			}
			lines = append(lines, "(expires): "+c.expires)
			covered = append(covered, "(expires)")
		case "host":
			// The Host header is not in r.Header on a server request; Go puts
			// it on the request itself. Reading r.Header.Get("Host") returns
			// empty, and a base built over an empty host verifies against
			// nothing while looking like a signature mismatch.
			host := r.Host
			if host == "" && origin != "" {
				host = strings.TrimPrefix(strings.TrimPrefix(origin,
					"https://"), "http://")
			}
			lines = append(lines, "host: "+host)
			covered = append(covered, "@authority")
		default:
			if strings.HasPrefix(name, "(") {
				return "", nil, fmt.Errorf(
					"this signature covers %q, which this program cannot "+
						"rebuild. Refusing rather than skipping it", name)
			}
			// Multiple values are joined with ", " per the draft.
			values := r.Header.Values(http.CanonicalHeaderKey(name))
			for i := range values {
				values[i] = strings.TrimSpace(values[i])
			}
			lines = append(lines, name+": "+strings.Join(values, ", "))
			covered = append(covered, name)
		}
	}
	return strings.Join(lines, "\n"), covered, nil
}

// verifyCavage checks a draft-cavage signature.
func verifyCavage(r *http.Request, origin string, keys []PublicKey,
	maxAge time.Duration, now time.Time) (*Signed, error) {

	c, err := parseCavage(r.Header.Get("Signature"))
	if err != nil {
		return nil, err
	}

	// Freshness, before any cryptography, on a cheap comparison.
	//
	// The draft has no created parameter in ordinary use, so the Date header
	// is what bounds a replay -- and it only bounds anything because it is one
	// of the signed headers. Which is why cavageWhen is given the covered list
	// and refuses to read a timestamp that is not in it.
	when, err := cavageWhen(r, c)
	if err != nil {
		return nil, err
	}
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	if age := now.Sub(when); age > maxAge {
		return nil, fmt.Errorf("this signature was made %s ago, limit %s",
			age.Round(time.Second), maxAge)
	}
	if when.Sub(now) > time.Minute {
		return nil, fmt.Errorf("this signature is dated in the future")
	}
	// expires was parsed and then never compared to anything. A sender that
	// says when its signature stops being good is entitled to be believed,
	// and the RFC 9421 path here has always honoured the equivalent.
	if c.expires != "" && cavageCovers(c, "(expires)") {
		secs, err := parseUnix(c.expires)
		if err != nil {
			return nil, fmt.Errorf(
				"this signature covers (expires) and %q is not a unix time",
				c.expires)
		}
		if exp := time.Unix(secs, 0); now.After(exp) {
			return nil, fmt.Errorf("this signature expired %s ago",
				now.Sub(exp).Round(time.Second))
		}
	}

	var key PublicKey
	found := false
	for _, k := range keys {
		if k.ID == c.keyID {
			key, found = k, true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("no key named %q is configured", c.keyID)
	}

	base, covered, err := cavageBase(r, c, origin)
	if err != nil {
		return nil, err
	}
	raw, err := decodeSignature(c.signature)
	if err != nil {
		return nil, err
	}
	if err := verifyWith(key, []byte(base), raw); err != nil {
		return nil, err
	}
	return &Signed{KeyID: c.keyID, Created: when, Covered: covered}, nil
}

// cavageWhen is the moment a signature claims to have been made.
//
// Only a timestamp the signature actually covers is read, and that is the
// whole of this function's job.
//
// The draft puts created= and expires= in the Signature header as parameters,
// and they enter the signing base only when (created) or (expires) appears in
// headers=. So a parameter that is not listed there is unsigned data sitting
// inside the signature header, and it used to be read anyway. Appending
// `,created=<now>` to a captured request left headers= untouched, so the base
// was byte-identical and the signature still verified -- while the age check
// read the attacker's number. A six-year-old replay passed. The five-minute
// window bounded nothing on that path.
//
// The Date header had the same shape: it was read whether or not `date` was in
// headers=, so a sender that signed only (request-target), host and digest --
// which some fediverse servers do -- could have its Date rewritten by anyone
// holding a copy of the request.
//
// Refusing is the only answer available. There is no timestamp to fall back
// on: an unsigned one is the attacker's.
func cavageWhen(r *http.Request, c cavageSignature) (time.Time, error) {
	if c.created != "" && cavageCovers(c, "(created)") {
		secs, err := parseUnix(c.created)
		if err != nil {
			return time.Time{}, fmt.Errorf(
				"this signature covers (created) and %q is not a unix time",
				c.created)
		}
		return time.Unix(secs, 0), nil
	}
	if !cavageCovers(c, "date") {
		return time.Time{}, fmt.Errorf(
			"this signature covers neither (created) nor date, so nothing " +
				"about its age is signed and a captured request would " +
				"authenticate forever")
	}
	raw := strings.TrimSpace(r.Header.Get("Date"))
	if raw == "" {
		return time.Time{}, fmt.Errorf(
			"this signature carries no date, so its age cannot be checked " +
				"and a captured request would authenticate forever")
	}
	when, err := http.ParseTime(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("the Date header %q is not a date", raw)
	}
	return when, nil
}

// cavageCovers reports whether a component is in the signature's headers list.
func cavageCovers(c cavageSignature, name string) bool {
	for _, h := range c.headers {
		if strings.EqualFold(h, name) {
			return true
		}
	}
	return false
}

// SignCavage adds a draft-cavage signature to an outbound request.
//
// The format almost every fediverse server verifies. Sent instead of RFC 9421
// rather than alongside it, because the two put incompatible syntax in the
// same header and a receiver picks by whether Signature-Input is present.
//
// A Date header is set if the caller has not, because the draft's replay bound
// is the date and a signature over an absent one bounds nothing.
func SignCavage(r *http.Request, keyID string, alg Algorithm, key crypto.Signer,
	headers []string, now time.Time) error {

	if len(headers) == 0 {
		return fmt.Errorf(
			"a signature covering nothing proves nothing; name the headers")
	}
	if r.Header.Get("Date") == "" {
		r.Header.Set("Date", now.UTC().Format(http.TimeFormat))
	}

	lower := make([]string, len(headers))
	for i, h := range headers {
		lower[i] = strings.ToLower(h)
	}
	base, _, err := cavageBase(r, cavageSignature{headers: lower}, "")
	if err != nil {
		return err
	}

	sig, err := signWith(alg, key, []byte(base))
	if err != nil {
		return err
	}
	r.Header.Set("Signature", fmt.Sprintf(
		`keyId=%q,algorithm=%q,headers=%q,signature=%q`,
		keyID, cavageAlgorithmName(alg), strings.Join(lower, " "),
		encodeSignature(sig)))
	// Removed, so a receiver cannot be handed one format's header alongside
	// the other's and have to guess which describes the signature.
	r.Header.Del("Signature-Input")
	return nil
}

// cavageAlgorithmName is what the draft calls each algorithm. Advisory on the
// wire -- a verifier that trusts it lets the sender choose its own check --
// but omitting it makes some implementations refuse the signature outright.
func cavageAlgorithmName(alg Algorithm) string {
	switch alg {
	case RSAPKCS1SHA256:
		return "rsa-sha256"
	case Ed25519:
		return "ed25519"
	}
	return string(alg)
}
