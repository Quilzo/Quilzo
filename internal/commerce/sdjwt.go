// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package commerce

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// An SD-JWT, read far enough to check a mandate.
//
// # What this implements, and why that much
//
// RFC 9901 selective disclosure: a signed JWT whose payload hides selected
// claims behind digests, with the claims themselves travelling beside the
// token as base64url arrays of [salt, key, value] (object members) or
// [salt, value] (array elements). The digest of a disclosure is the SHA-256
// of the disclosure's own encoded text, base64url — so a verifier that finds
// a digest in the payload and the matching disclosure beside the token can
// put the claim back and know it was there when the issuer signed.
//
// AP2 puts every mandate claim a merchant checks inside disclosures — the
// vct, the payee, the amount — so a merchant that does not flatten them
// cannot verify anything. This implements the digest arithmetic, the _sd
// member form, the "..." pointer form AP2's delegate_payload uses, and
// refuses anything else, including any _sd_alg but sha-256: an algorithm
// this package has not implemented, named by a token it was just handed, is
// an instruction to skip a check, not a choice to honour.
//
// # What it deliberately does not verify
//
// The key-binding JWT — the fourth segment a holder appends in kb+sd-jwt —
// is separated out and returned unread beyond its presence, because binding
// the holder's key is the Credential Provider's and the processor's duty
// under AP2, not the merchant's. The merchant's protections are the ones
// this package does check: the issuer's signature, the hash that ties the
// mandate to this shop's checkout, the payee, the amount, and that a mandate
// is never accepted twice.
type sdjwt struct {
	// Payload is the flattened claims: digests replaced by the disclosed
	// values, _sd and _sd_alg removed.
	Payload map[string]any
	// Digest is the SHA-256 of the whole presented token, which is what
	// identifies it for replay recording. Not the sd_hash claim inside a
	// closed mandate — that names the open mandate it was delegated from,
	// and conflating the two would let one closed mandate's reuse hide
	// behind another's identifier.
	Digest string
	// KeyBinding says the presentation carried a holder's key-binding JWT.
	KeyBinding bool
	// KeyID names the issuer's key that signed, from the header.
	KeyID string
	// IssuedAt and Expiry are the mandate's own times, once read.
	IssuedAt, Expiry time.Time
}

// parseSDJWT splits a presented SD-JWT and flattens its disclosures.
//
// The token is expected in the presentation form: JWS, then tilde-separated
// disclosures, then optionally the key-binding JWT. A disclosure is base64url
// and so cannot contain a dot; a segment that does is the key-binding JWT and
// nothing else.
func parseSDJWT(token string) (*sdjwt, []byte, error) {
	parts := strings.Split(token, "~")
	if len(parts) < 2 {
		return nil, nil, fmt.Errorf("this mandate has no disclosures, so " +
			"either it is not an SD-JWT or every claim in it is a lie of " +
			"omission")
	}
	jws, kb := parts[0], ""
	disclosures := make([]string, 0, len(parts))
	for _, p := range parts[1:] {
		if p == "" {
			continue
		}
		if strings.Contains(p, ".") {
			if kb != "" {
				return nil, nil, fmt.Errorf("this mandate carries two key-binding JWTs")
			}
			kb = p
			continue
		}
		disclosures = append(disclosures, p)
	}
	if jws == "" || strings.Count(jws, ".") != 2 {
		return nil, nil, fmt.Errorf("the mandate's first segment is not a signed JWT")
	}
	kid, rawPayload, err := unverifiedParts(jws)
	if err != nil {
		return nil, nil, err
	}

	byDigest := map[string][]any{}
	for _, d := range disclosures {
		decoded, err := base64.RawURLEncoding.DecodeString(d)
		if err != nil {
			return nil, nil, fmt.Errorf("a disclosure is not base64url: %w", err)
		}
		var arr []any
		if err := json.Unmarshal(decoded, &arr); err != nil {
			return nil, nil, fmt.Errorf("a disclosure is not a JSON array: %w", err)
		}
		if len(arr) != 2 && len(arr) != 3 {
			return nil, nil, fmt.Errorf("a disclosure has %d parts; RFC 9901 "+
				"allows two or three", len(arr))
		}
		sum := sha256.Sum256([]byte(d))
		byDigest[base64.RawURLEncoding.EncodeToString(sum[:])] = arr
	}

	var payload any
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, nil, fmt.Errorf("the mandate's payload is not JSON: %w", err)
	}
	flat, err := flatten(payload, byDigest, 0)
	if err != nil {
		return nil, nil, err
	}
	claims, ok := flat.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("the mandate's payload is not an object")
	}
	sum := sha256.Sum256([]byte(token))
	return &sdjwt{
		Payload:    claims,
		Digest:     base64.RawURLEncoding.EncodeToString(sum[:]),
		KeyBinding: kb != "",
		KeyID:      kid,
	}, []byte(jws), nil
}

// maxFlattenDepth bounds the recursive walk.
//
// A disclosure's value is attacker-shaped JSON that can nest as deeply as
// the issuer cares to write, and a verifier that recursed without a limit
// would spend its stack on it. Ten is deeper than any mandate AP2 defines.
const maxFlattenDepth = 10

// flatten replaces digests with disclosed values, recursively.
//
// Unrevealed digests — decoys, or claims the holder chose not to disclose —
// are dropped, not kept: a claim that stays a digest is a claim the mandate
// did not make, and leaving the digest in the result would let a caller
// mistake it for a value. A "..." pointer to a disclosure that was not
// presented is an error rather than a drop, because the payload said
// something belongs there and nothing arrived to fill it.
func flatten(v any, byDigest map[string][]any, depth int) (any, error) {
	if depth > maxFlattenDepth {
		return nil, fmt.Errorf("the mandate nests deeper than %d levels",
			maxFlattenDepth)
	}
	switch t := v.(type) {
	case map[string]any:
		// A whole object standing in for a disclosure: the array-element
		// form, which AP2's delegate_payload and acceptable_items use.
		if d, ok := t["..."].(string); ok && len(t) == 1 {
			arr, ok := byDigest[d]
			if !ok {
				return nil, fmt.Errorf("the mandate names a disclosure that was not presented")
			}
			if len(arr) != 2 {
				return nil, fmt.Errorf("a \"...\" pointer needs a two-part "+
					"disclosure and this one has %d", len(arr))
			}
			return flatten(arr[1], byDigest, depth+1)
		}
		if alg, ok := t["_sd_alg"].(string); ok && alg != "sha-256" {
			return nil, fmt.Errorf("this mandate selects %q as its digest "+
				"algorithm, and sha-256 is the only one implemented here. A "+
				"token choosing an algorithm its verifier has not agreed to "+
				"is a token choosing not to be checked", alg)
		}
		out := map[string]any{}
		if list, ok := t["_sd"].([]any); ok {
			for _, d := range list {
				ds, ok := d.(string)
				if !ok {
					return nil, fmt.Errorf("the _sd list carries something that is not a digest")
				}
				arr, ok := byDigest[ds]
				if !ok {
					continue // A decoy, or undisclosed: dropped, not revealed.
				}
				if len(arr) != 3 {
					return nil, fmt.Errorf("an _sd entry needs a three-part "+
						"disclosure and this one has %d", len(arr))
				}
				key, ok := arr[1].(string)
				if !ok {
					return nil, fmt.Errorf("an _sd disclosure's name is not a string")
				}
				if _, clash := out[key]; clash {
					return nil, fmt.Errorf("the mandate discloses %q twice", key)
				}
				val, err := flatten(arr[2], byDigest, depth+1)
				if err != nil {
					return nil, err
				}
				out[key] = val
			}
		}
		for k, vv := range t {
			if k == "_sd" || k == "_sd_alg" {
				continue
			}
			val, err := flatten(vv, byDigest, depth+1)
			if err != nil {
				return nil, err
			}
			out[k] = val
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(t))
		for _, item := range t {
			val, err := flatten(item, byDigest, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, val)
		}
		return out, nil
	}
	return v, nil
}

// unverifiedParts reads the header and payload of a compact JWS.
//
// The signature is verified by the caller, with the key the header names;
// reading first is how the key gets chosen. Nothing here is trusted — the
// header's key id selects a key from a list the operator supplied, and the
// payload is only parsed.
func unverifiedParts(jws string) (string, []byte, error) {
	segs := strings.Split(jws, ".")
	rawHeader, err := base64.RawURLEncoding.DecodeString(segs[0])
	if err != nil {
		return "", nil, fmt.Errorf("the mandate's header is not base64url: %w", err)
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Enc string `json:"enc"`
	}
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return "", nil, fmt.Errorf("the mandate's header is not JSON: %w", err)
	}
	if h.Enc != "" {
		return "", nil, fmt.Errorf("this mandate is encrypted, and an encrypted " +
			"mandate cannot be checked by a merchant it names")
	}
	if h.Alg == "none" || h.Alg == "" {
		return "", nil, fmt.Errorf("this mandate is signed with %q", h.Alg)
	}
	payload, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return "", nil, fmt.Errorf("the mandate's payload is not base64url: %w", err)
	}
	return h.Kid, payload, nil
}
