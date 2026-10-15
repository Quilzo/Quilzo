// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package commerce

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/oidc"
)

// The mandate layer: AP2 credentials, checked against issuer keys the
// operator supplied.
//
// Trust here follows the same rule as Web Bot Auth in internal/crawl: keys
// are configured, never fetched. AP2 mandates are signed by whoever the
// operator of this shop has agreed to accept mandates from — an agent
// platform, a credential provider — and the honest expression of that
// agreement is a key in configuration, auditable, removable, and impossible
// to acquire by sending this server a URL. A verifier that resolved issuer
// keys by fetching would let any request name the key that authenticates it.

// MandateKinds, from the AP2 specification: the closed credential a verifier
// always receives, and the open constraint set it is delegated from. A
// merchant verifies closed ones; an open one arriving here is a protocol
// confusion, refused with the reason rather than "accepted, loosely".
const (
	vctCheckoutClosed = "mandate.checkout.1"
	vctCheckoutOpen   = "mandate.checkout.open.1"
	vctPaymentClosed  = "mandate.payment.1"
	vctPaymentOpen    = "mandate.payment.open.1"
)

// ClockSkew is how far a mandate's times may disagree with this server's.
//
// Signed at one machine, verified at another, compared against a third
// clock: some disagreement is physics. Two minutes is the same allowance the
// rest of this program makes on signed surfaces, and the window is not the
// replay protection — the presentation digest recorded with the order is,
// because a window closes and a record does not.
const ClockSkew = 2 * time.Minute

// IssuerKey is one mandate issuer's signing key, as configured.
type IssuerKey struct {
	// Name is who this is for the order record: the party whose signature
	// on a mandate this shop accepts.
	Name string
	// KeyID is the kid the mandate's header names.
	KeyID string
	// Public is the ECDSA or RSA key, already parsed.
	Public crypto.PublicKey
}

// issuerKeys adapts the configured keys to oidc's KeySource, whose key
// lookup is by the kid a token names — and which returns an error for a kid
// it does not know, which is the refusal this package wants: an unknown
// issuer is not anonymous, it is untrusted.
type issuerKeys struct{ keys []IssuerKey }

func (s issuerKeys) Key(kid string) (crypto.PublicKey, error) {
	for _, k := range s.keys {
		if k.KeyID == kid {
			return k.Public, nil
		}
	}
	return nil, fmt.Errorf("no issuer key %q is configured", kid)
}

// mandateAlgorithms is what a mandate may be signed with here.
//
// ECDSA P-256 is what AP2's examples use and what the merchant's own
// checkout is signed with; the P-384, P-521 and RSA variants are admitted
// because an issuer may hold them and all are FIPS 186-5 approved. EdDSA is
// not: AP2 binds mandates to checkouts through hashes, and the
// specification's rainbow-table reasoning wants non-deterministic
// signatures on the objects being hashed into that binding.
var mandateAlgorithms = []oidc.Algorithm{
	oidc.ES256, oidc.ES384, oidc.ES512, oidc.RS256, oidc.PS256,
}

// Facts is what a verified mandate said, kept for the order record.
type Facts struct {
	// Vct is the verified type string, e.g. mandate.payment.1.
	Vct string
	// Issuer names the configured key that verified.
	Issuer string
	// Digest identifies the presentation, for replay recording.
	Digest string
	// TransactionID is the mandate's own reference, when it carried one.
	TransactionID string
	// KeyBinding says the holder appended a key-binding JWT.
	KeyBinding bool
	// IssuedAt and Expiry are the mandate's times.
	IssuedAt, Expiry time.Time
}

// verifyMandateSignature checks the presentation's issuer signature and
// returns the flattened claims.
//
// The typ check accepts the spellings AP2's examples carry — "sd-jwt",
// "example+sd-jwt" and the key-bound "kb+sd-jwt" — and plain JWT, because
// the type of a mandate is carried in its vct claim, checked after the
// signature, and a verifier that pinned typ strings would refuse mandates
// over a header decoration.
func verifyMandateSignature(token string, issuers []IssuerKey, now time.Time) (*sdjwt, map[string]any, error) {
	parsed, jws, err := parseSDJWT(token)
	if err != nil {
		return nil, nil, err
	}
	keys := issuerKeys{keys: issuers}
	// The signature is checked over the token's own three segments, under an
	// algorithm from the agreed list and the key the header names — the same
	// hardening oidc applies to ID tokens, which is why the call is reused
	// rather than re-implemented. The payload bytes it returns are the same
	// ones parseSDJWT flattened before the key was known; the successful
	// verification is what retroactively authenticates them.
	if _, err := oidc.VerifyJWS(string(jws), mandateAlgorithms, keys,
		"a mandate issuer", "a mandate", func(typ string) bool {
			switch typ {
			case "", "JWT", "sd-jwt", "example+sd-jwt", "kb+sd-jwt":
				return true
			}
			return false
		}); err != nil {
		return nil, nil, err
	}

	claims := parsed.Payload
	// AP2's presentations put the mandate's own claims one level down, in a
	// delegate_payload behind "..." pointers: the envelope the issuer signed
	// says what to hash with, and the delegated object says what is
	// authorised. Hoist it, keeping any envelope claim the delegated object
	// does not carry — iat and exp appear in either place across AP2's own
	// examples, and refusing one spelling of each would be refusing working
	// mandates over a layout choice.
	if dp, ok := claims["delegate_payload"].([]any); ok {
		if len(dp) != 1 {
			return nil, nil, fmt.Errorf("this mandate delegates %d payloads "+
				"and one is the most a presentation may carry", len(dp))
		}
		inner, ok := dp[0].(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("this mandate's delegated payload is " +
				"not an object of claims")
		}
		for k, v := range claims {
			if k != "delegate_payload" {
				if _, carried := inner[k]; !carried {
					inner[k] = v
				}
			}
		}
		claims = inner
		parsed.Payload = inner
	}
	iat, exp := timeOf(claims["iat"]), timeOf(claims["exp"])
	if !exp.IsZero() && now.Add(ClockSkew).After(exp) {
		return nil, nil, fmt.Errorf("this mandate expired at %s", exp.UTC().Format(time.RFC3339))
	}
	if !iat.IsZero() && iat.After(now.Add(ClockSkew)) {
		return nil, nil, fmt.Errorf("this mandate was issued at %s, which has "+
			"not happened yet", iat.UTC().Format(time.RFC3339))
	}
	parsed.IssuedAt, parsed.Expiry = iat, exp
	return parsed, claims, nil
}

// CheckoutFacts is what a verified checkout mandate said.
type CheckoutFacts struct {
	Facts
	// CheckoutHash is the base64url SHA-256 of the checkout JWT the mandate
	// was checked against — the binding, restated on the order.
	CheckoutHash string
}

// VerifyCheckoutMandate checks the credential that authorises a purchase:
// that it is a closed checkout mandate, from a configured issuer, whose
// checkout_hash is the hash of the checkout JWT this shop issued for this
// very session.
//
// This is the merchant's principal protection under AP2 against a stolen
// mandate being replayed against a different basket: the mandate is bound to
// this checkout by a hash over the merchant's own signature, so a mandate
// taken from one order cannot authorise another without breaking SHA-256.
func VerifyCheckoutMandate(token, checkoutJWT string, issuers []IssuerKey, now time.Time) (CheckoutFacts, error) {
	parsed, claims, err := verifyMandateSignature(token, issuers, now)
	if err != nil {
		return CheckoutFacts{}, err
	}
	vct, _ := claims["vct"].(string)
	switch vct {
	case vctCheckoutClosed:
	case vctCheckoutOpen:
		return CheckoutFacts{}, fmt.Errorf("this is an open checkout mandate, " +
			"the constraints a person approved. A merchant verifies the closed " +
			"mandate delegated from it, not the constraints themselves")
	case "":
		return CheckoutFacts{}, fmt.Errorf("this mandate carries no vct, so it " +
			"does not say what it authorises")
	default:
		return CheckoutFacts{}, fmt.Errorf("this mandate's vct is %q, not a "+
			"checkout mandate", vct)
	}
	sum := sha256.Sum256([]byte(checkoutJWT))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	got, _ := claims["checkout_hash"].(string)
	if got == "" {
		return CheckoutFacts{}, fmt.Errorf("this checkout mandate names no " +
			"checkout_hash, so it is bound to no checkout of this shop's")
	}
	if !constantTimeEqual(got, want) {
		return CheckoutFacts{}, fmt.Errorf("this checkout mandate is bound to a " +
			"different checkout than the one it was presented against")
	}
	tid, _ := claims["transaction_id"].(string)
	return CheckoutFacts{
		Facts: Facts{
			Vct: vct, Digest: parsed.Digest, TransactionID: tid,
			KeyBinding: parsed.KeyBinding,
			IssuedAt:   parsed.IssuedAt, Expiry: parsed.Expiry,
			Issuer: issuerName(issuers, parsed.KeyID),
		},
		CheckoutHash: got,
	}, nil
}

// PaymentFacts is what a verified payment mandate said.
type PaymentFacts struct {
	Facts
	// PayeeName and PayeeWebsite are who the mandate pays, as disclosed.
	PayeeName, PayeeWebsite string
	// Amount and Currency are what it authorised.
	Amount   int64
	Currency string
	// Instrument is the disclosed description of how it pays, recorded for
	// the order and never used to decide anything.
	Instrument string
}

// VerifyPaymentMandate checks the credential that authorises the money: a
// closed payment mandate, from a configured issuer, paying exactly this shop
// exactly the total of this checkout, in the checkout's currency, inside
// its validity window.
//
// The amount is compared for equality, not as a bound. An open mandate
// constrains what a closed one may ask for, and checking bounds is the
// credential provider's side of that; a merchant asked to accept less than
// the total, or in a currency the checkout is not in, is a merchant being
// asked to hand over goods on a promise of the difference.
func VerifyPaymentMandate(token string, payeeName, payeeWebsite string, amount int64, currency string,
	issuers []IssuerKey, now time.Time) (PaymentFacts, error) {

	parsed, claims, err := verifyMandateSignature(token, issuers, now)
	if err != nil {
		return PaymentFacts{}, err
	}
	vct, _ := claims["vct"].(string)
	switch vct {
	case vctPaymentClosed:
	case vctPaymentOpen:
		return PaymentFacts{}, fmt.Errorf("this is an open payment mandate, the " +
			"spending constraints a person approved. It authorises nothing on " +
			"its own and cannot be accepted as a payment")
	case "":
		return PaymentFacts{}, fmt.Errorf("this mandate carries no vct, so it " +
			"does not say what it authorises")
	default:
		return PaymentFacts{}, fmt.Errorf("this mandate's vct is %q, not a "+
			"payment mandate", vct)
	}

	payee, _ := claims["payee"].(map[string]any)
	if payee == nil {
		return PaymentFacts{}, fmt.Errorf("this payment mandate names no payee")
	}
	gotName, _ := payee["name"].(string)
	gotSite, _ := payee["website"].(string)
	if !strings.EqualFold(strings.TrimSpace(gotName), strings.TrimSpace(payeeName)) ||
		!strings.EqualFold(strings.TrimSpace(strings.TrimSuffix(gotSite, "/")),
			strings.TrimSuffix(strings.TrimSpace(payeeWebsite), "/")) {
		return PaymentFacts{}, fmt.Errorf("this payment mandate pays %q at %s, "+
			"and this shop is %q at %s", gotName, gotSite, payeeName, payeeWebsite)
	}

	amountClaim, _ := claims["payment_amount"].(map[string]any)
	if amountClaim == nil {
		return PaymentFacts{}, fmt.Errorf("this payment mandate states no amount")
	}
	gotAmount, ok := wholeOf(amountClaim["amount"])
	if !ok {
		return PaymentFacts{}, fmt.Errorf("this payment mandate's amount is not " +
			"a whole number of minor units")
	}
	gotCurrency, _ := amountClaim["currency"].(string)
	if !strings.EqualFold(gotCurrency, currency) {
		return PaymentFacts{}, fmt.Errorf("this payment mandate is in %s and "+
			"the checkout is in %s", gotCurrency, currency)
	}
	if gotAmount != amount {
		return PaymentFacts{}, fmt.Errorf("this payment mandate authorises a " +
			"different amount than the checkout totals")
	}

	instrument, _ := claims["payment_instrument"].(map[string]any)
	desc, _ := instrument["description"].(string)
	tid, _ := claims["transaction_id"].(string)
	return PaymentFacts{
		Facts: Facts{
			Vct: vct, Digest: parsed.Digest, TransactionID: tid,
			KeyBinding: parsed.KeyBinding,
			IssuedAt:   parsed.IssuedAt, Expiry: parsed.Expiry,
			Issuer: issuerName(issuers, parsed.KeyID),
		},
		PayeeName: gotName, PayeeWebsite: gotSite,
		Amount: gotAmount, Currency: strings.ToUpper(gotCurrency),
		Instrument: desc,
	}, nil
}

// wholeOf reads a JSON number as a whole int64, or not.
//
// Mandate amounts are minor units and integers in AP2's credentials; a
// fraction here is a malformed mandate, not a price to round.
func wholeOf(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		if x != float64(int64(x)) || x < 0 || x > 1e15 {
			return 0, false
		}
		return int64(x), true
	case int64:
		return x, x >= 0
	case int:
		return int64(x), x >= 0
	}
	return 0, false
}

// timeOf reads a numeric epoch claim.
func timeOf(v any) time.Time {
	switch x := v.(type) {
	case float64:
		return time.Unix(int64(x), 0).UTC()
	case int64:
		return time.Unix(x, 0).UTC()
	case int:
		return time.Unix(int64(x), 0).UTC()
	}
	return time.Time{}
}

// constantTimeEqual compares two digest strings without early exit.
//
// A digest comparison that returns on the first differing character is a
// timing side channel on the expected value. The values here are hashes this
// server computed over its own output and a claim from a credential, so the
// practical risk is small — and the fix is one loop, so it is fixed.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// issuerName says which configured issuer a kid belonged to.
func issuerName(keys []IssuerKey, kid string) string {
	for _, k := range keys {
		if k.KeyID == kid {
			return k.Name
		}
	}
	return "an unconfigured key"
}

// ParseIssuerKey decodes a configured issuer key: name, key id, and a public
// key as base64 or hex.
//
// An ECDSA point in uncompressed form (65 bytes for P-256), a DER
// SubjectPublicKeyInfo, or a PKCS#1 RSA modulus form are all accepted,
// because an operator copying a key out of an issuer's documentation should
// not have to know which spelling it is — the same accommodation
// crawl.ParseKey makes for crawler keys.
func ParseIssuerKey(name, kid, encoded string) (IssuerKey, error) {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(kid) == "" {
		return IssuerKey{}, fmt.Errorf("an issuer key needs a name and a key id")
	}
	raw, err := decodeAny(strings.TrimSpace(encoded))
	if err != nil {
		return IssuerKey{}, fmt.Errorf("%s: %w", name, err)
	}
	if pub, err := x509.ParsePKIXPublicKey(raw); err == nil {
		return IssuerKey{Name: name, KeyID: kid, Public: pub}, nil
	}
	// An uncompressed EC point: 0x04 || X || Y, on P-256 or P-384 by length.
	if (len(raw) == 65 || len(raw) == 97) && raw[0] == 0x04 {
		half := (len(raw) - 1) / 2
		curve := elliptic.P256()
		if half == 48 {
			curve = elliptic.P384()
		}
		x, y := new(big.Int).SetBytes(raw[1:1+half]), new(big.Int).SetBytes(raw[1+half:])
		if curve.IsOnCurve(x, y) {
			return IssuerKey{Name: name, KeyID: kid,
				Public: &ecdsa.PublicKey{Curve: curve, X: x, Y: y}}, nil
		}
	}
	return IssuerKey{}, fmt.Errorf("%s: the key is not DER, or an uncompressed "+
		"P-256 point", name)
}

// decodeAny reads a key as base64url, base64 or hex, whatever it is.
func decodeAny(s string) ([]byte, error) {
	for _, dec := range []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		hex.DecodeString,
	} {
		if raw, err := dec(s); err == nil && len(raw) > 0 {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("the key is not base64 or hex")
}
