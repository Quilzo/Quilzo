// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package commerce

import (
	"strings"
	"testing"
	"time"
)

// The control: a closed checkout mandate, properly issued and bound to the
// checkout this shop signed, verifies and reports its facts.
func TestACheckoutMandateBoundToThisCheckoutVerifies(t *testing.T) {
	svc, _, _, issuerPriv, issuer := newShop(t, "")
	cs := madeSession(t, svc)

	token := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "kb+sd-jwt",
		map[string]any{"vct": "mandate.checkout.1",
			"checkout_hash": CheckoutHash(cs.JWT),
			"exp":           float64(time.Now().Add(time.Hour).Unix())})
	// A key-bound presentation appends the holder's JWT; this shop does not
	// verify it, but records that it was there.
	token += "~" + signJWS(t, issuerPriv, "holder", "kb+jwt", map[string]any{"iat": 1})

	facts, err := VerifyCheckoutMandate(token, cs.JWT, []IssuerKey{issuer}, time.Now())
	if err != nil {
		t.Fatalf("a properly bound mandate was refused: %v", err)
	}
	if facts.Issuer != "ExampleTS" {
		t.Errorf("issuer is %q", facts.Issuer)
	}
	if !facts.KeyBinding {
		t.Error("the key binding was not recorded")
	}
	if facts.Digest == "" {
		t.Error("no digest for replay recording")
	}
}

// The whole point of the binding: a mandate taken from one checkout cannot
// authorise another.
func TestAMandateFromAnotherCheckoutIsRefused(t *testing.T) {
	svc, _, _, issuerPriv, issuer := newShop(t, "")
	cs := madeSession(t, svc)

	// A second, different session.
	cs2 := madeSession(t, svc)
	token := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "kb+sd-jwt",
		map[string]any{"vct": "mandate.checkout.1",
			"checkout_hash": CheckoutHash(cs.JWT),
			"exp":           float64(time.Now().Add(time.Hour).Unix())})

	if _, err := VerifyCheckoutMandate(token, cs2.JWT, []IssuerKey{issuer}, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "different checkout") {
		t.Fatalf("a mandate for another checkout was accepted: %v", err)
	}
}

// A mandate whose hash names nothing is a mandate bound to nothing.
func TestAMandateWithNoHashIsRefused(t *testing.T) {
	_, _, _, issuerPriv, issuer := newShop(t, "")
	anyJWT := "header.payload.sig"
	token := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "example+sd-jwt",
		map[string]any{"vct": "mandate.checkout.1",
			"exp": float64(time.Now().Add(time.Hour).Unix())})
	if _, err := VerifyCheckoutMandate(token, anyJWT, []IssuerKey{issuer}, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "no checkout_hash") {
		t.Fatalf("an unbound mandate was accepted: %v", err)
	}
}

// Expired is expired.
func TestAnExpiredMandateIsRefused(t *testing.T) {
	svc, _, _, issuerPriv, issuer := newShop(t, "")
	cs := madeSession(t, svc)
	token := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "example+sd-jwt",
		map[string]any{"vct": "mandate.checkout.1",
			"checkout_hash": CheckoutHash(cs.JWT),
			"exp":           float64(time.Now().Add(-time.Minute).Unix())})
	if _, err := VerifyCheckoutMandate(token, cs.JWT, []IssuerKey{issuer}, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired mandate was accepted: %v", err)
	}
}

// Open mandates authorise nothing on their own and are refused as such.
func TestAnOpenMandateIsRefusedAsNotAnAuthorisation(t *testing.T) {
	svc, _, _, issuerPriv, issuer := newShop(t, "")
	cs := madeSession(t, svc)
	token := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "example+sd-jwt",
		map[string]any{"vct": "mandate.checkout.open.1",
			"constraints": []any{}, "exp": float64(time.Now().Add(time.Hour).Unix())})
	if _, err := VerifyCheckoutMandate(token, cs.JWT, []IssuerKey{issuer}, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "open checkout mandate") {
		t.Fatalf("an open mandate was accepted: %v", err)
	}
}

// A signature from a key this shop never configured is nobody's.
func TestAnUnconfiguredIssuerIsRefused(t *testing.T) {
	otherPriv, other := issuerFor(t, "Stranger", "stranger-1")
	anyJWT := "h.p.s"
	token := mintDelegateSDJWT(t, otherPriv, other.KeyID, "example+sd-jwt",
		map[string]any{"vct": "mandate.checkout.1",
			"checkout_hash": CheckoutHash(anyJWT),
			"exp":           float64(time.Now().Add(time.Hour).Unix())})
	if _, err := VerifyCheckoutMandate(token, anyJWT, nil, time.Now()); err == nil {
		t.Fatal("a mandate from an unconfigured issuer was accepted")
	}
}

// The payment mandate checks: right shop, right amount, right currency.
func TestAPaymentMandatePayingThisShopTheRightAmountVerifies(t *testing.T) {
	_, _, _, issuerPriv, issuer := newShop(t, "")
	token := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "kb+sd-jwt",
		map[string]any{"vct": "mandate.payment.1",
			"payee":          map[string]any{"name": "Marginalia", "website": "https://shop.test"},
			"payment_amount": map[string]any{"amount": float64(2400), "currency": "GBP"},
			"payment_instrument": map[string]any{"id": "stub", "type": "card",
				"description": "Card ••••4242"},
			"exp": float64(time.Now().Add(time.Hour).Unix())})

	facts, err := VerifyPaymentMandate(token, "Marginalia", "https://shop.test",
		2400, "GBP", []IssuerKey{issuer}, time.Now())
	if err != nil {
		t.Fatalf("a correct payment mandate was refused: %v", err)
	}
	if facts.Amount != 2400 || facts.Currency != "GBP" {
		t.Errorf("amount %d %s", facts.Amount, facts.Currency)
	}
	if facts.Instrument != "Card ••••4242" {
		t.Errorf("instrument %q", facts.Instrument)
	}
}

func TestAPaymentMandatePayingAnotherShopIsRefused(t *testing.T) {
	_, _, _, issuerPriv, issuer := newShop(t, "")
	token := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "example+sd-jwt",
		map[string]any{"vct": "mandate.payment.1",
			"payee":          map[string]any{"name": "Another Shop", "website": "https://other.test"},
			"payment_amount": map[string]any{"amount": float64(2400), "currency": "GBP"},
			"exp":            float64(time.Now().Add(time.Hour).Unix())})
	if _, err := VerifyPaymentMandate(token, "Marginalia", "https://shop.test",
		2400, "GBP", []IssuerKey{issuer}, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "pays") {
		t.Fatalf("a mandate paying another shop was accepted: %v", err)
	}
}

func TestAPaymentMandateForAnotherAmountIsRefused(t *testing.T) {
	_, _, _, issuerPriv, issuer := newShop(t, "")
	token := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "example+sd-jwt",
		map[string]any{"vct": "mandate.payment.1",
			"payee":          map[string]any{"name": "Marginalia", "website": "https://shop.test"},
			"payment_amount": map[string]any{"amount": float64(9999), "currency": "GBP"},
			"exp":            float64(time.Now().Add(time.Hour).Unix())})
	if _, err := VerifyPaymentMandate(token, "Marginalia", "https://shop.test",
		2400, "GBP", []IssuerKey{issuer}, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "amount") {
		t.Fatalf("a mandate for a different amount was accepted: %v", err)
	}
}

func TestAPaymentMandateInAnotherCurrencyIsRefused(t *testing.T) {
	_, _, _, issuerPriv, issuer := newShop(t, "")
	token := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "example+sd-jwt",
		map[string]any{"vct": "mandate.payment.1",
			"payee":          map[string]any{"name": "Marginalia", "website": "https://shop.test"},
			"payment_amount": map[string]any{"amount": float64(2400), "currency": "USD"},
			"exp":            float64(time.Now().Add(time.Hour).Unix())})
	if _, err := VerifyPaymentMandate(token, "Marginalia", "https://shop.test",
		2400, "GBP", []IssuerKey{issuer}, time.Now()); err == nil {
		t.Fatal("a mandate in another currency was accepted")
	}
}

// A fractional amount is a malformed mandate, not a price to round.
func TestAFractionalAmountIsRefused(t *testing.T) {
	_, _, _, issuerPriv, issuer := newShop(t, "")
	token := mintDelegateSDJWT(t, issuerPriv, issuer.KeyID, "example+sd-jwt",
		map[string]any{"vct": "mandate.payment.1",
			"payee":          map[string]any{"name": "Marginalia", "website": "https://shop.test"},
			"payment_amount": map[string]any{"amount": 24.5, "currency": "GBP"},
			"exp":            float64(time.Now().Add(time.Hour).Unix())})
	if _, err := VerifyPaymentMandate(token, "Marginalia", "https://shop.test",
		2400, "GBP", []IssuerKey{issuer}, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "whole number") {
		t.Fatalf("a fractional amount was accepted: %v", err)
	}
}

// madeSession makes a checkout session over the first in-stock product, for
// mandate tests that need a signed checkout to bind to.
func madeSession(t *testing.T, svc *Service) *Checkout {
	if t != nil {
		t.Helper()
	}
	cart := &Cart{ID: "ct_test", Currency: "GBP", Lines: []Line{{
		ItemID: "notebook", Title: "Linen Notebook", SKU: "NB-1",
		UnitAmount: 2400, Quantity: 1, Amount: 2400}},
		ExpiresAt: time.Now().Add(time.Hour), Created: time.Now(), Agent: "ExampleAgent"}
	totals, total := totalsOf("GBP", cart.Lines)
	cs := &Checkout{ID: "cs_test", CartID: cart.ID, Status: "ready_for_complete",
		Currency: "GBP", Lines: cart.Lines, Totals: totals, Total: total,
		Created: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	jwt, err := svc.Merchant.SignCheckout(cs.signedContents(), svc.PayeeWebsite,
		time.Now(), cs.ExpiresAt)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		return cs
	}
	cs.JWT = jwt
	return cs
}
