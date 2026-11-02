// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assistant

import (
	"strings"
	"testing"
	"time"
)

// A visitor is who the host site signed they are, for as long as it said,
// and nothing else: not with another key, not altered, not for ever.
func TestAVisitorIsWhoTheSiteSigned(t *testing.T) {
	key := []byte("a key the shop and the chatbot share")
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	tok := SignVisitor(map[string]string{"customer": "c-1042", "email": "ana@hartsbakery.co.uk"}, key, now.Add(time.Hour))
	claims, err := VerifyVisitor(tok, key, now)
	if err != nil || claims["customer"] != "c-1042" || claims["email"] != "ana@hartsbakery.co.uk" || len(claims) != 2 {
		t.Fatalf("%v %v", claims, err)
	}
	body, sig, _ := strings.Cut(tok, ".")
	forged := SignVisitor(map[string]string{"customer": "c-1"}, key, now.Add(time.Hour))
	fbody, _, _ := strings.Cut(forged, ".")
	for name, bad := range map[string]string{
		"another key":   SignVisitor(map[string]string{"customer": "c-1042"}, []byte("somebody else's key entirely"), now.Add(time.Hour)),
		"a new body":    fbody + "." + sig,
		"no signature":  body,
		"expired":       SignVisitor(map[string]string{"customer": "c-1042"}, key, now.Add(-time.Minute)),
		"for ever":      SignVisitor(map[string]string{"customer": "c-1042"}, key, now.Add(48*time.Hour)),
		"a bad claim":   SignVisitor(map[string]string{"Customer Id": "x"}, key, now.Add(time.Hour)),
		"a long one":    strings.Repeat("a", MaxVisitorToken+1),
		"two lines":     SignVisitor(map[string]string{"name": "Ana\nadmin"}, key, now.Add(time.Hour)),
		"empty":         "",
		"short key use": "x.y",
	} {
		if _, err := VerifyVisitor(bad, key, now); err == nil {
			t.Errorf("%s was taken for the site's word", name)
		}
	}
	if _, err := VerifyVisitor(tok, []byte("short"), now); err == nil {
		t.Error("a short key was used")
	}
}

// An agent action names an agent and what it asks for, and one that needs
// to know who the visitor is needs the site's key named.
func TestAnAgentActionMeansWhatItSays(t *testing.T) {
	ok := Assistant{Name: "help", Title: "Help", IdentitySecret: "shop-visitors", Actions: []Action{
		{Name: "booking", Kind: Agent, Target: "bookings", Description: "Look up your booking", Fields: []string{"booking_ref"}},
		{Name: "orders", Kind: Agent, Target: "orders", Description: "Check your order", Identity: true, Writes: true},
	}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		a    Assistant
		want string
	}{
		{Assistant{Name: "h", Title: "H", Actions: []Action{{Name: "x", Kind: Agent, Target: "../x", Description: "d"}}}, "not an agent's name"},
		{Assistant{Name: "h", Title: "H", Actions: []Action{{Name: "x", Kind: Agent, Target: "a", Description: "d", Identity: true}}}, "identity_secret"},
		{Assistant{Name: "h", Title: "H", Actions: []Action{{Name: "x", Kind: Agent, Target: "a", Description: "d", Fields: []string{"Bad Field"}}}}, "not a field's name"},
		{Assistant{Name: "h", Title: "H", Actions: []Action{{Name: "x", Kind: Link, Target: "about", Description: "d", Writes: true}}}, "only an agent action"},
	} {
		if err := c.a.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.a.Actions, err, c.want)
		}
	}
	p, err := ok.Propose(ActionCall{Name: "booking", Args: map[string]string{"booking_ref": "HB-2201", "other": "x"}})
	if err != nil || p.Args["booking_ref"] != "HB-2201" || p.Args["other"] != "" {
		t.Fatalf("%+v %v", p, err)
	}
}
