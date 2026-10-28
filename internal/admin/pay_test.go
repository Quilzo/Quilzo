// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/pay"
)

// The Payments screen says what has to be true before payments can be
// turned on, asks a second administrator to turn them on, and once they are
// on shows the links, brings them up to date, reads orders from the
// provider, and turns them off. Nobody but an administrator opens it.
func TestThePaymentsScreen(t *testing.T) {
	srv, token := setup(t)
	status := PayStatus{Offers: 12, Catalogue: ""}
	var enabled, disabled, synced int
	var shipTo []string
	srv.Pay = &PayHooks{
		Status: func() (PayStatus, error) { return status, nil },
		Enable: func(s []string, done string, _ Actor) (bool, error) {
			enabled++
			shipTo = s
			return false, nil
		},
		Disable: func(Actor) error { disabled++; return nil },
		Sync:    func(Actor) (int, int, error) { synced++; return 2, 1, nil },
		Orders: func(int, Actor) ([]pay.Order, error) {
			return []pay.Order{{Ref: "cs_1", At: time.Date(2026, 10, 28, 9, 30, 0, 0, time.UTC), Amount: 2400,
				Currency: "GBP", Paid: true, Offer: "letterpress-cards", Name: "Ana Diaz", Email: "ana@example.com",
				Ship: "4 Mill Lane, Leeds"}}, nil
		},
	}

	page := get(t, srv, "/pay", token).Body.String()
	if !strings.Contains(page, "restricted key") || strings.Contains(page, `value="enable"`) {
		t.Fatal("with no key the screen offers to turn payments on, or does not say how to set one")
	}
	whole(t, page)

	status.Key = true
	page = get(t, srv, "/pay", token).Body.String()
	if !strings.Contains(page, `value="enable"`) || !strings.Contains(page, "in test mode") {
		t.Fatal("with a test key and a catalogue the screen does not offer to turn payments on")
	}
	whole(t, page)
	code, loc := postFormLoc(t, srv, token, "/pay/act", url.Values{"do": {"enable"}, "ship_to": {"gb, ie"}})
	if code != http.StatusSeeOther || !strings.Contains(loc, "second+administrator") || enabled != 1 ||
		strings.Join(shipTo, ",") != "GB,IE" {
		t.Fatalf("asking went %d to %q, shipping to %v", code, loc, shipTo)
	}

	status.Waiting = true
	if page := get(t, srv, "/pay", token).Body.String(); !strings.Contains(page, "waits for a second administrator") {
		t.Fatal("a waiting request is not shown")
	}

	status = PayStatus{Provider: pay.ProviderStripe, By: []string{"dana", "sam"}, At: time.Now(), Key: true, LiveKey: true,
		Offers: 12, Live: 11, ToMake: 1, Synced: time.Now(), Options: pay.Options{ShipTo: []string{"GB"}}}
	page = get(t, srv, "/pay", token).Body.String()
	for _, want := range []string{"live: real money", "dana and sam", "1 to make", "Show the latest orders", "Turn payments off"} {
		if !strings.Contains(page, want) {
			t.Errorf("the screen does not say %q", want)
		}
	}
	whole(t, page)
	orders := get(t, srv, "/pay?orders=1", token)
	if b := orders.Body.String(); !strings.Contains(b, "ana@example.com") || !strings.Contains(b, "24.00 GBP") ||
		orders.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("the orders are not shown, or a browser may keep them")
	}
	whole(t, orders.Body.String())
	if _, loc := postFormLoc(t, srv, token, "/pay/act", url.Values{"do": {"sync"}}); !strings.Contains(loc, "2+new") || synced != 1 {
		t.Errorf("syncing went to %q", loc)
	}
	if _, loc := postFormLoc(t, srv, token, "/pay/act", url.Values{"do": {"disable"}}); !strings.Contains(loc, "off") || disabled != 1 {
		t.Errorf("turning off went to %q", loc)
	}

	if err := srv.Policy.Grant(auth.Binding{Principal: "rae", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	rae, _, err := srv.Tokens.IssueSession("rae", "rae", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if code := get(t, srv, "/pay?orders=1", rae).Code; code != http.StatusForbidden {
		t.Errorf("an author read the orders: %d", code)
	}
	if code, _ := postFormLoc(t, srv, rae, "/pay/act", url.Values{"do": {"disable"}}); code != http.StatusForbidden || disabled != 1 {
		t.Errorf("an author turned payments off: %d", code)
	}
}
