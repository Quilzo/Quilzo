// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/pay"
	"github.com/quilzo/quilzo/internal/render"
)

// shopProvider is a payment provider in memory.
type shopProvider struct {
	n       int
	made    []pay.Offer
	retired []string
	orders  []pay.Order
	fail    error
}

func (p *shopProvider) Name() string { return pay.ProviderStripe }

func (p *shopProvider) Make(_ context.Context, o pay.Offer, _ pay.Options) (pay.Link, error) {
	if p.fail != nil {
		return pay.Link{}, p.fail
	}
	p.n++
	p.made = append(p.made, o)
	return pay.Link{Offer: o, URL: fmt.Sprintf("https://buy.stripe.com/t_%d", p.n), Provider: pay.ProviderStripe,
		Ref: fmt.Sprintf("plink_%d", p.n), Made: time.Now()}, nil
}

func (p *shopProvider) Retire(_ context.Context, l pay.Link) error {
	if p.fail != nil {
		return p.fail
	}
	p.retired = append(p.retired, l.Ref)
	return nil
}

func (p *shopProvider) Orders(context.Context, int) ([]pay.Order, error) { return p.orders, nil }

// shopStore is the demonstration shop, published, with a provider in memory.
func shopStore(t *testing.T) (string, *shopProvider) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(root, []string{"--templates", filepath.Join(root, "templates")}); err != nil {
		t.Fatal(err)
	}
	p := &shopProvider{}
	payProviderSeam = func(string) (pay.Provider, error) { return p, nil }
	t.Cleanup(func() { payProviderSeam = nil })
	return root, p
}

var buyRow = regexp.MustCompile(`<p>([^|<]*)\|([^|<]*)\|([^|<]*)\|([^<]*)</p>`)

// shopPage is what the live shop page offers: each product's name, price
// and where its Buy button goes.
func shopPage(t *testing.T, root string) map[string][2]string {
	t.Helper()
	st, err := siteFor(root, &Design{Layouts: render.OneLayout(`<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head><body>` +
		`{% for feed in feeds %}{% for row in feed.rows %}<p>{{ row.slug }}|{{ row.price }}|{{ row.buy_href }}|{{ row.buy_price }}</p>{% end %}{% end %}</body></html>`)}, siteOpts{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/shop", nil))
	out := map[string][2]string{}
	for _, m := range buyRow.FindAllStringSubmatch(w.Body.String(), -1) {
		out[m[1]] = [2]string{m[2], m[3]}
		// A button says what it charges, and it is what the record says.
		if m[3] != "" && !strings.HasPrefix(m[4], "£") {
			t.Errorf("%s's Buy button charges %q", m[1], m[4])
		}
	}
	if len(out) == 0 {
		t.Fatalf("the shop page lists nothing: %d %s", w.Code, w.Body)
	}
	return out
}

// reprice changes a product's price in the draft.
func reprice(t *testing.T, root, slug string, price int) {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := draftTree(s)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := collection.Build(s, tree, "products", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range idx.Records {
		if r.Fields["slug"] == slug {
			r.Fields["price"] = float64(price)
			next, _, err := collection.PutMany(s, tree, "products", []collection.Record{{ID: r.ID, Fields: r.Fields}}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := commitTree(root, s, next, "reprice "+slug, "dana"); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("no product %s", slug)
}

// A shop sells through the provider's checkout once payments are on: every
// product for sale gets a link and a Buy button, a product that cannot be
// bought gets neither, a new price gets a new link after it is published
// and the old one is retired, and a price no link charges yet shows no
// button at all.
func TestAShopSellsAtExactlyThePublishedPrice(t *testing.T) {
	root, prov := shopStore(t)
	before := shopPage(t, root)
	for slug, v := range before {
		if v[1] != "" {
			t.Fatalf("%s has a Buy button before payments are on", slug)
		}
	}

	on, err := requestPay(root, dual.PayChange{Provider: pay.ProviderStripe, ShipTo: []string{"GB"}}, "", asAdmin("dana"))
	if err != nil || !on {
		t.Fatalf("turning payments on: %v %v", on, err)
	}
	made, retired, err := syncPay(root, asAdmin("dana"))
	if err != nil || len(made) == 0 || len(retired) != 0 {
		t.Fatalf("the first sync made %d and retired %d: %v", len(made), len(retired), err)
	}
	page := shopPage(t, root)
	selling, notForSale := 0, ""
	for slug, v := range page {
		if v[1] == "" {
			notForSale = slug
			continue
		}
		selling++
		if !strings.HasPrefix(v[1], "https://buy.stripe.com/") {
			t.Errorf("%s's Buy button goes to %s", slug, v[1])
		}
	}
	if selling != len(made) {
		t.Fatalf("%d links made and %d Buy buttons", len(made), selling)
	}
	if notForSale == "" {
		t.Error("every product has a Buy button; the demonstration has one that cannot be bought")
	}

	// A new price, published: the new link is made and the old one retired.
	slug := prov.made[0].ID
	old := page[slug][1]
	reprice(t, root, slug, int(prov.made[0].Amount)+100)
	if err := runPublish(t, root, "--no-a11y-check"); err != nil {
		t.Fatal(err)
	}
	after := shopPage(t, root)
	if after[slug][1] == "" || after[slug][1] == old {
		t.Fatalf("after a new price the button goes to %q (was %q)", after[slug][1], old)
	}
	if len(prov.retired) != 1 {
		t.Fatalf("the old price's link was not retired: %v", prov.retired)
	}

	// The provider is down when the next price changes: that product shows
	// no button rather than one charging the old price, and the rest sell.
	prov.fail = errors.New("connection refused")
	reprice(t, root, slug, int(prov.made[0].Amount)+200)
	if err := runPublish(t, root, "--no-a11y-check"); err != nil {
		t.Fatalf("a provider being down stopped a publish: %v", err)
	}
	down := shopPage(t, root)
	if down[slug][1] != "" {
		t.Fatalf("a price no link charges has a Buy button: %s", down[slug][1])
	}
	others := 0
	for s, v := range down {
		if s != slug && v[1] != "" {
			others++
		}
	}
	if others != selling-1 {
		t.Fatalf("%d other products still sell, not %d", others, selling-1)
	}
	if st, _ := loadPayState(root); !strings.Contains(st.Problem, "connection refused") {
		t.Fatalf("the failure was not kept for the screen: %q", st.Problem)
	}
	prov.fail = nil
	if _, _, err := syncPay(root, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if shopPage(t, root)[slug][1] == "" {
		t.Fatal("once the provider answered, the product still had no button")
	}

	// Orders are named by what their link sold, and the record says
	// somebody looked and nothing about the buyer.
	prov.orders = []pay.Order{{Ref: "cs_1", Amount: 2400, Currency: "GBP", Paid: true, Link: "plink_1",
		Name: "Ana Diaz", Email: "ana@example.com", Ship: "4 Mill Lane, Leeds"}}
	orders, err := readOrders(root, 10, asAdmin("dana"))
	if err != nil || len(orders) != 1 || orders[0].Offer != slug {
		t.Fatalf("orders %+v: %v", orders, err)
	}
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		for k, v := range e.Detail {
			if strings.Contains(v, "ana@example.com") || strings.Contains(v, "Mill Lane") || strings.Contains(v, "Ana Diaz") {
				t.Fatalf("the audit log kept a buyer's details under %s in %s", k, e.Action)
			}
		}
	}

	// Off: the buttons go at once and every link is retired.
	if err := payDisable(root, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	for s, v := range shopPage(t, root) {
		if v[1] != "" {
			t.Fatalf("%s still has a Buy button with payments off", s)
		}
	}
	book, _ := loadPayBook(root)
	for _, l := range book.Links {
		if l.Live() {
			t.Fatalf("%s still sells with payments off", l.ID)
		}
	}
}

// Two administrators turn payments on: one asks, another approves, and the
// links are made when they do.
func TestPaymentsWaitForASecondAdministrator(t *testing.T) {
	root, prov := shopStore(t)
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "admin"})
	on, err := requestPay(root, dual.PayChange{Provider: pay.ProviderStripe}, "", asAdmin("dana"))
	if err != nil || on {
		t.Fatalf("one administrator turned payments on: %v %v", on, err)
	}
	if st, _ := loadPayState(root); st.Provider != "" {
		t.Fatal("payments are on before anybody approved")
	}
	if !payPending(root) {
		t.Fatal("the request is not waiting")
	}
	pend, err := dualStore(root).Pending(time.Now())
	if err != nil || len(pend) != 1 {
		t.Fatalf("%v %v", pend, err)
	}
	r, err := dualStore(root).Decide(pend[0].ID, "sam", true, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := applyDual(root, r, "sam"); err != nil {
		t.Fatal(err)
	}
	st, _ := loadPayState(root)
	if st.Provider != pay.ProviderStripe || strings.Join(st.By, ",") != "dana,sam" {
		t.Fatalf("approved, payments are %+v", st)
	}
	if len(prov.made) == 0 {
		t.Fatal("approving made no links")
	}

	// Without a catalogue there is nothing to sell, and nobody is asked.
	if err := cmdConfig(root, []string{"unset", "site.catalogue"}); err != nil {
		t.Fatal(err)
	}
	if _, err := requestPay(root, dual.PayChange{Provider: pay.ProviderStripe}, "", asAdmin("dana")); err == nil ||
		!strings.Contains(err.Error(), "site.catalogue") {
		t.Fatalf("payments for no catalogue: %v", err)
	}
}
