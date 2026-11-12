// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package pay

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/listing"
)

const (
	testKey = "rk_test_0123456789abcdef"
	liveKey = "rk_live_0123456789abcdef"
)

// fakeStripe answers as Stripe does, and keeps what it was asked.
//
// It keeps the links it made, each in the mode of the key that made it, as
// Stripe does: a key sees and changes only the links of its own mode, and a
// link it cannot see is "No such payment_link". The list of what sells is
// counted in listed rather than asked, so what a test says about the
// requests that make and retire links is unchanged by a sync asking it.
type fakeStripe struct {
	mu      sync.Mutex
	asked   []*http.Request
	forms   []map[string]string
	n       int
	refuse  string
	retired []string
	// links are the payment links made, by id, with the mode that made
	// them; active those still selling. page is how many a list answers
	// at once.
	links  map[string]string
	active map[string]bool
	order  []string
	listed int
	page   int
}

// forget is the provider losing every link, as a test account reset does.
func (f *fakeStripe) forget() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.links, f.active, f.order = nil, nil, nil
}

func (f *fakeStripe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mode := map[string]string{"Bearer " + testKey: "test", "Bearer " + liveKey: "live"}[r.Header.Get("Authorization")]
	if mode == "" || r.Header.Get("Stripe-Version") != StripeVersion {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"message":"Invalid API Key provided"}}`)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/payment_links" {
		f.listed++
		f.list(w, r, mode)
		return
	}
	_ = r.ParseForm()
	form := map[string]string{}
	for k, v := range r.Form {
		form[k] = v[0]
	}
	f.asked = append(f.asked, r)
	f.forms = append(f.forms, form)
	if f.refuse != "" && strings.HasPrefix(r.URL.Path, f.refuse) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":{"message":"No such thing"}}`)
		return
	}
	f.n++
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/prices":
		fmt.Fprintf(w, `{"id":"price_%d"}`, f.n)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/payment_links":
		id, at := fmt.Sprintf("plink_%d", f.n), fmt.Sprintf("https://buy.stripe.com/test_%d", f.n)
		if mode == "live" {
			at = fmt.Sprintf("https://buy.stripe.com/%dlive", f.n)
		}
		if f.links == nil {
			f.links, f.active = map[string]string{}, map[string]bool{}
		}
		f.links[id], f.active[id], f.order = mode, true, append(f.order, id)
		fmt.Fprintf(w, `{"id":%q,"url":%q}`, id, at)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/payment_links/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/payment_links/")
		if f.links[id] != mode {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":{"code":"resource_missing","message":"No such payment_link: '%s'"}}`, id)
			return
		}
		f.active[id] = false
		f.retired = append(f.retired, id)
		fmt.Fprint(w, `{}`)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/checkout/sessions":
		fmt.Fprint(w, `{"data":[{"id":"cs_1","created":1793000000,"amount_total":420,"currency":"gbp",
			"payment_status":"paid","payment_link":"plink_2",
			"customer_details":{"email":"ana@example.com","name":"Ana"},
			"shipping_details":{"name":"Ana","address":{"line1":"4 Mill Lane","city":"Leeds","postal_code":"LS1 4AB","country":"GB"}}}]}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// list answers what sells, a page at a time, newest first, as Stripe does.
func (f *fakeStripe) list(w http.ResponseWriter, r *http.Request, mode string) {
	q := r.URL.Query()
	if q.Get("active") != "true" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":{"message":"asked for links that do not sell"}}`)
		return
	}
	var ids []string
	for i := len(f.order) - 1; i >= 0; i-- {
		if id := f.order[i]; f.links[id] == mode && f.active[id] {
			ids = append(ids, id)
		}
	}
	if after := q.Get("starting_after"); after != "" {
		for i, id := range ids {
			if id == after {
				ids = ids[i+1:]
				break
			}
		}
	}
	page := f.page
	if page == 0 {
		page = 100
	}
	more := len(ids) > page
	if more {
		ids = ids[:page]
	}
	var data []string
	for _, id := range ids {
		data = append(data, fmt.Sprintf(`{"id":%q,"active":true}`, id))
	}
	fmt.Fprintf(w, `{"object":"list","data":[%s],"has_more":%v}`, strings.Join(data, ","), more)
}

func stripeAt(t *testing.T) (*Stripe, *fakeStripe) {
	t.Helper()
	f := &fakeStripe{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &Stripe{Key: testKey, Base: srv.URL}, f
}

var sourdough = Offer{ID: "sourdough", Title: "Country sourdough", Amount: 420, Currency: "GBP"}

// A catalogue row is an offer exactly as the catalogue feed reads it, and
// not one when it cannot be bought.
func TestARowIsAnOfferOnlyWhenItCanBeBought(t *testing.T) {
	row := map[string]any{"slug": "sourdough", "name": "Country sourdough", "price": float64(420), "currency": "gbp"}
	if o, ok := OfferOf(row); !ok || o != sourdough {
		t.Fatalf("read as %+v, %v", o, ok)
	}
	for name, change := range map[string]map[string]any{
		"sold out":        {"availability": "sold_out"},
		"no price":        {"price": nil},
		"free":            {"price": float64(0)},
		"half a penny":    {"price": 12.5},
		"no currency":     {"currency": "pounds"},
		"no name or slug": {"slug": "", "id": "", "name": ""},
	} {
		r := map[string]any{}
		for k, v := range row {
			r[k] = v
		}
		for k, v := range change {
			r[k] = v
		}
		if o, ok := OfferOf(r); ok {
			t.Errorf("%s: read as an offer %+v", name, o)
		}
	}
}

// A Buy button appears only for a live link selling exactly what the page
// says, at the provider's own checkout.
func TestABuyButtonGoesOnlyWhereThePriceIsTheLinks(t *testing.T) {
	b := &Book{Links: []Link{{Offer: sourdough, URL: "https://buy.stripe.com/abc", Provider: ProviderStripe, Ref: "plink_1"}}}
	row := map[string]any{"slug": "sourdough", "name": "Country sourdough", "price": float64(420), "currency": "GBP"}
	if got, price := b.Buy(row); got != "https://buy.stripe.com/abc" || price != "£4.20" {
		t.Fatalf("the button goes to %q for %q", got, price)
	}
	repriced := map[string]any{"slug": "sourdough", "name": "Country sourdough", "price": float64(450), "currency": "GBP"}
	if got, _ := b.Buy(repriced); got != "" {
		t.Fatalf("a new price was offered the old price's link %q", got)
	}
	renamed := map[string]any{"slug": "sourdough", "name": "Sourdough", "price": float64(420), "currency": "GBP"}
	if got, _ := b.Buy(renamed); got != "" {
		t.Fatal("a renamed product was offered a link that names it otherwise")
	}
	b.Retire("plink_1", time.Now())
	if got, _ := b.Buy(row); got != "" {
		t.Fatal("a retired link was offered")
	}
	for _, bad := range []string{"http://buy.stripe.com/abc", "https://buy.stripe.com.evil.example/abc",
		"https://evil.example/abc", "javascript:alert(1)", "https://user@buy.stripe.com/x", "https://buy.stripe.com:8443/x"} {
		bk := &Book{Links: []Link{{Offer: sourdough, URL: bad, Provider: ProviderStripe, Ref: "plink_2"}}}
		if got, _ := bk.Buy(row); got != "" {
			t.Errorf("%s was offered as a checkout", bad)
		}
	}
}

// Syncing makes a link for each new offer and price, then retires what is
// no longer offered, at Stripe, with the key, the pinned version and an
// idempotency key on everything it makes.
func TestSyncMakesLinksForPricesAndRetiresTheOldOnes(t *testing.T) {
	s, f := stripeAt(t)
	b := &Book{}
	opts := Options{ShipTo: []string{"GB", "IE"}, Done: "Thank you: we bake it fresh."}
	made, retired, err := Sync(context.Background(), s, b, []Offer{sourdough}, opts, time.Now())
	if err != nil || len(made) != 1 || len(retired) != 0 {
		t.Fatalf("made %v retired %v: %v", made, retired, err)
	}
	if l := made[0]; l.URL != "https://buy.stripe.com/test_2" || l.Ref != "plink_2" || l.Provider != ProviderStripe || l.Offer != sourdough {
		t.Fatalf("the link is %+v", l)
	}
	price, link := f.forms[0], f.forms[1]
	if price["currency"] != "gbp" || price["unit_amount"] != "420" || price["product_data[name]"] != "Country sourdough" ||
		price["product_data[metadata][quilzo_offer]"] != "sourdough" {
		t.Errorf("the price asked for is %v", price)
	}
	if link["line_items[0][price]"] != "price_1" || link["line_items[0][quantity]"] != "1" ||
		link["shipping_address_collection[allowed_countries][1]"] != "IE" ||
		link["after_completion[hosted_confirmation][custom_message]"] != opts.Done {
		t.Errorf("the link asked for is %v", link)
	}
	for _, r := range f.asked {
		if r.Header.Get("Idempotency-Key") == "" {
			t.Errorf("%s %s carried no idempotency key", r.Method, r.URL.Path)
		}
	}

	// Again, nothing changed: nothing is made or retired, and Stripe is
	// asked only what still sells.
	asked, listed := len(f.asked), f.listed
	if made, retired, err := Sync(context.Background(), s, b, []Offer{sourdough}, opts, time.Now()); err != nil || len(made)+len(retired) != 0 || len(f.asked) != asked || f.listed != listed+1 {
		t.Fatalf("an unchanged catalogue made %v and retired %v, listing %d time(s): %v", made, retired, f.listed-listed, err)
	}

	// A new price: a new link first, then the old one retired.
	dearer := sourdough
	dearer.Amount = 450
	made, retired, err = Sync(context.Background(), s, b, []Offer{dearer}, opts, time.Now())
	if err != nil || len(made) != 1 || len(retired) != 1 || retired[0].Ref != "plink_2" || f.retired[0] != "plink_2" {
		t.Fatalf("a new price made %v, retired %v (%v): %v", made, retired, f.retired, err)
	}
	if _, ok := b.Live(dearer); !ok {
		t.Fatal("the new price has no live link")
	}
	if _, ok := b.Live(sourdough); ok {
		t.Fatal("the old price still sells")
	}
	if l, ok := b.Named("plink_2"); !ok || l.Live() {
		t.Fatal("a retired link was forgotten, so its orders cannot be named")
	}

	// Gone from the catalogue: retired, nothing made.
	if made, retired, err := Sync(context.Background(), s, b, nil, opts, time.Now()); err != nil || len(made) != 0 || len(retired) != 1 {
		t.Fatalf("a product taken off sale: made %v retired %v, %v", made, retired, err)
	}
}

// A link is checked against the provider and the key it is made with.
//
// The book was the only thing a sync looked at, so a link was selling for
// as long as its price was unchanged, whatever Stripe said. A shop set up
// on a test key and then given its live key kept every Buy button on
// test-mode checkout, where real cards are refused, and pay sync said the
// links matched; links Stripe no longer had stayed on the page; and one
// Stripe could not find could never be retired, so every sync after ended
// "Stripe refused it (404): No such payment_link".
func TestALinkIsCheckedAgainstTheProviderAndTheKey(t *testing.T) {
	s, f := stripeAt(t)
	b := &Book{}
	rye := Offer{ID: "rye", Title: "Seeded rye", Amount: 460, Currency: "GBP"}
	row := map[string]any{"slug": "sourdough", "name": "Country sourdough", "price": float64(420), "currency": "GBP"}
	made, _, err := Sync(context.Background(), s, b, []Offer{sourdough, rye}, Options{}, time.Now())
	if err != nil || len(made) != 2 || made[0].Mode != "test" {
		t.Fatalf("made %+v: %v", made, err)
	}
	testLink := made[1].URL // sourdough sorts after rye

	// The live key: what the test key made sells nothing a customer can
	// pay for, so it is made again with the live key and the test link is
	// not offered.
	s.Key = liveKey
	made, retired, err := Sync(context.Background(), s, b, []Offer{sourdough, rye}, Options{}, time.Now())
	if err != nil || len(made) != 2 || len(retired) != 2 {
		t.Fatalf("with the live key: made %v, retired %v: %v", made, retired, err)
	}
	for _, l := range made {
		if l.Mode != "live" || strings.Contains(l.URL, "/test_") {
			t.Errorf("made %+v with the live key", l)
		}
	}
	if href, _ := b.Buy(row); href == testLink || href == "" || strings.Contains(href, "/test_") {
		t.Fatalf("the Buy button goes to %q with the live key", href)
	}

	// Gone at the provider: no longer offered, and made again.
	f.forget()
	made, retired, err = Sync(context.Background(), s, b, []Offer{sourdough, rye}, Options{}, time.Now())
	if err != nil || len(made) != 2 || len(retired) != 2 {
		t.Fatalf("after the provider lost them: made %v, retired %v: %v", made, retired, err)
	}
	if href, _ := b.Buy(row); href != made[1].URL {
		t.Fatalf("the Buy button goes to %q, not the link made again %q", href, made[1].URL)
	}

	// Turning payments off once the provider has lost them retires them,
	// rather than keeping them in the book as selling.
	f.forget()
	_, retired, err = Sync(context.Background(), s, b, nil, Options{}, time.Now())
	if err != nil || len(retired) != 2 || b.SellingIn("") != 0 {
		t.Fatalf("retiring links the provider no longer has: retired %v: %v", retired, err)
	}
	// A link Stripe cannot find when it is retired is retired already,
	// and saying otherwise on every sync after fixes nothing; one of the
	// other mode is not, because this key cannot see it.
	gone := Link{Offer: rye, URL: "https://buy.stripe.com/9live", Provider: ProviderStripe, Ref: "plink_9", Mode: "live"}
	if err := s.Retire(context.Background(), gone); err != nil {
		t.Fatalf("retiring a link Stripe does not have: %v", err)
	}
	gone.Mode = "test"
	if err := s.Retire(context.Background(), gone); err == nil || !strings.Contains(err.Error(), "No such payment_link") {
		t.Fatalf("retiring a test link with the live key: %v", err)
	}

	// A test key cannot stop a link the live key made, which still takes
	// real money: it is not offered on a shop testing with a test key, and
	// the sync says it is still selling at Stripe.
	s.Key = liveKey
	b = &Book{}
	if _, _, err := Sync(context.Background(), s, b, []Offer{rye}, Options{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.Key = testKey
	made, _, err = Sync(context.Background(), s, b, []Offer{rye}, Options{}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "real money") || len(made) != 1 || made[0].Mode != "test" {
		t.Fatalf("a test key over live links: made %v: %v", made, err)
	}
	if l, ok := b.Live(rye); !ok || l.Mode != "test" {
		t.Fatalf("a shop on a test key offers %+v", l)
	}
}

// What sells is read a page at a time, to the end.
func TestWhatSellsIsReadToTheEnd(t *testing.T) {
	s, f := stripeAt(t)
	b := &Book{}
	var offers []Offer
	for i := 0; i < 5; i++ {
		offers = append(offers, Offer{ID: fmt.Sprintf("loaf-%d", i), Title: "Loaf", Amount: 400, Currency: "GBP"})
	}
	if _, _, err := Sync(context.Background(), s, b, offers, Options{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.page = 2
	made, retired, err := Sync(context.Background(), s, b, offers, Options{}, time.Now())
	if err != nil || len(made)+len(retired) != 0 || f.listed != 3 {
		t.Fatalf("made %v, retired %v, %d page(s): %v", made, retired, f.listed, err)
	}
}

// What Stripe refuses is said, with what it said and never the key; what
// worked before it stays in the book.
func TestARefusalIsSaidAndWhatWorkedIsKept(t *testing.T) {
	s, f := stripeAt(t)
	b := &Book{}
	rye := Offer{ID: "rye", Title: "Seeded rye", Amount: 460, Currency: "GBP"}
	if _, _, err := Sync(context.Background(), s, b, []Offer{sourdough}, Options{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.refuse = "/v1/payment_links/"
	made, _, err := Sync(context.Background(), s, b, []Offer{rye}, Options{}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "No such thing") || strings.Contains(err.Error(), testKey) {
		t.Fatalf("the refusal said %v", err)
	}
	if len(made) != 1 {
		t.Fatalf("the new link was not kept: %v", made)
	}
	if _, ok := b.Live(rye); !ok {
		t.Fatal("the link that was made is not in the book")
	}
	if _, ok := b.Live(sourdough); !ok {
		t.Fatal("a link Stripe would not retire was marked retired")
	}

	bad := &Stripe{Key: "sk_test_" + strings.Repeat("x", 20), Base: s.Base}
	if _, err := bad.Orders(context.Background(), 5); err == nil || strings.Contains(err.Error(), bad.Key) {
		t.Fatalf("a wrong key: %v", err)
	}
	if _, err := (&Stripe{Key: "pk_test_publishable", Base: s.Base}).Orders(context.Background(), 5); err == nil {
		t.Fatal("a publishable key was sent")
	}
	if _, _, err := Sync(context.Background(), s, b, nil, Options{ShipTo: []string{"england"}}, time.Now()); err == nil {
		t.Fatal("a country that is not a code was sent")
	}
}

// Orders are read from Stripe, with the buyer and where it goes, and named
// by the link they came through.
func TestOrdersAreReadFromStripe(t *testing.T) {
	s, f := stripeAt(t)
	orders, err := s.Orders(context.Background(), 10)
	if err != nil || len(orders) != 1 {
		t.Fatalf("%v %v", orders, err)
	}
	o := orders[0]
	if o.Ref != "cs_1" || !o.Paid || o.Total() != "4.20 GBP" || o.Email != "ana@example.com" || o.Link != "plink_2" ||
		o.Ship != "Ana, 4 Mill Lane, Leeds, LS1 4AB, GB" {
		t.Fatalf("the order is %+v", o)
	}
	if q := f.asked[0].URL.Query(); q.Get("status") != "complete" || q.Get("limit") != "10" {
		t.Errorf("asked for %v", q)
	}
}

func TestAPriceIsShownTheWayAShopperReadsIt(t *testing.T) {
	for o, want := range map[Offer]string{
		{Amount: 420, Currency: "GBP"}:  "£4.20",
		{Amount: 5, Currency: "EUR"}:    "€0.05",
		{Amount: 1200, Currency: "JPY"}: "¥1200",
		{Amount: 999, Currency: "AUD"}:  "A$9.99",
		{Amount: 4500, Currency: "SEK"}: "45.00 SEK",
	} {
		if got := o.Display(); got != want {
			t.Errorf("%d %s reads %q, not %q", o.Amount, o.Currency, got, want)
		}
	}
}

// The price a catalogue row shows and the price its Buy button says are one
// price, written once. The page's was a copy kept by hand, which said
// £12.00 beside a button that charged £13.00 once the price had changed.
func TestThePageAndItsButtonSayOnePrice(t *testing.T) {
	for _, row := range []map[string]any{
		{"slug": "ink", "name": "Indigo ink", "price": float64(1300), "currency": "GBP", "price_display": "£12.00"},
		{"slug": "club", "name": "Ink club", "price": float64(420), "currency": "gbp", "interval": "month", "price_display": "£4.20"},
		{"slug": "yen", "name": "Yen ink", "price": float64(1500), "currency": "JPY"},
		{"slug": "krona", "name": "Krona ink", "price": float64(4500), "currency": "SEK"},
	} {
		o, ok := OfferOf(row)
		if !ok {
			t.Fatalf("%v is no offer", row["slug"])
		}
		b := &Book{Links: []Link{{Offer: o, URL: "https://buy.stripe.com/x", Provider: ProviderStripe, Ref: "plink_1"}}}
		_, charged := b.Buy(row)
		shown, ok := listing.WrittenPrice(row)
		if !ok || shown != charged {
			t.Errorf("%v: the page shows %q and the button charges %q", row["slug"], shown, charged)
		}
	}
}

// A provider that does not answer is said once, not once for each product.
func TestAProviderThatDoesNotAnswerIsSaidOnce(t *testing.T) {
	s := &Stripe{Key: testKey, Base: "http://127.0.0.1:1"}
	offers := []Offer{sourdough, {ID: "rye", Title: "Rye", Amount: 460, Currency: "GBP"}}
	_, _, err := Sync(context.Background(), s, &Book{}, offers, Options{}, time.Now())
	if !errors.Is(err, ErrUnreachable) || strings.Count(err.Error(), "did not answer") != 1 ||
		!strings.Contains(err.Error(), "2 payment link(s) were not made") {
		t.Fatalf("%v", err)
	}
}
