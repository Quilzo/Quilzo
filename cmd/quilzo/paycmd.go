// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/pay"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Taking payments for what the catalogue sells (internal/pay).
//
// Two administrators turn it on, because from then on a price on a page is a
// price somebody pays; one turns it off. The provider's key is a sealed
// secret (`quilzo secret set stripe`) or QUILZO_SECRET_STRIPE, read by the
// admin and never by the site. After anything is published or rolled back
// the links are brought into line with the live catalogue, and until they
// are, a product whose price changed shows no Buy button.

func payDir(root string) string       { return filepath.Join(root, "pay") }
func payStatePath(root string) string { return filepath.Join(payDir(root), "pay.json") }
func payBookPath(root string) string  { return filepath.Join(payDir(root), "links.json") }

// paySecret is the name the provider's key is kept under.
const paySecret = "stripe"

// payState is whether the site takes payments, and through whom.
type payState struct {
	// Provider is who takes the money; empty is no payments.
	Provider string      `json:"provider,omitempty"`
	Options  pay.Options `json:"options"`
	// By are the administrators who turned it on, and At when.
	By []string  `json:"by,omitempty"`
	At time.Time `json:"at,omitempty"`
	// Synced is when the links last matched the live catalogue, and Problem
	// what stopped the last attempt.
	Synced  time.Time `json:"synced,omitempty"`
	Problem string    `json:"problem,omitempty"`
}

func loadPayState(root string) (payState, error) {
	var st payState
	if err := loadJSON(payStatePath(root), &st); err != nil && !errors.Is(err, os.ErrNotExist) {
		return st, err
	}
	return st, nil
}

func savePayState(root string, st payState) error {
	if err := os.MkdirAll(payDir(root), 0o700); err != nil {
		return err
	}
	return saveJSON(payStatePath(root), st)
}

func loadPayBook(root string) (*pay.Book, error) {
	b := &pay.Book{}
	if err := loadJSON(payBookPath(root), b); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return b, nil
}

// payProviderSeam replaces the provider in tests.
var payProviderSeam func(root string) (pay.Provider, error)

// payProvider is the provider the site sells through, with its key.
func payProvider(root, name string) (pay.Provider, error) {
	if payProviderSeam != nil {
		return payProviderSeam(root)
	}
	if name != pay.ProviderStripe {
		return nil, fmt.Errorf("%q is not a provider this sells through; stripe is", name)
	}
	key, err := readSecret(root, paySecret)
	if err != nil {
		return nil, err
	}
	if !pay.ValidStripeKey(key) {
		return nil, errors.New("the stripe credential is not a Stripe secret or restricted key (sk_… or rk_…)")
	}
	return &pay.Stripe{Key: key}, nil
}

// liveOffers are what the published catalogue sells: every row of the
// listing site.catalogue names, at the live site, that is an offer.
func liveOffers(root string) ([]pay.Offer, error) {
	cfg, err := loadConfig(root)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(cfg.Raw("site.catalogue"))
	if name == "" {
		return nil, errors.New("no catalogue is named, so there is nothing to sell; name its listing with site.catalogue")
	}
	set, err := loadListings(root)
	if err != nil {
		return nil, err
	}
	l, ok := set.Get(name)
	if !ok {
		return nil, fmt.Errorf("site.catalogue names %q and no listing has that name", name)
	}
	s, err := open(root)
	if err != nil {
		return nil, err
	}
	tree, err := liveTree(s)
	if err != nil || tree == "" {
		return nil, err
	}
	idx, err := collection.Build(s, tree, l.Collection, nil)
	if err != nil {
		return nil, err
	}
	rows, _, err := listing.Every(l, idx, nil, pay.MaxLinks)
	if err != nil {
		return nil, err
	}
	var out []pay.Offer
	for _, r := range rows {
		if o, ok := pay.OfferOf(r); ok {
			out = append(out, o)
		}
	}
	return out, nil
}

// liveTree is the tree the live site serves, or "" before anything is.
func liveTree(s *store.Store) (string, error) {
	cid := s.GetRef(site.RefLive)
	if cid == "" {
		return "", nil
	}
	c, err := s.GetCommit(cid)
	if err != nil {
		return "", err
	}
	return c.Tree, nil
}

// paySyncMu keeps one process from syncing twice at once; across
// processes, the provider's idempotency keys make the same link once.
var paySyncMu sync.Mutex

// syncPay brings the links into line with the live catalogue, and records
// how that went. It does nothing when payments are off.
func syncPay(root string, caller *Caller) (made, retired []pay.Link, err error) {
	paySyncMu.Lock()
	defer paySyncMu.Unlock()
	st, err := loadPayState(root)
	if err != nil || st.Provider == "" {
		return nil, nil, err
	}
	fail := func(err error) ([]pay.Link, []pay.Link, error) {
		st.Problem = err.Error()
		_ = savePayState(root, st)
		record(root, caller.auditRecord("pay.synced", "/", audit.Failure, map[string]string{"problem": clip(err.Error(), 300)}))
		return made, retired, err
	}
	offers, err := liveOffers(root)
	if err != nil {
		return fail(err)
	}
	prov, err := payProvider(root, st.Provider)
	if err != nil {
		return fail(err)
	}
	book, err := loadPayBook(root)
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	made, retired, err = pay.Sync(ctx, prov, book, offers, st.Options, time.Now())
	// The book is saved whatever happened: a link that was made is a link
	// that exists, and forgetting it would make it again.
	if serr := saveJSON(payBookPath(root), book); serr != nil && err == nil {
		err = serr
	}
	if err != nil {
		return fail(err)
	}
	st.Synced, st.Problem = time.Now().UTC(), ""
	if err := savePayState(root, st); err != nil {
		return made, retired, err
	}
	record(root, caller.auditRecord("pay.synced", "/", audit.Success, map[string]string{
		"made": strconv.Itoa(len(made)), "retired": strconv.Itoa(len(retired)), "offers": strconv.Itoa(len(offers))}))
	return made, retired, nil
}

// syncPayAfterLive brings the links into line after the live site changed.
// The site already shows no Buy button for a price no link sells, so a
// failure here is said and recorded, and does not undo the publish.
func syncPayAfterLive(root string, caller *Caller) {
	made, retired, err := syncPay(root, caller)
	switch {
	case err != nil:
		w.Human("%spayments: the links were not brought up to date, so a changed price shows no Buy button until they are: %v\n  quilzo pay sync%s\n",
			yellow, err, reset)
	case len(made)+len(retired) > 0:
		w.Human("%spayments: %d new payment link(s), %d retired%s\n", dim, len(made), len(retired), reset)
	}
}

// payReader answers the site's question, where a Buy button goes and what
// it charges, from the book on disk: looked at once a second at most, and
// read again only when it changed.
type payReader struct {
	root    string
	mu      sync.Mutex
	checked time.Time
	seen    [2]time.Time
	on      bool
	book    *pay.Book
}

func (r *payReader) Buy(row map[string]any) (string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	if !r.on {
		return "", ""
	}
	return r.book.Buy(row)
}

// Tag names the links as they stand, for a page's ETag; "" while nothing
// is for sale, so a site without payments keeps the tags it had.
func (r *payReader) Tag() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	if !r.on {
		return ""
	}
	return fmt.Sprintf("p%x%x", r.seen[0].UnixNano(), r.seen[1].UnixNano())
}

// refresh reads the state and the book again when they changed, looking at
// most once a second. Called with mu held.
func (r *payReader) refresh() {
	if now := time.Now(); r.book == nil || now.Sub(r.checked) >= time.Second {
		r.checked = now
		var mods [2]time.Time
		for i, p := range []string{payStatePath(r.root), payBookPath(r.root)} {
			if fi, err := os.Stat(p); err == nil {
				mods[i] = fi.ModTime()
			}
		}
		if mods != r.seen || r.book == nil {
			st, _ := loadPayState(r.root)
			book, err := loadPayBook(r.root)
			if err != nil {
				book = &pay.Book{}
			}
			r.on, r.book, r.seen = st.Provider != "", book, mods
		}
	}
}

// cmdPay is `quilzo pay [status] | enable stripe | disable | sync | orders`.
func cmdPay(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	caller := resolveCaller(root, flagToken)
	switch args[0] {
	case "status":
		return payStatus(root)
	case "enable":
		return payEnable(root, args[1:], caller)
	case "disable":
		return payDisable(root, caller)
	case "sync":
		made, retired, err := syncPay(root, caller)
		if err != nil {
			return err
		}
		if st, _ := loadPayState(root); st.Provider == "" {
			return errors.New("payments are off; quilzo pay enable stripe turns them on")
		}
		if w.JSON(map[string]any{"made": made, "retired": retired}) {
			return nil
		}
		for _, l := range made {
			w.Human("  %snew%s  %s at %s  %s\n", green, reset, l.Title, l.Price(), l.URL)
		}
		for _, l := range retired {
			w.Human("  %sretired%s  %s at %s\n", dim, reset, l.Title, l.Price())
		}
		w.Human("the payment links match the live catalogue\n")
		return nil
	case "orders":
		return payOrders(root, args[1:], caller)
	}
	return fmt.Errorf("unknown pay command %q; try status, enable, disable, sync or orders", args[0])
}

func payStatus(root string) error {
	st, err := loadPayState(root)
	if err != nil {
		return err
	}
	book, err := loadPayBook(root)
	if err != nil {
		return err
	}
	offers, oerr := liveOffers(root)
	missing, stale := book.Plan(offers)
	live := 0
	for _, l := range book.Links {
		if l.Live() {
			live++
		}
	}
	_, kerr := readSecret(root, paySecret)
	out := map[string]any{"provider": st.Provider, "options": st.Options, "by": st.By, "at": st.At,
		"synced": st.Synced, "problem": st.Problem, "offers": len(offers), "live_links": live,
		"to_make": len(missing), "to_retire": len(stale), "key": kerr == nil}
	if oerr != nil {
		out["catalogue"] = oerr.Error()
	}
	if w.JSON(out) {
		return nil
	}
	if st.Provider == "" {
		w.Human("payments are off\n")
	} else {
		w.Human("payments through %s, turned on by %s on %s\n", st.Provider, strings.Join(st.By, " and "), st.At.Format("2 Jan 2006"))
	}
	if kerr != nil {
		w.Human("  %sno key: quilzo secret set stripe < key.txt (a restricted key: write Prices, Products and Payment Links, read Checkout Sessions)%s\n", yellow, reset)
	}
	if oerr != nil {
		w.Human("  %s%v%s\n", yellow, oerr, reset)
	} else {
		w.Human("  %d product(s) for sale, %d payment link(s) selling", len(offers), live)
		if st.Provider != "" && len(missing)+len(stale) > 0 {
			w.Human(", %d to make and %d to retire: quilzo pay sync", len(missing), len(stale))
		}
		w.Human("\n")
	}
	if st.Provider != "" && st.Problem != "" {
		w.Human("  %sthe last sync stopped: %s%s\n", yellow, st.Problem, reset)
	}
	return nil
}

// payEnable is `quilzo pay enable stripe [--ship-to GB,IE] [--done "…"]`,
// which waits for a second administrator.
func payEnable(root string, args []string, caller *Caller) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("pay enable", flag.ContinueOnError)
	shipTo := fs.String("ship-to", "", "countries to deliver to, as ISO codes (GB,IE); none asks for no address")
	done := fs.String("done", "", "what the checkout says once somebody has paid")
	why := fs.String("reason", "", "why, for the record")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo pay enable stripe [--ship-to GB,IE] [--done \"…\"]")
	}
	ch := dual.PayChange{Provider: pos[0], Done: strings.TrimSpace(*done)}
	for _, c := range strings.Split(*shipTo, ",") {
		if c = strings.ToUpper(strings.TrimSpace(c)); c != "" {
			ch.ShipTo = append(ch.ShipTo, c)
		}
	}
	on, err := requestPay(root, ch, *why, caller)
	if err != nil || !on {
		return err
	}
	w.Human("payments are on, through %s\n", ch.Provider)
	syncPayAfterLive(root, caller)
	return nil
}

// requestPay asks for payments to be turned on, and turns them on when the
// caller is the only administrator; it reports whether they are on now.
func requestPay(root string, ch dual.PayChange, why string, caller *Caller) (bool, error) {
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return false, err
	}
	if ch.Provider != pay.ProviderStripe {
		return false, fmt.Errorf("%q is not a provider this sells through; stripe is", ch.Provider)
	}
	if err := (pay.Options{ShipTo: ch.ShipTo, Done: ch.Done}).Validate(); err != nil {
		return false, err
	}
	// Checked before anybody is asked to approve something that cannot work.
	if _, err := payProvider(root, ch.Provider); err != nil {
		return false, err
	}
	if _, err := liveOffers(root); err != nil {
		return false, err
	}
	what := "take payments through Stripe's hosted checkout"
	if len(ch.ShipTo) > 0 {
		what += ", delivering to " + strings.Join(ch.ShipTo, ", ")
	}
	apply, err := proposeSecond(root, caller, dual.Pay, what, ch, why)
	if err != nil || !apply {
		return false, err
	}
	return true, applyPay(root, ch, []string{caller.Name}, caller)
}

// applyPay turns payments on, as approved. The links are made by whoever
// called it, which says how that went.
func applyPay(root string, ch dual.PayChange, by []string, caller *Caller) error {
	st, err := loadPayState(root)
	if err != nil {
		return err
	}
	st.Provider, st.Options, st.By, st.At = ch.Provider, pay.Options{ShipTo: ch.ShipTo, Done: ch.Done}, by, time.Now().UTC()
	if err := savePayState(root, st); err != nil {
		return err
	}
	return recordE(root, caller.auditRecord("pay.enabled", "/", audit.Success, map[string]string{
		"provider": ch.Provider, "ship_to": strings.Join(ch.ShipTo, ",")}))
}

// payPending reports whether a request to turn payments on is waiting.
func payPending(root string) bool {
	pend, err := dualStore(root).Pending(time.Now())
	if err != nil {
		return false
	}
	for _, r := range pend {
		if r.Kind == dual.Pay {
			return true
		}
	}
	return false
}

// payDisable turns payments off at once, and retires every link it can.
func payDisable(root string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	st, err := loadPayState(root)
	if err != nil {
		return err
	}
	if st.Provider == "" {
		w.Human("payments are already off\n")
		return nil
	}
	provider := st.Provider
	st.Provider, st.Problem = "", ""
	if err := savePayState(root, st); err != nil {
		return err
	}
	// The buttons are gone now; the links at the provider go next, so a link
	// somebody copied stops selling too.
	retired, problem := 0, ""
	book, err := loadPayBook(root)
	if err != nil {
		return err
	}
	if _, stale := book.Plan(nil); len(stale) > 0 {
		if prov, perr := payProvider(root, provider); perr == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			_, gone, serr := pay.Sync(ctx, prov, book, nil, pay.Options{}, time.Now())
			cancel()
			retired = len(gone)
			if serr != nil {
				problem = serr.Error()
			}
			if err := saveJSON(payBookPath(root), book); err != nil {
				return err
			}
		} else {
			problem = perr.Error()
		}
	}
	if err := recordE(root, caller.auditRecord("pay.disabled", "/", audit.Success, map[string]string{
		"provider": provider, "retired": strconv.Itoa(retired)})); err != nil {
		return err
	}
	w.Human("payments are off; %d payment link(s) retired at %s\n", retired, provider)
	if problem != "" {
		w.Human("  %ssome links could not be retired, so retire them in the provider's dashboard: %s%s\n", yellow, problem, reset)
	}
	return nil
}

// payOrders is `quilzo pay orders [--limit N]`: the latest completed
// checkouts, read from the provider and not kept.
func payOrders(root string, args []string, caller *Caller) error {
	fs := flag.NewFlagSet("pay orders", flag.ContinueOnError)
	limit := fs.Int("limit", 25, "how many, newest first (at most 100)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	orders, err := readOrders(root, *limit, caller)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"orders": orders}) {
		return nil
	}
	if len(orders) == 0 {
		w.Human("no completed checkouts yet\n")
		return nil
	}
	for _, o := range orders {
		paid := "paid"
		if !o.Paid {
			paid = "not paid"
		}
		w.Human("%s  %-14s %-8s %s  %s <%s>\n", o.At.Format("2 Jan 15:04"), o.Total(), paid, o.Offer, o.Name, o.Email)
		if o.Ship != "" {
			w.Human("    deliver to %s\n", o.Ship)
		}
	}
	return nil
}

// readOrders reads the latest orders from the provider, names what each
// sold from the book, and records that somebody looked, never what they saw.
func readOrders(root string, limit int, caller *Caller) ([]pay.Order, error) {
	st, err := loadPayState(root)
	if err != nil {
		return nil, err
	}
	if st.Provider == "" {
		return nil, errors.New("payments are off; quilzo pay enable stripe turns them on")
	}
	prov, err := payProvider(root, st.Provider)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	orders, err := prov.Orders(ctx, limit)
	if err != nil {
		return nil, err
	}
	book, err := loadPayBook(root)
	if err != nil {
		return nil, err
	}
	for i := range orders {
		if l, ok := book.Named(orders[i].Link); ok {
			orders[i].Offer = l.ID
		}
	}
	record(root, caller.auditRecord("pay.orders.read", "/", audit.Success, map[string]string{"count": strconv.Itoa(len(orders))}))
	return orders, nil
}

// payHooks are the Payments screen's.
func payHooks(root string, signedIn func(admin.Actor) *Caller) *admin.PayHooks {
	return &admin.PayHooks{
		Status: func() (admin.PayStatus, error) {
			st, err := loadPayState(root)
			if err != nil {
				return admin.PayStatus{}, err
			}
			out := admin.PayStatus{Provider: st.Provider, Options: st.Options, By: st.By, At: st.At,
				Synced: st.Synced, Problem: st.Problem, Waiting: payPending(root)}
			if key, kerr := readSecret(root, paySecret); kerr == nil && pay.ValidStripeKey(key) {
				out.Key, out.LiveKey = true, (&pay.Stripe{Key: key}).Live()
			}
			book, err := loadPayBook(root)
			if err != nil {
				return out, err
			}
			offers, oerr := liveOffers(root)
			if oerr != nil {
				out.Catalogue = oerr.Error()
			}
			missing, stale := book.Plan(offers)
			out.Offers, out.ToMake, out.ToRetire = len(offers), len(missing), len(stale)
			for _, l := range book.Links {
				if l.Live() {
					out.Live++
				}
			}
			return out, nil
		},
		Enable: func(shipTo []string, done string, by admin.Actor) (bool, error) {
			caller := signedIn(by)
			on, err := requestPay(root, dual.PayChange{Provider: pay.ProviderStripe, ShipTo: shipTo, Done: done}, "", caller)
			if err == nil && on {
				_, _, err = syncPay(root, caller)
			}
			return on, err
		},
		Disable: func(by admin.Actor) error { return payDisable(root, signedIn(by)) },
		Sync: func(by admin.Actor) (int, int, error) {
			caller := signedIn(by)
			if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
				return 0, 0, err
			}
			if st, _ := loadPayState(root); st.Provider == "" {
				return 0, 0, errors.New("payments are off")
			}
			made, retired, err := syncPay(root, caller)
			return len(made), len(retired), err
		},
		Orders: func(limit int, by admin.Actor) ([]pay.Order, error) {
			caller := signedIn(by)
			if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
				return nil, err
			}
			return readOrders(root, limit, caller)
		},
	}
}
