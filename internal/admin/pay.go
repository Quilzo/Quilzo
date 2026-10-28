// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/pay"
)

// Payments: selling what the catalogue lists through the provider's own
// checkout (internal/pay). Two administrators turn it on; the links follow
// what is published; orders are read from the provider when somebody asks,
// shown, and not kept.

// PayStatus is what the screen says about payments.
type PayStatus struct {
	// Provider is who takes the money; empty is off.
	Provider string
	Options  pay.Options
	By       []string
	At       time.Time
	// Key says the provider's key is set, and LiveKey that it takes real
	// money rather than test payments.
	Key, LiveKey bool
	// Catalogue is why nothing can be sold, when that is so.
	Catalogue string
	// Offers are the products for sale; Live the links selling them; ToMake
	// and ToRetire what a sync would do.
	Offers, Live, ToMake, ToRetire int
	Synced                         time.Time
	Problem                        string
	// Waiting is a request to turn payments on that a second administrator
	// has not decided yet.
	Waiting bool
}

// PayHooks are what the screen asks of the payments.
type PayHooks struct {
	Status func() (PayStatus, error)
	// Enable asks for payments through Stripe; it reports whether they are
	// on now, or wait for a second administrator.
	Enable  func(shipTo []string, done string, by Actor) (on bool, err error)
	Disable func(by Actor) error
	Sync    func(by Actor) (made, retired int, err error)
	Orders  func(limit int, by Actor) ([]pay.Order, error)
}

func (s *Server) handlePay(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	// Orders name people and where they live: never kept by a browser.
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{"Title": "Payments", "Nav": "pay", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Pay == nil {
		data["Unavailable"] = "This build was started without payments wired in."
		s.render(w, r, "pay.html", data)
		return
	}
	st, err := s.Pay.Status()
	if err != nil {
		data["Error"] = err.Error()
	}
	data["Status"] = st
	if st.Provider != "" && r.URL.Query().Get("orders") == "1" {
		orders, oerr := s.Pay.Orders(25, p.actor())
		if oerr != nil {
			data["OrdersError"] = oerr.Error()
		}
		data["Orders"], data["ShowOrders"] = orders, true
	}
	s.render(w, r, "pay.html", data)
}

func (s *Server) handlePayAct(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	if s.Pay == nil {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	back := func(msg string, err error) {
		v := "m=" + url.QueryEscape(msg)
		if err != nil {
			v = "e=" + url.QueryEscape(err.Error())
		}
		http.Redirect(w, r, "/pay?"+v, http.StatusSeeOther)
	}
	switch r.FormValue("do") {
	case "enable":
		var shipTo []string
		for _, c := range strings.Split(r.FormValue("ship_to"), ",") {
			if c = strings.ToUpper(strings.TrimSpace(c)); c != "" {
				shipTo = append(shipTo, c)
			}
		}
		on, err := s.Pay.Enable(shipTo, strings.TrimSpace(r.FormValue("done")), p.actor())
		switch {
		case err != nil:
			back("", err)
		case on:
			back("Payments are on. Every published price now has a Buy button.", nil)
		default:
			back("Turning payments on waits for a second administrator, in Approvals.", nil)
		}
	case "disable":
		if err := s.Pay.Disable(p.actor()); err != nil {
			back("", err)
			return
		}
		back("Payments are off, and the payment links are retired.", nil)
	case "sync":
		made, retired, err := s.Pay.Sync(p.actor())
		if err != nil {
			back("", err)
			return
		}
		back(fmt.Sprintf("The payment links match the live catalogue: %d new, %d retired.", made, retired), nil)
	default:
		back("", errors.New("say what to do"))
	}
}
