// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/commerce"
	"github.com/quilzo/quilzo/internal/out"
)

// cmdCommerce is the operator's side of the shop: making the key that signs
// checkouts, seeing what was ordered, and checking the configuration the
// site server will refuse to start without.
func cmdCommerce(root string, args []string) error {
	fs := flag.NewFlagSet("commerce", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmd := ""
	if fs.NArg() > 0 {
		cmd = fs.Arg(0)
	}
	caller := resolveCaller(root, flagToken)
	switch cmd {
	case "keygen":
		return commerceKeygen(root, caller)
	case "orders":
		return commerceOrders(root, w.Mode == out.JSON)
	case "status":
		return commerceStatus(root)
	default:
		fmt.Fprintln(fs.Output(),
			"quilzo commerce keygen | orders | status")
		fmt.Fprintln(fs.Output(),
			"  keygen   make the ECDSA key that signs this shop's checkouts")
		fmt.Fprintln(fs.Output(),
			"  orders   the orders agents have placed, newest first")
		fmt.Fprintln(fs.Output(),
			"  status   whether the UCP surface is configured, and what it is missing")
		if cmd != "" {
			return fmt.Errorf("unknown commerce command %q", cmd)
		}
		return nil
	}
}

// commerceKeygen makes the merchant key.
//
// It does not overwrite: a second run with a key already present is almost
// certainly an accident, and the accident it would be is every outstanding
// checkout becoming unverifiable at a stroke.
func commerceKeygen(root string, caller *Caller) error {
	path := filepath.Join(root, "commerce", "merchant.json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf(
			"%s already exists. A second key would orphan every checkout "+
				"signed by the first; move the old key away first if you mean "+
				"to replace it", path)
	}
	key, err := commerce.GenerateMerchantKey()
	if err != nil {
		return err
	}
	if err := key.Save(path); err != nil {
		return err
	}
	jwk, _ := json.Marshal(key.PublicJWK())
	fmt.Printf("the merchant key is %s\nits public half, for the UCP "+
		"discovery document, is served from there automatically:\n%s\n",
		path, jwk)
	// Making this key is the act that decides whose checkout signatures
	// count, which is the shape of a grant even though it grants no access:
	// an audit reader wants to know when it happened and who did it.
	record(root, caller.auditRecord("commerce.keygen",
		"/commerce/merchant.json", audit.Success,
		map[string]string{"kid": key.KeyID}))
	return nil
}

// commerceOrders lists what has been ordered.
func commerceOrders(root string, asJSON bool) error {
	data, err := os.ReadFile(commerce.OrdersPath(root))
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("no orders yet")
			return nil
		}
		return err
	}
	var f struct {
		Orders []commerce.Order `json:"orders"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("%s is not an order book: %w", commerce.OrdersPath(root), err)
	}
	if len(f.Orders) == 0 {
		fmt.Println("no orders yet")
		return nil
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(f.Orders)
	}
	for i := len(f.Orders) - 1; i >= 0; i-- {
		o := f.Orders[i]
		mandates := "no mandate presented"
		if o.CheckoutM != nil {
			mandates = o.CheckoutM.Vct
		}
		if o.PaymentM != nil {
			mandates += ", " + o.PaymentM.Vct
		}
		fmt.Printf("%s  %s by %s  %d %s  %d line(s)  %s\n",
			o.At.Local().Format(time.RFC3339), o.ID, o.Agent, o.Total, o.Currency,
			len(o.Lines), mandates)
		for _, l := range o.Lines {
			fmt.Printf("    %dx %s (%s)\n", l.Quantity, l.Title, l.ItemID)
		}
	}
	return nil
}

// commerceStatus says what the site server will decide about the commerce
// surface, before it decides it on a restart.
func commerceStatus(root string) error {
	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	on := cfg.Bool("commerce.on")
	say := func(what string, ok bool, missing string) {
		mark, note := "yes", ""
		if !ok {
			mark, note = "no", " — "+missing
		}
		fmt.Printf("%-34s %s%s\n", what, mark, note)
	}
	say("commerce.on", on, "the UCP surface stays off")
	if !on {
		return nil
	}
	_, err = commerce.LoadMerchantKey(filepath.Join(root, "commerce", "merchant.json"))
	say("merchant key", err == nil, "run `quilzo commerce keygen`")

	payee := strings.TrimSpace(cfg.Raw("commerce.payee"))
	name, website := "", payee
	if i := strings.Index(payee, "|"); i >= 0 {
		name, website = strings.TrimSpace(payee[:i]), strings.TrimSpace(payee[i+1:])
	}
	say("payee (commerce.payee)", name != "" && strings.HasPrefix(website, "https://"),
		"set name|https://website as a payment mandate must name it")

	nAgents := 0
	for _, entry := range strings.Split(cfg.Raw("commerce.agents"), ",") {
		if strings.TrimSpace(entry) != "" {
			nAgents++
		}
	}
	fmt.Printf("%-34s %d\n", "agents configured", nAgents)

	nIssuers := 0
	for _, entry := range strings.Split(cfg.Raw("commerce.issuers"), ",") {
		if strings.TrimSpace(entry) != "" {
			nIssuers++
		}
	}
	fmt.Printf("%-34s %d\n", "mandate issuers configured", nIssuers)
	if nIssuers == 0 {
		fmt.Println("no issuer is configured, so no payment mandate will " +
			"verify; orders will record none_presented")
	}
	return nil
}
