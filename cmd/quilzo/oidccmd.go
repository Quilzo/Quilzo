// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/oidc"
)

func oidcPath(root string) string { return filepath.Join(root, "oidc.json") }

// oidcConfig is what an operator sets up.
//
// The client secret is deliberately not here. It comes from the environment,
// for the same reason the encryption key does: a credential stored beside the
// data it protects is a credential that travels with every backup.
type oidcConfig struct {
	Issuer      string `json:"issuer"`
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	// Claim is which claim becomes the quilzo principal. Defaults to email,
	// because that is what an access policy is written in terms of — but sub is
	// the stable one, and an operator whose provider recycles addresses should
	// say so.
	Claim string `json:"claim"`
	// RequireVerifiedEmail refuses a sign-in whose email the provider has not
	// verified. On by default: an unverified address is a claim by whoever
	// signed up, and mapping it to a principal lets them choose who to be.
	RequireVerifiedEmail bool `json:"require_verified_email"`
	// Provider is google or microsoft when configured from a preset, which
	// switches on that provider's own check: hd for Google, tid and the
	// sign-in name for Microsoft.
	Provider string `json:"provider,omitempty"`
	// Domains are the organisation's domains: the Workspace domains a
	// Google token must be managed by, or the domains a Microsoft sign-in
	// name must be in.
	Domains []string `json:"domains,omitempty"`
	// Tenant is the Entra tenant's identifier.
	Tenant string `json:"tenant,omitempty"`
}

// providerLabel is what the sign-in button calls a preset.
func (c *oidcConfig) providerLabel() string {
	switch c.Provider {
	case "google":
		return "Google"
	case "microsoft":
		return "Microsoft"
	}
	return ""
}

const oidcSecretEnv = "QUILZO_OIDC_SECRET"

var (
	reDomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	reTenant = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

func loadOIDC(root string) (*oidcConfig, error) {
	c := &oidcConfig{}
	if err := loadJSON(oidcPath(root), c); err != nil {
		return nil, err
	}
	if c.Issuer == "" {
		return nil, nil
	}
	if c.Claim == "" {
		c.Claim = "email"
	}
	return c, nil
}

func cmdOIDC(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		return oidcStatus(root)
	case "configure":
		return oidcConfigure(root, args[1:])
	case "check":
		return oidcCheck(root, args[1:])
	default:
		return fmt.Errorf("unknown oidc command %q; try status, configure or check",
			args[0])
	}
}

func oidcConfigure(root string, args []string) error {
	fs := flag.NewFlagSet("configure", flag.ContinueOnError)
	issuer := fs.String("issuer", "", "the provider's issuer URL")
	clientID := fs.String("client-id", "", "this application's client id")
	redirect := fs.String("redirect-uri", "", "where the provider sends the browser back")
	claim := fs.String("claim", "email", "which claim becomes the principal: email or sub")
	allowUnverified := fs.Bool("allow-unverified-email", false,
		"accept an email the provider has not verified")
	provider := fs.String("provider", "",
		"google or microsoft, which sets the issuer and that provider's checks")
	domains := fs.String("domain", "",
		"the organisation's domain(s), comma-separated")
	tenant := fs.String("tenant", "", "the Microsoft Entra tenant ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var doms []string
	for _, d := range strings.Split(*domains, ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			if !reDomain.MatchString(d) {
				return fmt.Errorf("%q is not a domain", d)
			}
			doms = append(doms, d)
		}
	}
	switch *provider {
	case "":
	case "google":
		// Google's issuer is one for every account in the world, so the
		// domain is what makes a sign-in this organisation's.
		if len(doms) == 0 {
			return fmt.Errorf("--provider google needs --domain: the " +
				"Workspace domain whose accounts may sign in. Without it " +
				"any Google account carrying a matching address would do, " +
				"including a personal one somebody kept after leaving")
		}
		*issuer, *claim = "https://accounts.google.com", "email"
		*allowUnverified = false
	case "microsoft":
		t := strings.ToLower(strings.TrimSpace(*tenant))
		if !reTenant.MatchString(t) {
			return fmt.Errorf("--provider microsoft needs --tenant, the " +
				"tenant's ID (a GUID from the Entra admin centre). Not common, " +
				"organizations or consumers: those accept every tenant's " +
				"accounts, and not a domain name, whose issuer does not match")
		}
		*tenant = t
		*issuer = "https://login.microsoftonline.com/" + t + "/v2.0"
		*claim = "preferred_username"
	default:
		return fmt.Errorf("--provider is google or microsoft; for any other " +
			"provider give --issuer")
	}
	if *issuer == "" || *clientID == "" || *redirect == "" {
		return fmt.Errorf(
			"usage: quilzo oidc configure --issuer https://idp.example \\\n" +
				"    --client-id ... --redirect-uri https://cms.example/auth/callback")
	}
	if _, err := fetch.ValidateURL(*issuer); err != nil {
		return fmt.Errorf("the issuer URL is not usable: %w", err)
	}
	switch *claim {
	case "email", "sub", "preferred_username":
	default:
		return fmt.Errorf("--claim must be email or sub; %q is not a claim this "+
			"maps to a principal", *claim)
	}

	cfg := &oidcConfig{
		Issuer: strings.TrimSuffix(*issuer, "/"), ClientID: *clientID,
		RedirectURI: *redirect, Claim: *claim,
		RequireVerifiedEmail: !*allowUnverified,
		Provider:             *provider, Domains: doms, Tenant: *tenant,
	}
	if err := saveJSON(oidcPath(root), cfg); err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "oidc.configure", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"issuer": cfg.Issuer, "client": cfg.ClientID, "claim": cfg.Claim,
			"provider": cfg.Provider, "domains": strings.Join(cfg.Domains, ","),
		},
	})

	if w.JSON(cfg) {
		return nil
	}
	w.Human("configured %s%s%s\n", bold, cfg.Issuer, reset)
	w.Human("  %sthe client secret is not stored here. Set %s%s\n",
		dim, oidcSecretEnv, reset)
	w.Human("  %sa secret kept beside the data it protects travels with every "+
		"backup%s\n", dim, reset)
	w.Human("\n  %squilzo oidc check — talk to the provider and report what it "+
		"offers%s\n", dim, reset)
	return nil
}

func oidcStatus(root string) error {
	cfg, err := loadOIDC(root)
	if err != nil {
		return err
	}
	if cfg == nil {
		if w.JSON(map[string]any{"configured": false}) {
			return nil
		}
		w.Human("no identity provider is configured\n")
		w.Human("  %squilzo oidc configure --issuer ... --client-id ...%s\n",
			dim, reset)
		w.Human("\n  %sSAML identity providers are set up with quilzo saml add.%s\n", dim, reset)
		return nil
	}
	if w.JSON(map[string]any{
		"configured": true, "issuer": cfg.Issuer, "client_id": cfg.ClientID,
		"claim": cfg.Claim, "secret_set": secretSet(),
	}) {
		return nil
	}
	w.Human("%s%s%s\n", bold, cfg.Issuer, reset)
	w.Human("  client       %s\n", cfg.ClientID)
	w.Human("  redirect     %s\n", cfg.RedirectURI)
	w.Human("  principal    the %s claim\n", cfg.Claim)
	if cfg.RequireVerifiedEmail && cfg.Claim == "email" {
		w.Human("  %sunverified addresses are refused%s\n", dim, reset)
	}
	if !secretSet() {
		w.Human("  %s%s is not set%s\n", yellow, oidcSecretEnv, reset)
	}
	return nil
}

func secretSet() bool { return os.Getenv(oidcSecretEnv) != "" }

// oidcCheck talks to the provider and reports what was negotiated.
//
// This exists because an identity provider misconfiguration is otherwise
// discovered by a person who cannot log in, at which point the information
// available is "it did not work". Everything here is what the sign-in path
// would do, run deliberately.
func oidcCheck(root string, args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	issuer := fs.String("issuer", "", "check this issuer instead of the configured one")
	if err := fs.Parse(args); err != nil {
		return err
	}

	target := *issuer
	if target == "" {
		cfg, err := loadOIDC(root)
		if err != nil {
			return err
		}
		if cfg == nil {
			return fmt.Errorf("no provider is configured; pass --issuer to check one")
		}
		target = cfg.Issuer
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w.Human("%sdiscovery%s\n", bold, reset)
	p, err := oidc.Discover(ctx, target, fetch.For("sso"))
	if err != nil {
		return errBlocked{err}
	}
	w.Human("  issuer       %s\n", p.Discovery.Issuer)
	w.Human("  authorize    %s\n", p.Discovery.AuthorizationEndpoint)
	w.Human("  token        %s\n", p.Discovery.TokenEndpoint)
	w.Human("  keys         %s\n", p.Discovery.JWKSURI)

	w.Human("\n%salgorithms%s\n", bold, reset)
	w.Human("  provider     %s\n", strings.Join(p.Discovery.SigningAlgs, ", "))
	var agreed []string
	for _, a := range p.Algorithms {
		agreed = append(agreed, string(a))
	}
	w.Human("  agreed       %s%s%s\n", green, strings.Join(agreed, ", "), reset)
	w.Human("  %sa token naming anything outside this list is refused before "+
		"its\n  signature is examined%s\n", dim, reset)

	w.Human("\n%skeys%s\n", bold, reset)
	if err := p.Warm(ctx); err != nil {
		return errBlocked{err}
	}
	w.Human("  %d usable signing key(s)\n", p.KeyCount())

	_ = w.JSON(map[string]any{
		"issuer": p.Discovery.Issuer, "algorithms": agreed,
		"keys": p.KeyCount(),
	})
	w.Human("\n  %severything above is what a sign-in would do, run "+
		"deliberately%s\n", dim, reset)
	return nil
}
