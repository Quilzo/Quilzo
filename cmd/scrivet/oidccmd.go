package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/fetch"
	"github.com/rsh1k/scrivet/internal/oidc"
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
	// Claim is which claim becomes the scrivet principal. Defaults to email,
	// because that is what an access policy is written in terms of — but sub is
	// the stable one, and an operator whose provider recycles addresses should
	// say so.
	Claim string `json:"claim"`
	// RequireVerifiedEmail refuses a sign-in whose email the provider has not
	// verified. On by default: an unverified address is a claim by whoever
	// signed up, and mapping it to a principal lets them choose who to be.
	RequireVerifiedEmail bool `json:"require_verified_email"`
}

const oidcSecretEnv = "SCRIVET_OIDC_SECRET"

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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *issuer == "" || *clientID == "" || *redirect == "" {
		return fmt.Errorf(
			"usage: scrivet oidc configure --issuer https://idp.example \\\n" +
				"    --client-id ... --redirect-uri https://cms.example/auth/callback")
	}
	if _, err := fetch.ValidateURL(*issuer); err != nil {
		return fmt.Errorf("the issuer URL is not usable: %w", err)
	}
	switch *claim {
	case "email", "sub":
	default:
		return fmt.Errorf("--claim must be email or sub; %q is not a claim this "+
			"maps to a principal", *claim)
	}

	cfg := &oidcConfig{
		Issuer: strings.TrimSuffix(*issuer, "/"), ClientID: *clientID,
		RedirectURI: *redirect, Claim: *claim,
		RequireVerifiedEmail: !*allowUnverified,
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
	w.Human("\n  %sscrivet oidc check — talk to the provider and report what it "+
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
		w.Human("  %sscrivet oidc configure --issuer ... --client-id ...%s\n",
			dim, reset)
		w.Human("\n  %sSAML is not implemented, deliberately. Go's encoding/xml "+
			"does not\n  preserve semantics across a parse and re-serialise, "+
			"which is how XML\n  Signature Wrapping gets in — both major Go SAML "+
			"libraries shipped it.\n  Point a provider that speaks both at this "+
			"instead; that moves the XML\n  parsing to software whose full-time "+
			"job it is.%s\n", dim, reset)
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
	p, err := oidc.Discover(ctx, target, fetch.New())
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
