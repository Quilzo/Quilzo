// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/oidc"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/saml"
	"github.com/quilzo/quilzo/internal/ssf"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// Security events from the identity provider (OpenID Shared Signals): the
// stream, as connected from here. What an event does is signalsact.go.
//
// One stream, bound to one way of signing in. The provider's word ends the
// sessions it vouched for and nothing it did not: a stream bound to OIDC
// ends "oidc:" sessions, one bound to saml:okta ends "saml:okta:" ones, and
// a person's passkey session, their long-lived tokens and the apps they
// connected stay theirs unless the provider disables their account
// outright, when it is a suspension like SCIM's.
//
// Connecting a stream is the whole opt-in. There is no rule to write and
// nothing to enable after: what each event does is fixed, and every one of
// them only takes access away, so connecting needs one administrator and
// no second one.

func signalsPath(root string) string { return filepath.Join(root, "signals.json") }

// signalsSecretEnv is where the client secret for the transmitter's stream
// API is read from, by this command and by the server's daily
// verification. Not stored, for the same reason the OIDC client secret is
// not: a credential kept beside the data travels with every backup.
const signalsSecretEnv = "QUILZO_SIGNALS_SECRET"

// signalsBy marks what the receiver did: the principal of its audit
// records, and the GrantedBy of the only deny it ever adds or lifts.
const signalsBy = "signals"

// signalsPushPrefix starts every push secret. Not qz_, which is this
// store's own token prefix: a push secret presented anywhere else here
// must not count as somebody guessing a token.
const signalsPushPrefix = "qzsig_"

// signalsConfig is signals.json: the stream, what it has done, and what
// stops a replay from undoing it. Digests only, never a secret.
type signalsConfig struct {
	// Provider is the sign-in this stream speaks for, "oidc" or
	// "saml:NAME": its sessions are the only ones an event ends, and its
	// rule for naming people the only one a subject is read by. Empty is
	// no stream.
	Provider string `json:"provider,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	Audience string `json:"audience,omitempty"`
	JWKS     string `json:"jwks_uri,omitempty"`
	// Manual is a stream made in the transmitter's own console, with no
	// stream API to ask anything of.
	Manual    bool   `json:"manual,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenURL  string `json:"token_endpoint,omitempty"`
	ConfigURL string `json:"configuration_endpoint,omitempty"`
	StatusURL string `json:"status_endpoint,omitempty"`
	VerifyURL string `json:"verification_endpoint,omitempty"`
	Stream    string `json:"stream_id,omitempty"`
	// Push is the digest of the bearer the transmitter pushes with.
	Push string `json:"push_digest,omitempty"`
	// State is the digest of the state the last verification was asked
	// with; Asked when, and Verified when one was last answered.
	State    string    `json:"state_digest,omitempty"`
	Asked    time.Time `json:"asked,omitzero"`
	Verified time.Time `json:"verified,omitzero"`
	// AskFailed is why the last request for a verification failed, until
	// one succeeds. Kept so the status and the Sign-ins screen can say it:
	// a server started without the client secret in its environment asked
	// and failed every day, and all either showed was "last asked", which
	// read as asked and not yet answered.
	AskFailed   string    `json:"ask_failed,omitempty"`
	Status      string    `json:"status,omitempty"`
	Connected   time.Time `json:"connected,omitzero"`
	ConnectedBy string    `json:"connected_by,omitempty"`

	Counts signalsCounts `json:"counts"`
	Hour   signalsHour   `json:"hour"`
	// LastActed is, by the digest of somebody's name, when the last event
	// acted on for them was issued. Kept when the stream is turned off and
	// across restarts, so an older account-enabled cannot lift a newer
	// suspension by arriving later or again.
	LastActed map[string]int64 `json:"last_acted,omitempty"`
	// LastDisabled and LastEnabled are, by the same digest, when the last
	// account-disabled or account-purged, and the last account-enabled,
	// acted on for them were issued. Kept the same way, so an older
	// disable cannot suspend again somebody the provider enabled since:
	// the transmitter's retry of a disable that failed here once arrived
	// after the enable it sent next, and the enable was undone.
	LastDisabled map[string]int64 `json:"last_disabled,omitempty"`
	LastEnabled  map[string]int64 `json:"last_enabled,omitempty"`
}

// keep carries over what the receiver remembers about whom it acted on,
// from the stream that was to the one that is, or to none: what stops an
// old event undoing a newer one.
func (c *signalsConfig) keep(from *signalsConfig) {
	c.LastActed, c.LastDisabled, c.LastEnabled = from.LastActed, from.LastDisabled, from.LastEnabled
}

// signalsCounts are what the stream has sent and what came of it.
type signalsCounts struct {
	Received  int       `json:"received"`
	Acted     int       `json:"acted"`
	Unmatched int       `json:"unmatched"`
	Refused   int       `json:"refused"`
	Capped    int       `json:"capped"`
	LastAt    time.Time `json:"last_at,omitzero"`
	LastType  string    `json:"last_type,omitempty"`
	// Unnoted are refusals since RefusedNoted, when the last summary of
	// them went to the audit log.
	Unnoted      int       `json:"unnoted,omitempty"`
	RefusedNoted time.Time `json:"refused_noted,omitzero"`
}

// signalsHour is the hour the cap counts in: the digests of the people
// acted on in it, and whether its being reached was recorded.
type signalsHour struct {
	Start time.Time `json:"start,omitzero"`
	Who   []string  `json:"who,omitempty"`
	Noted bool      `json:"noted,omitempty"`
}

// connected reports whether a stream is connected.
func (c *signalsConfig) connected() bool { return c != nil && c.Provider != "" }

func loadSignals(root string) (*signalsConfig, error) {
	c := &signalsConfig{}
	return c, loadJSON(signalsPath(root), c)
}

func updateSignals(root string, change func(*signalsConfig) error) error {
	return atomicfile.Update(signalsPath(root), change)
}

// signalsClient is how this reaches the transmitter: its keys, its
// configuration, its token endpoint and its stream API, through the
// egress purpose "signals". A variable so a test can stand in for the
// transmitter.
var signalsClient = func() ssf.HTTP { return fetch.For("signals") }

// signalsKeyGet reads a key set through signalsClient.
func signalsKeyGet(ctx context.Context, u string) ([]byte, error) {
	res, err := signalsClient().Do(ctx, "GET", u, nil, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}
	if res.Status != 200 {
		return nil, fmt.Errorf("the key set answered %d", res.Status)
	}
	return res.Body, nil
}

// signalsAlgorithms are the ones a stream's tokens may be signed with.
var signalsAlgorithms = []oidc.Algorithm{oidc.RS256, oidc.ES256, oidc.PS256}

// signalsReceivers keeps one verifier per stream, with the key set it has
// read, so a delivery does not fetch the transmitter's keys again.
type signalsReceivers struct {
	mu  sync.Mutex
	key string
	r   *ssf.Receiver
}

func (c *signalsReceivers) get(cfg *signalsConfig) (*ssf.Receiver, error) {
	key := cfg.Issuer + "\x00" + cfg.Audience + "\x00" + cfg.JWKS
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.r != nil && c.key == key {
		return c.r, nil
	}
	ks, err := oidc.NewKeySet(cfg.JWKS, signalsKeyGet)
	if err != nil {
		return nil, err
	}
	c.key, c.r = key, &ssf.Receiver{Issuer: cfg.Issuer, Audience: cfg.Audience, Keys: ks, Algorithms: signalsAlgorithms}
	return c.r, nil
}

// signalsSecret is a new push secret, or state for a verification.
func signalsSecret(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// signalsMatches compares a presented value with a kept digest.
func signalsMatches(presented, digest string) bool {
	return presented != "" && digest != "" &&
		subtle.ConstantTimeCompare([]byte(ssf.Digest(presented)), []byte(digest)) == 1
}

// signalsBase is this admin's address as the bound provider sends people
// back to it, which is where its transmitter can reach it too, and checks
// that the provider is one this store signs people in with.
func signalsBase(root, provider string) (string, error) {
	switch {
	case provider == "oidc":
		oc, err := loadOIDC(root)
		if err != nil {
			return "", err
		}
		if oc == nil {
			return "", errors.New("no OIDC provider is configured, so there are no sessions for its events to end: " +
				"quilzo oidc configure first")
		}
		u, err := url.Parse(oc.RedirectURI)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("the OIDC redirect URI %q is not an address", oc.RedirectURI)
		}
		return u.Scheme + "://" + u.Host, nil
	case strings.HasPrefix(provider, "saml:"):
		sc, err := samlNamed(root, strings.TrimPrefix(provider, "saml:"))
		if err != nil {
			return "", err
		}
		return strings.TrimSuffix(sc.URL, "/"), nil
	}
	return "", fmt.Errorf("--provider is oidc or saml:NAME, the sign-in whose sessions the events end; not %q", provider)
}

// samlNamed is one configured SAML provider.
func samlNamed(root, name string) (*saml.Config, error) {
	all, err := loadSAML(root)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Name == name {
			return &all[i], nil
		}
	}
	return nil, fmt.Errorf("there is no SAML provider %q (quilzo saml list)", name)
}

// signalsUsage names one of --client-id and --jwks as needed, which the
// brackets of the first spelling hid: both looked optional, and connecting
// with neither was refused.
func signalsUsage() error {
	return errors.New("usage: quilzo signals connect --provider oidc|saml:NAME (--client-id ID | --jwks URL) " +
		"[--issuer URL] [--audience A] | status | off")
}

func cmdSignals(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "connect":
		return signalsConnect(root, args[1:])
	case "status":
		return signalsStatus(root)
	case "off":
		return signalsOff(root)
	}
	return signalsUsage()
}

func signalsConnect(root string, args []string) error {
	fs := flag.NewFlagSet("signals connect", flag.ContinueOnError)
	provider := fs.String("provider", "", "the sign-in whose sessions the events end: oidc or saml:NAME")
	issuer := fs.String("issuer", "", "the transmitter's issuer; the OIDC issuer by default")
	audience := fs.String("audience", "", "this receiver as the transmitter names it; the push address by default")
	clientID := fs.String("client-id", "", "the client the transmitter issued for its stream API; the secret is read from "+signalsSecretEnv)
	jwks := fs.String("jwks", "", "the transmitter's key set, for a stream made in its own console")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// A word left over is a flag mistyped or a value given its own place,
	// and parsing stops there: `connect --provider oidc oops --client-id ID`
	// read no client and said so, about the wrong thing.
	if fs.NArg() > 0 {
		return signalsUsage()
	}
	if *provider == "" {
		return errors.New("--provider names the sign-in whose sessions the events end: oidc, or saml:NAME for a " +
			"SAML provider (quilzo saml list)")
	}
	caller := resolveCaller(root, "")
	now := time.Now().UTC()
	cur, err := loadSignals(root)
	if err != nil {
		return err
	}
	if cur.connected() {
		return fmt.Errorf("a stream from %s is connected already; quilzo signals off first", cur.Issuer)
	}
	base, err := signalsBase(root, *provider)
	if err != nil {
		return err
	}
	push := base + admin.SignalsPath
	if _, err := fetch.ValidateURL(push); err != nil {
		return fmt.Errorf("the transmitter pushes to %s, which has to be https and public: %w", push, err)
	}
	iss := strings.TrimSpace(*issuer)
	if iss == "" && *provider == "oidc" {
		oc, _ := loadOIDC(root)
		iss = oc.Issuer
	}
	if iss == "" {
		return errors.New("--issuer is the transmitter's issuer, which a SAML provider does not say")
	}
	if _, err := fetch.ValidateURL(iss); err != nil {
		return fmt.Errorf("the issuer is not usable: %w", err)
	}
	aud := strings.TrimSpace(*audience)
	if aud == "" {
		aud = push
	}
	secret, err := signalsSecret(signalsPushPrefix)
	if err != nil {
		return err
	}
	cfg := signalsConfig{Provider: *provider, Issuer: iss, Audience: aud, Push: ssf.Digest(secret),
		Connected: now, ConnectedBy: caller.Name}

	if *jwks != "" {
		if *clientID != "" {
			return errors.New("--jwks is for a stream made in the transmitter's own console; " +
				"with --client-id the stream is asked for through its API instead, so give one or the other")
		}
		if _, err := fetch.ValidateURL(*jwks); err != nil {
			return fmt.Errorf("the key set is not usable: %w", err)
		}
		cfg.JWKS, cfg.Manual = *jwks, true
		if err := signalsSave(root, cfg); err != nil {
			return err
		}
		if err := recordE(root, caller.auditRecord("signals.connected", "/", audit.Success,
			map[string]string{"issuer": iss, "type": "manual"})); err != nil {
			return err
		}
		if w.JSON(map[string]any{"provider": cfg.Provider, "issuer": iss, "push_url": push, "audience": aud,
			"authorization": "Bearer " + secret, "events": ssf.Requested}) {
			return nil
		}
		w.Human("connected; in %s's console, make a push stream (RFC 8935) with:\n", iss)
		w.Human("  endpoint       %s\n", push)
		w.Human("  audience       %s\n", aud)
		w.Human("  authorization  Bearer %s\n", secret)
		w.Human("  %sthe authorization is shown once and kept here only as a digest%s\n", dim, reset)
		w.Human("  events:\n")
		for _, e := range ssf.Requested {
			w.Human("    %s\n", e)
		}
		w.Human("  %sit cannot be asked to verify, so posture reports it as silent: quilzo signals status%s\n", dim, reset)
		return nil
	}

	if *clientID == "" {
		return errors.New("--client-id is the client the transmitter issued for managing its stream, with the secret in " +
			signalsSecretEnv + "; a transmitter with no stream API is connected with --jwks instead")
	}
	clientSecret := os.Getenv(signalsSecretEnv)
	if clientSecret == "" {
		return fmt.Errorf("%s is not set; it holds the client secret, which is never stored here", signalsSecretEnv)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	h := signalsClient()
	t, err := ssf.Discover(ctx, h, iss)
	if err != nil {
		return err
	}
	// The issuer the transmitter says it is, which Discover has checked is
	// the one asked for, give or take a trailing slash. Its tokens carry
	// this spelling and Verify compares exactly, so keeping the one typed
	// refused every event it sent, verification among them.
	iss = t.Issuer
	cfg.Issuer = iss
	if t.ConfigurationEndpoint == "" {
		return fmt.Errorf("%s publishes no stream API, so the stream has to be made in its own console: "+
			"connect again with --jwks %s", t.Issuer, t.JWKSURI)
	}
	tokenURL, err := ssf.TokenEndpoint(ctx, h, iss)
	if err != nil {
		return err
	}
	access, err := ssf.ClientCredentials(ctx, h, tokenURL, *clientID, clientSecret, []string{"ssf.manage", "ssf.read"})
	if err != nil {
		return err
	}
	s, err := t.CreateStream(ctx, h, access, push, "Bearer "+secret, "Quilzo", ssf.Requested)
	if err != nil {
		return err
	}
	// The audience is the transmitter's to choose; it is what its tokens
	// will carry.
	if auds := s.Audiences(); len(auds) > 0 && !slices.Contains(auds, aud) {
		cfg.Audience = auds[0]
	}
	cfg.JWKS, cfg.ClientID, cfg.TokenURL, cfg.Stream = t.JWKSURI, *clientID, tokenURL, s.ID
	cfg.ConfigURL, cfg.StatusURL, cfg.VerifyURL = t.ConfigurationEndpoint, t.StatusEndpoint, t.VerificationEndpoint
	verr := signalsAskVerification(ctx, h, &cfg, access, now)
	if verr != nil {
		cfg.AskFailed = onOneLine(verr.Error())
	}
	if st, _, err := t.Status(ctx, h, access, s.ID); err == nil {
		cfg.Status = st
	}
	if err := signalsSave(root, cfg); err != nil {
		return err
	}
	if err := recordE(root, caller.auditRecord("signals.connected", "/", audit.Success,
		map[string]string{"issuer": iss, "type": "stream"})); err != nil {
		return err
	}
	// Connected either way; a verification that could not be asked for is
	// a warning, on standard error, which the server's daily request
	// retries. In JSON it is in the document too, since a caller reading
	// only that would otherwise see false and never why.
	doc := map[string]any{"provider": cfg.Provider, "issuer": iss, "stream": s.ID, "push_url": push,
		"events": len(s.EventsDelivered), "verification_asked": verr == nil}
	if verr != nil {
		doc["verification_error"] = cfg.AskFailed
		fmt.Fprintf(w.Err, "  %sverification was not asked for: %s; the server asks again within a day, with the "+
			"client secret in %s in its own environment%s\n", yellow, cfg.AskFailed, signalsSecretEnv, reset)
	}
	if w.JSON(doc) {
		return nil
	}
	w.Human("stream %s made at %s; %d event types will be pushed to %s\n", s.ID, iss, len(s.EventsDelivered), push)
	if verr == nil {
		w.Human("  verification asked for; quilzo signals status shows when it arrives\n")
	}
	return nil
}

// signalsSave writes a newly connected stream, keeping what the receiver
// remembers about whom it acted on.
func signalsSave(root string, cfg signalsConfig) error {
	return updateSignals(root, func(c *signalsConfig) error {
		cfg.keep(c)
		*c = cfg
		return nil
	})
}

// signalsTransmitter is the stream's endpoints, as connecting stored them.
func (c *signalsConfig) transmitter() *ssf.Transmitter {
	return &ssf.Transmitter{Issuer: c.Issuer, JWKSURI: c.JWKS, ConfigurationEndpoint: c.ConfigURL,
		StatusEndpoint: c.StatusURL, VerificationEndpoint: c.VerifyURL}
}

// signalsAccess is an access token for the stream API, with the client
// secret from the environment.
func signalsAccess(ctx context.Context, h ssf.HTTP, c *signalsConfig, scopes ...string) (string, error) {
	secret := os.Getenv(signalsSecretEnv)
	if secret == "" {
		return "", fmt.Errorf("%s is not set in this process's environment", signalsSecretEnv)
	}
	return ssf.ClientCredentials(ctx, h, c.TokenURL, c.ClientID, secret, scopes)
}

// signalsAskVerification asks the transmitter to prove the stream reaches
// here, and keeps the digest of the state it will have to send back.
func signalsAskVerification(ctx context.Context, h ssf.HTTP, c *signalsConfig, access string, now time.Time) error {
	state, err := signalsSecret("")
	if err != nil {
		return err
	}
	if err := c.transmitter().RequestVerification(ctx, h, access, c.Stream, state); err != nil {
		return err
	}
	c.State, c.Asked = ssf.Digest(state), now
	return nil
}

// facts is the stream as the posture rule judges it, so the status, the
// Sign-ins screen and the finding call the same stream silent.
func (c *signalsConfig) facts() posture.SignalsFacts {
	return posture.SignalsFacts{Connected: c.Connected, Verified: c.Verified, Manual: c.Manual}
}

// signalsStatus says what the Sign-ins screen says, in the same words:
// whose sign-ins, whether it has answered a verification and whether it
// has gone silent, why the last request failed, what the identity provider
// says of the stream, the counts, and the last event.
func signalsStatus(root string) error {
	c, err := loadSignals(root)
	if err != nil {
		return err
	}
	if !c.connected() {
		if w.JSON(map[string]any{"connected": false}) {
			return nil
		}
		w.Human("no stream is connected, so a session the identity provider ends, or an account it disables, goes on " +
			"here until it ends by itself\n")
		w.Human("  %squilzo signals connect --provider oidc --client-id ID   with the secret in %s; "+
			"or --jwks URL, for a stream made in the provider's own console%s\n", dim, signalsSecretEnv, reset)
		return nil
	}
	now := time.Now()
	silent := !c.Manual && c.facts().Silent(now)
	// A time never reached is left out rather than written as the year 1,
	// which a caller would have to know to read as never.
	doc := map[string]any{"connected": true, "provider": c.Provider, "issuer": c.Issuer, "audience": c.Audience,
		"stream": c.Stream, "manual": c.Manual, "status": c.Status, "silent": silent,
		"connected_at": c.Connected, "counts": c.Counts}
	for k, t := range map[string]time.Time{"verified": c.Verified, "asked": c.Asked} {
		if !t.IsZero() {
			doc[k] = t
		}
	}
	if c.AskFailed != "" {
		doc["ask_failed"] = c.AskFailed
	}
	if w.JSON(doc) {
		return nil
	}
	w.Human("  %s%s%s sign-ins, from %s; connected %s\n", bold, c.Provider, reset, c.Issuer, signalsWhen(c.Connected))
	if c.Manual {
		w.Human("  %scannot be asked:%s made in the identity provider's own console, so it cannot be asked to prove "+
			"it reaches here\n", yellow, reset)
	} else {
		mark := ""
		if silent {
			mark = yellow + "silent: " + reset
		}
		switch {
		case !c.Verified.IsZero():
			w.Human("  %slast answered a verification %s; last asked %s\n", mark, signalsWhen(c.Verified), signalsWhen(c.Asked))
		case !c.Asked.IsZero() && silent:
			w.Human("  %snever answered a verification; last asked %s\n", mark, signalsWhen(c.Asked))
		case !c.Asked.IsZero():
			w.Human("  verification not answered yet; asked %s\n", signalsWhen(c.Asked))
		default:
			w.Human("  %sverification not asked yet; the server asks within a day\n", mark)
		}
		if c.AskFailed != "" {
			w.Human("  %sthe last request failed:%s %s\n", yellow, reset, c.AskFailed)
		}
	}
	switch c.Status {
	case "":
	case "enabled":
		w.Human("  the stream is enabled, as the identity provider last said\n")
	default:
		w.Human("  %sthe stream is %s%s, as the identity provider last said, so nothing is sent while it is\n",
			yellow, c.Status, reset)
	}
	n := c.Counts
	w.Human("  %d received, %d acted on, %d unmatched, %d refused, %d past the hourly cap, told to send it again later\n",
		n.Received, n.Acted, n.Unmatched, n.Refused, n.Capped)
	if !n.LastAt.IsZero() {
		w.Human("  last event: %s, %s\n", n.LastType, signalsWhen(n.LastAt))
	} else {
		w.Human("  last event: none yet\n")
	}
	return nil
}

func signalsWhen(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2 Jan 2006 15:04 UTC")
}

// signalsOff disconnects the stream, asking the transmitter to delete it
// first when there is a stream API to ask. What it did stays done: a deny
// it added is lifted by the provider enabling the account, or by a person.
func signalsOff(root string) error {
	caller := resolveCaller(root, "")
	c, err := loadSignals(root)
	if err != nil {
		return err
	}
	if !c.connected() {
		if w.JSON(map[string]any{"connected": false, "was_connected": false}) {
			return nil
		}
		w.Human("no stream is connected\n")
		return nil
	}
	warn, deleted := "", false
	if !c.Manual && c.Stream != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		h := signalsClient()
		access, err := signalsAccess(ctx, h, c, "ssf.manage")
		if err == nil {
			err = c.transmitter().DeleteStream(ctx, h, access, c.Stream)
		}
		if err != nil {
			warn = "the identity provider did not delete the stream (" + onOneLine(err.Error()) + "); delete it in " +
				"its console, or it goes on pushing to an address that refuses everything"
		} else {
			deleted = true
		}
	} else if c.Manual {
		warn = "the stream was made in the identity provider's console; delete it there, or it goes on pushing to " +
			"an address that refuses everything"
	}
	issuer := c.Issuer
	if err := updateSignals(root, func(s *signalsConfig) error {
		var off signalsConfig
		off.keep(s)
		*s = off
		return nil
	}); err != nil {
		return err
	}
	if err := recordE(root, caller.auditRecord("signals.disconnected", "/", audit.Success,
		map[string]string{"issuer": issuer})); err != nil {
		return err
	}
	// Turned off here either way. What is left to do at the provider is a
	// warning, on standard error, and in the JSON document too: a script
	// that turned the stream off read nothing at all, not even whether the
	// provider still had it.
	if warn != "" {
		fmt.Fprintf(w.Err, "  %s%s%s\n", yellow, warn, reset)
	}
	doc := map[string]any{"connected": false, "was_connected": true, "issuer": issuer,
		"deleted_at_provider": deleted}
	if warn != "" {
		doc["warning"] = warn
	}
	if w.JSON(doc) {
		return nil
	}
	w.Human("turned off; anything pushed to %s is refused from now. Denies it added stay until the account is "+
		"enabled or a person lifts them\n", admin.SignalsPath)
	return nil
}

// signalsJob is what the server does about the stream on its timer: once a
// day it asks the transmitter to verify the stream, which is the only way
// a stream gone quiet can be told from one with nothing to say; and it
// writes the hour's summary of refusals that no later refusal wrote.
func signalsJob(root string) upkeep.Job {
	return upkeep.Job{Name: "signals", Do: func(now time.Time) (int, error) {
		c, err := loadSignals(root)
		if err != nil || !c.connected() {
			return 0, err
		}
		n := signalsNoteRefusals(root, now)
		if c.Manual || c.VerifyURL == "" || now.Sub(c.Asked) < 24*time.Hour {
			return n, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		h := signalsClient()
		asked := *c
		access, err := signalsAccess(ctx, h, &asked, "ssf.manage", "ssf.read")
		if err == nil {
			err = signalsAskVerification(ctx, h, &asked, access, now)
		}
		outcome, detail := audit.Success, map[string]string{"issuer": c.Issuer}
		if err != nil {
			outcome, detail["error"] = audit.Failure, onOneLine(err.Error())
			// Not asked again until tomorrow: a failure every quarter hour
			// is a log nobody reads, and posture reports the silence.
			asked.State, asked.Asked = c.State, now
		}
		status := ""
		if err == nil {
			if st, _, serr := asked.transmitter().Status(ctx, h, access, c.Stream); serr == nil {
				status = st
			}
		}
		if uerr := updateSignals(root, func(s *signalsConfig) error {
			if s.Stream != c.Stream {
				return atomicfile.ErrUnchanged
			}
			s.State, s.Asked = asked.State, asked.Asked
			s.AskFailed = ""
			if err != nil {
				s.AskFailed = detail["error"]
			}
			if status != "" {
				s.Status = status
			}
			return nil
		}); uerr != nil && !errors.Is(uerr, atomicfile.ErrUnchanged) {
			return n, uerr
		}
		record(root, audit.Record{Action: "signals.verify-asked", Resource: "/", Outcome: outcome,
			Principal: signalsBy, Kind: audit.KindService, Verified: true, Detail: detail})
		return n + 1, err
	}}
}

// signalsFacts is the stream as the posture scan reads it.
func signalsFacts(root string) *posture.SignalsFacts {
	c, err := loadSignals(root)
	if err != nil || !c.connected() {
		return nil
	}
	return &posture.SignalsFacts{Connected: c.Connected, Verified: c.Verified, Manual: c.Manual}
}

// signalsHooks is the receiver as the admin mounts it, and the stream as
// the Sign-ins screen shows it.
func signalsHooks(root string) *admin.SignalsAdmin {
	receivers := &signalsReceivers{}
	push := &ssf.Push{
		Stream: func() (ssf.Connected, error) {
			c, err := loadSignals(root)
			if err != nil || !c.connected() {
				return ssf.Connected{}, err
			}
			r, err := receivers.get(c)
			if err != nil {
				return ssf.Connected{}, err
			}
			return ssf.Connected{Receiver: r, Bearer: c.Push}, nil
		},
		Deliver: func(set *ssf.SET) error { return signalsDeliver(root, set, time.Now()) },
		Refused: func(why string) { signalsRefused(root, time.Now()) },
	}
	return &admin.SignalsAdmin{
		Handler: push,
		Status: func() (*admin.SignalsStatus, error) {
			c, err := loadSignals(root)
			if err != nil || !c.connected() {
				return nil, err
			}
			n := c.Counts
			return &admin.SignalsStatus{Provider: c.Provider, Issuer: c.Issuer, Manual: c.Manual,
				Verified: c.Verified, Asked: c.Asked, AskFailed: c.AskFailed, State: c.Status, Connected: c.Connected,
				LastAt: n.LastAt, LastType: n.LastType, Received: n.Received, Acted: n.Acted,
				Unmatched: n.Unmatched, Refused: n.Refused, Capped: n.Capped}, nil
		},
	}
}
