// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/connect"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/vault"
)

// Connected accounts (internal/connect): the providers an administrator
// declares, the accounts people connect at them, sealed, and the token an
// agent acting for one of those people is given.
//
//	quilzo connect providers                          declared, and the templates
//	quilzo connect provider add NAME --template google --client-id ID --client-secret SECRET
//	quilzo connect provider remove NAME
//	quilzo connect start NAME                         prints where to sign in
//	quilzo connect list                               your connected accounts, and when they end
//	quilzo connect revoke NAME [--person WHO]
//
// Starting from the command line prints the provider's address; the
// browser comes back to the admin's own address, which finishes it for the
// person who started it, signed in there.

func connectProvidersPath(root string) string { return filepath.Join(root, "connect.json") }
func connectionsPath(root string) string      { return filepath.Join(root, "connections.json") }
func connectPendingDir(root string) string    { return filepath.Join(root, "connect-pending") }

type connectProviders struct {
	Providers []connect.Provider `json:"providers"`
}

func loadConnectProviders(root string) (connectProviders, error) {
	var f connectProviders
	b, err := os.ReadFile(connectProvidersPath(root))
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("%s is unreadable: %w", connectProvidersPath(root), err)
	}
	return f, nil
}

func (f connectProviders) get(name string) (connect.Provider, bool) {
	for _, p := range f.Providers {
		if p.Name == name {
			return p, true
		}
	}
	return connect.Provider{}, false
}

// account is one person's connection, its tokens sealed. Whose it is is
// in its key, hashed, and nowhere else: the file names nobody.
type account struct {
	Provider  string          `json:"provider"`
	Scope     string          `json:"scope,omitempty"`
	Connected time.Time       `json:"connected"`
	Refreshed time.Time       `json:"refreshed,omitempty"`
	Sealed    json.RawMessage `json:"sealed"`
	// When its tokens end, beside them rather than in them, so a list
	// says it without opening them; one kept before this was learns it
	// the next time it is used.
	connect.Ends
}

type accounts struct {
	Accounts map[string]account `json:"accounts,omitempty"`
}

// accountKey is where a person's connection at a provider is kept: their
// name hashed, so the file's keys say nothing about who.
func accountKey(provider, person string) string {
	h := sha256.Sum256([]byte(person))
	return provider + "/" + hex.EncodeToString(h[:12])
}

func accountAAD(key string) []byte { return []byte("connection/" + key) }

func loadAccounts(root string) (accounts, error) {
	var f accounts
	b, err := os.ReadFile(connectionsPath(root))
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("%s is unreadable: %w", connectionsPath(root), err)
	}
	return f, nil
}

// changeAccounts changes the file under its lock.
func changeAccounts(root string, change func(*accounts, *vault.Keyring) error) error {
	kr, err := loadKeyring(root)
	if err != nil {
		return err
	}
	if kr == nil {
		return errors.New("a connected account's tokens are kept sealed, and this store has no keyring yet. " +
			"Run quilzo vault enable first")
	}
	unlock, err := atomicfile.Lock(connectionsPath(root) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	f, err := loadAccounts(root)
	if err != nil {
		return err
	}
	if f.Accounts == nil {
		f.Accounts = map[string]account{}
	}
	if err := change(&f, kr); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(connectionsPath(root), append(b, '\n'), 0o600)
}

func sealToken(kr *vault.Keyring, key string, t connect.Token) (json.RawMessage, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	s, err := kr.Seal(b, accountAAD(key))
	if err != nil {
		return nil, err
	}
	return vault.Marshal(s)
}

func openToken(kr *vault.Keyring, key string, raw json.RawMessage) (connect.Token, error) {
	var t connect.Token
	s, err := vault.Unmarshal(raw)
	if err != nil {
		return t, err
	}
	b, err := kr.Open(s, accountAAD(key))
	if err != nil {
		return t, err
	}
	return t, json.Unmarshal(b, &t)
}

// connectRedirect is where a provider sends a person back: the admin's
// own address, which has to be declared to be known.
func connectRedirect(root string) (string, error) {
	base := strings.TrimRight(mustConfig(root).Raw("admin.base_url"), "/")
	if base == "" {
		return "", errors.New("set admin.base_url to the admin's address first: a provider sends people back " +
			"to exactly one address, registered with it, and it is that address with /connections/callback")
	}
	return base + "/connections/callback", nil
}

// connectPoster sends a form to a provider's endpoint, through the checked
// client: no redirect is followed with a code or a secret in it.
var connectPoster connect.Poster = func(ctx context.Context, to string, form url.Values) ([]byte, error) {
	res, err := fetch.For("accounts").PostForm(ctx, to, form, "", "")
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}

// connectGetter makes the GET that Meta's dialects exchange and renew
// their tokens with, through the checked client. The address carries the
// client secret and the token, so no redirect is followed with it, and
// the answer is bounded as a token endpoint's is.
var connectGetter connect.Getter = func(ctx context.Context, u string) (int, http.Header, []byte, error) {
	c := fetch.For("accounts")
	c.Limits = fetch.Limits{MaxBytes: 64 << 10, Timeout: 15 * time.Second, MaxRedirects: -1}
	res, err := c.Do(ctx, http.MethodGet, u, nil, map[string]string{"Accept": "application/json"})
	if err != nil {
		return 0, nil, nil, err
	}
	return res.Status, res.Header, res.Body, nil
}

// clientSecret is a provider's client secret, when it has one.
func clientSecret(root string, p connect.Provider) (string, error) {
	if p.Secret == "" {
		return "", nil
	}
	return readSecret(root, p.Secret)
}

// beginConnect starts a person connecting their account, and says where
// to send their browser.
func beginConnect(root, name, person string) (string, error) {
	set, err := loadConnectProviders(root)
	if err != nil {
		return "", err
	}
	p, ok := set.get(name)
	if !ok {
		return "", fmt.Errorf("no provider called %s: quilzo connect providers", name)
	}
	redirect, err := connectRedirect(root)
	if err != nil {
		return "", err
	}
	pd, to, err := connect.Begin(p, redirect, person, time.Now())
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(pd)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(connectPendingDir(root), 0o700); err != nil {
		return "", err
	}
	if err := atomicfile.Write(filepath.Join(connectPendingDir(root), pd.State+".json"), b, 0o600); err != nil {
		return "", err
	}
	return to, nil
}

// takePending is a connection in progress, once: it is deleted as it is
// read, so an answer can finish it at most once.
func takePending(root, state string) (connect.Pending, error) {
	var pd connect.Pending
	if !connect.ValidState(state) {
		return pd, errors.New("this answer does not come from a connection started here")
	}
	path := filepath.Join(connectPendingDir(root), state+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		return pd, errors.New("this connection has finished already, expired, or was not started here")
	}
	if err := os.Remove(path); err != nil {
		return pd, err
	}
	if err := json.Unmarshal(b, &pd); err != nil || pd.State != state {
		return pd, errors.New("this connection's record is unreadable")
	}
	return pd, nil
}

// finishConnect finishes a connection, for the person signed in where the
// provider sent them back: the one who started it, or nobody.
func finishConnect(ctx context.Context, root, state, code, person string) (string, error) {
	pd, err := takePending(root, state)
	if err != nil {
		return "", err
	}
	if pd.Person != person {
		// Somebody else's connection, finished in this browser, would put
		// their account in this person's name (and an agent acting for
		// this person would write into it). Refused.
		recordE(root, audit.Record{Action: "connect.refused", Resource: "/connections", Outcome: audit.Denied,
			Principal: person, Kind: audit.KindHuman,
			Detail: map[string]string{"provider": pd.Provider, "why": "started by somebody else"}})
		return "", errors.New("this connection was started by somebody else; start your own")
	}
	set, err := loadConnectProviders(root)
	if err != nil {
		return "", err
	}
	p, ok := set.get(pd.Provider)
	if !ok {
		return "", fmt.Errorf("%s is no longer a provider here", pd.Provider)
	}
	secret, err := clientSecret(root, p)
	if err != nil {
		return "", err
	}
	tok, err := connect.Exchange(ctx, connectPoster, connectGetter, p, secret, pd, code, time.Now())
	if err != nil {
		recordE(root, audit.Record{Action: "connect.failed", Resource: "/connections", Outcome: audit.Failure,
			Principal: person, Kind: audit.KindHuman, Detail: map[string]string{"provider": pd.Provider, "why": clip(err.Error(), 200)}})
		return "", err
	}
	key := accountKey(p.Name, person)
	err = changeAccounts(root, func(f *accounts, kr *vault.Keyring) error {
		sealed, err := sealToken(kr, key, tok)
		if err != nil {
			return err
		}
		f.Accounts[key] = account{Provider: p.Name, Scope: tok.Scope, Connected: time.Now().UTC(), Sealed: sealed, Ends: tok.Ends()}
		return nil
	})
	if err != nil {
		return "", err
	}
	recordE(root, audit.Record{Action: "connect.connected", Resource: "/connections", Outcome: audit.Success,
		Principal: person, Kind: audit.KindHuman, Verified: true, Detail: map[string]string{"provider": pd.Provider}})
	return p.Title, nil
}

// connectionToken is the access token of a person's account at a
// provider, refreshed when due, for a call to host. A token that was only
// due to be renewed (Meta's, a day after the last renewal) and could not
// be still works, and is used as it is: the renewal is tried again at the
// next use, rather than the call failing while the token is good.
func connectionToken(ctx context.Context, root, provider, person, host string) (string, error) {
	set, err := loadConnectProviders(root)
	if err != nil {
		return "", err
	}
	p, ok := set.get(provider)
	if !ok {
		return "", fmt.Errorf("%s is not a provider here", provider)
	}
	if !p.Allows(host) {
		return "", fmt.Errorf("a %s token goes to %s, not to %s", p.Title, strings.Join(p.Hosts, ", "), host)
	}
	if person == "" {
		return "", errors.New("this acts for nobody, and a connected account is somebody's")
	}
	key := accountKey(provider, person)
	var out string
	err = changeAccounts(root, func(f *accounts, kr *vault.Keyring) error {
		a, ok := f.Accounts[key]
		if !ok {
			return fmt.Errorf("%s has not connected an account at %s: quilzo connect start %s, or Your accounts in the admin", person, p.Title, p.Name)
		}
		tok, err := openToken(kr, key, a.Sealed)
		if err != nil {
			return err
		}
		if tok.Due(time.Now()) {
			secret, err := clientSecret(root, p)
			if err != nil && tok.Lapsing(time.Now()) {
				return err
			}
			// A renewal that cannot be asked for, the client secret being
			// unreadable here (a process started without the variable that
			// carries it), is one that failed: the call failed a day after
			// connecting, with a token that worked for weeks more.
			var fresh connect.Token
			if err == nil {
				fresh, err = connect.Refresh(ctx, connectPoster, connectGetter, p, secret, tok, time.Now())
			}
			switch {
			case err != nil && tok.Lapsing(time.Now()):
				return fmt.Errorf("%s's account at %s could not be refreshed (%v): connect it again", person, p.Title, err)
			case err == nil:
				// A refresh token kept as it was ends when it did: the
				// answer that kept it says nothing new of that. (LinkedIn's
				// dialect keeps its own year from the first issue, which
				// using it does not renew.)
				if fresh.Refresh == tok.Refresh && fresh.RefreshExpiry.IsZero() {
					fresh.RefreshExpiry = tok.RefreshExpiry
				}
				if a.Sealed, err = sealToken(kr, key, fresh); err != nil {
					return err
				}
				a.Refreshed = time.Now().UTC()
				tok = fresh
			}
		}
		a.Ends = tok.Ends()
		f.Accounts[key] = a
		out = tok.Access
		return nil
	})
	return out, err
}

// revokeConnection disconnects a person's account: revoked at the
// provider, where it offers that, and forgotten here either way.
func revokeConnection(ctx context.Context, root, provider, person string) error {
	set, err := loadConnectProviders(root)
	if err != nil {
		return err
	}
	p, known := set.get(provider)
	key := accountKey(provider, person)
	var tok connect.Token
	err = changeAccounts(root, func(f *accounts, kr *vault.Keyring) error {
		a, ok := f.Accounts[key]
		if !ok {
			return fmt.Errorf("%s has no account connected at %s", person, provider)
		}
		tok, _ = openToken(kr, key, a.Sealed)
		delete(f.Accounts, key)
		return nil
	})
	if err != nil {
		return err
	}
	if known {
		secret, _ := clientSecret(root, p)
		for _, t := range []string{tok.Refresh, tok.Access} {
			_ = connect.Revoke(ctx, connectPoster, p, secret, t)
		}
	}
	return nil
}

// myConnections are a person's connected accounts.
func myConnections(root, person string) ([]account, error) {
	f, err := loadAccounts(root)
	if err != nil {
		return nil, err
	}
	var out []account
	for key, a := range f.Accounts {
		if key == accountKey(a.Provider, person) {
			a.Sealed = nil
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out, nil
}

func cmdConnect(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	caller := resolveCaller(root, flagToken)
	switch args[0] {
	case "providers":
		set, err := loadConnectProviders(root)
		if err != nil {
			return err
		}
		if w.JSON(set) {
			return nil
		}
		if len(set.Providers) == 0 {
			w.Human("  %sno provider is declared; templates: %s%s\n", dim, strings.Join(connect.TemplateNames(), ", "), reset)
		}
		for _, p := range set.Providers {
			w.Human("%s%s%s  (%s)\n    scopes %s\n    tokens go to %s\n", bold, p.Title, reset, p.Name,
				orDefault(strings.Join(p.Scopes, " "), "none asked"), strings.Join(p.Hosts, ", "))
		}
		return nil
	case "provider":
		return connectProvider(root, caller, args[1:])
	case "start":
		if len(args) != 2 {
			return errors.New("usage: quilzo connect start PROVIDER")
		}
		if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
			return err
		}
		to, err := beginConnect(root, args[1], caller.Name)
		if err != nil {
			return err
		}
		record(root, caller.auditRecord("connect.start", "/connections", audit.Success, map[string]string{"provider": args[1]}))
		w.Human("Open this in the browser where you are signed in to the admin as %s, within ten minutes:\n\n  %s\n", caller.Name, to)
		return nil
	case "list":
		mine, err := myConnections(root, caller.Name)
		if err != nil {
			return err
		}
		if w.JSON(mine) {
			return nil
		}
		if len(mine) == 0 {
			w.Human("  %s%s has connected no account%s\n", dim, caller.Name, reset)
		}
		now := time.Now()
		for _, a := range mine {
			w.Human("%s%s%s  connected %s%s\n    %s\n", bold, a.Provider, reset, a.Connected.Local().Format("2 Jan 2006"),
				map[bool]string{true: ", scopes " + a.Scope, false: ""}[a.Scope != ""], a.Ends.Said(time.Local))
			if a.LapsesSoon(now) {
				// One that has stopped says so, as Your accounts does: told to
				// connect it again "before" a time gone by, a person read a
				// connection that no longer worked as one that still did.
				when := "connect it again before " + a.Lapses().Local().Format("2 Jan 2006 15:04")
				if !a.Lapses().After(now) {
					when = "it stopped working " + a.Lapses().Local().Format("2 Jan 2006 15:04") + ", so connect it again"
				}
				w.Human("    %s%s: quilzo connect start %s%s\n", yellow, when, a.Provider, reset)
			}
		}
		return nil
	case "revoke":
		fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
		person := fs.String("person", "", "another person's account: an administrator's to disconnect")
		rest, flags := leadingArgs(args[1:], 1)
		if err := parseFlags(fs, flags, &rest, 1); err != nil {
			return err
		}
		if len(rest) != 1 {
			return errors.New("usage: quilzo connect revoke PROVIDER [--person WHO]")
		}
		who := caller.Name
		if *person != "" && *person != caller.Name {
			if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
				return err
			}
			who = *person
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := revokeConnection(ctx, root, rest[0], who); err != nil {
			return err
		}
		record(root, caller.auditRecord("connect.revoked", "/connections", audit.Success,
			map[string]string{"provider": rest[0], "own": fmt.Sprint(who == caller.Name)}))
		w.Human("  %sdisconnected; agents acting for %s no longer reach %s as them%s\n", green, who, rest[0], reset)
		return nil
	}
	return fmt.Errorf("unknown connect command %q; try providers, provider, start, list or revoke", args[0])
}

// connectProvider declares or removes a provider: an administrator's.
func connectProvider(root string, caller *Caller, args []string) error {
	if len(args) >= 1 && args[0] == "discover" {
		return connectDiscover(root, caller, args[1:])
	}
	if len(args) < 2 || (args[0] != "add" && args[0] != "remove") {
		return errors.New("usage: quilzo connect provider add NAME [--template " + strings.Join(connect.TemplateNames(), "|") +
			"] --client-id ID [--client-secret SECRET] [--scope S]... [--host H]... " +
			"[--auth-url URL --token-url URL --revocation-url URL --title T] [--dialect " + strings.Join(connect.DialectNames(), "|") + "]\n" +
			"       quilzo connect provider remove NAME\n" +
			"       quilzo connect provider discover NAME https://SERVER/mcp [--client-id ID] [--title T]")
	}
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	verb, name := args[0], args[1]
	fs := flag.NewFlagSet("provider", flag.ContinueOnError)
	template := fs.String("template", "", "start from a known provider: "+strings.Join(connect.TemplateNames(), ", "))
	title := fs.String("title", "", "what people connecting see")
	authURL := fs.String("auth-url", "", "the authorization endpoint")
	tokenURL := fs.String("token-url", "", "the token endpoint")
	revokeURL := fs.String("revocation-url", "", "the revocation endpoint, when it has one")
	clientID := fs.String("client-id", "", "the client id the provider issued")
	secret := fs.String("client-secret", "", "the sealed credential holding the client secret (quilzo secret set NAME)")
	dialect := fs.String("dialect", "", "how the provider departs from standard OAuth 2, for one declared without a template "+
		"(by default its platform's, at a social platform's site, and otherwise oauth2): "+strings.Join(connect.DialectNames(), ", "))
	var scopes, hosts multiFlag
	fs.Var(&scopes, "scope", "a scope to ask for; repeat for more")
	fs.Var(&hosts, "host", "an API host its tokens may go to; repeat for more")
	if err := parseFlags(fs, args[2:], nil, 0); err != nil {
		return err
	}
	unlock, err := atomicfile.Lock(connectProvidersPath(root) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	set, err := loadConnectProviders(root)
	if err != nil {
		return err
	}
	var kept []connect.Provider
	var inferred connect.Dialect
	for _, p := range set.Providers {
		if p.Name != name {
			kept = append(kept, p)
		}
	}
	if verb == "remove" {
		if len(kept) == len(set.Providers) {
			return fmt.Errorf("no provider called %s", name)
		}
	} else {
		p := connect.Provider{Name: name}
		if *template != "" {
			t, ok := connect.Templates[*template]
			if !ok {
				return fmt.Errorf("no template called %s; there are %s", *template, strings.Join(connect.TemplateNames(), ", "))
			}
			p = t
			p.Name = name
		}
		for _, f := range []struct {
			v    string
			into *string
		}{{*title, &p.Title}, {*authURL, &p.AuthURL}, {*tokenURL, &p.TokenURL}, {*revokeURL, &p.RevokeURL},
			{*clientID, &p.ClientID}, {*secret, &p.Secret}} {
			if strings.TrimSpace(f.v) != "" {
				*f.into = strings.TrimSpace(f.v)
			}
		}
		if d := strings.TrimSpace(*dialect); d != "" {
			p.Dialect = connect.Dialect(d)
		} else if *template == "" {
			// Declared by hand at a social platform's address, it speaks
			// that platform's dialect, as the template does: named none,
			// TikTok was asked as plain OAuth 2 and refused the request.
			// --dialect oauth2 declares it otherwise.
			p.Dialect = connect.PlatformDialect(p.AuthURL)
			inferred = p.Dialect
		}
		if len(scopes) > 0 {
			p.Scopes = append(append([]string{}, p.Scopes...), scopes...)
		}
		if len(hosts) > 0 {
			p.Hosts = hosts
		}
		if err := p.Check(); err != nil {
			if inferred != "" {
				return fmt.Errorf("%w (at its platform's site it speaks %s; --dialect oauth2 declares it otherwise)", err, inferred)
			}
			return err
		}
		kept = append(kept, p)
	}
	set.Providers = kept
	b, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicfile.Write(connectProvidersPath(root), append(b, '\n'), 0o600); err != nil {
		return err
	}
	record(root, caller.auditRecord("connect.provider."+verb, "/connections", audit.Success, map[string]string{"provider": name}))
	if verb == "add" {
		if inferred != "" {
			w.Human("  %sit speaks %s, its platform's dialect of OAuth; --dialect oauth2 declares it otherwise%s\n",
				dim, inferred, reset)
		}
		if redirect, err := connectRedirect(root); err == nil {
			w.Human("  %sregister this address with the provider as the redirect: %s%s\n", dim, redirect, reset)
		}
	}
	return nil
}

// actingFor is the person whose connected accounts a caller's calls go
// with: a person's own, and nobody's for a service or an agent acting on
// its own name.
func actingFor(c *Caller) string {
	if c == nil || c.Kind != audit.KindHuman {
		return ""
	}
	return c.Name
}

// connectionsCapability is the admin's Connected accounts screen.
func connectionsCapability(root string) *admin.Connections {
	return &admin.Connections{
		Providers: func() ([]connect.Provider, error) {
			set, err := loadConnectProviders(root)
			return set.Providers, err
		},
		Mine: func(person string) ([]admin.ConnectedAccount, error) {
			mine, err := myConnections(root, person)
			out := make([]admin.ConnectedAccount, 0, len(mine))
			for _, a := range mine {
				out = append(out, admin.ConnectedAccount{Provider: a.Provider, Scope: a.Scope, Connected: a.Connected, Expires: a.Ends})
			}
			return out, err
		},
		Start: func(provider, person string) (string, error) { return beginConnect(root, provider, person) },
		Finish: func(ctx context.Context, state, code, person string) (string, error) {
			return finishConnect(ctx, root, state, code, person)
		},
		Revoke: func(ctx context.Context, provider, person string) error {
			return revokeConnection(ctx, root, provider, person)
		},
	}
}
