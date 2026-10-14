// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/federate"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/oidc"
)

// Trusts: which other issuers' jobs may exchange their identity tokens for
// a short Quilzo token, and what they get (see internal/federate).

func trustPath(root string) string { return filepath.Join(root, "trust.json") }

type trustFile struct {
	Trusts []federate.Trust `json:"trusts"`
}

func loadTrusts(root string) ([]federate.Trust, error) {
	var f trustFile
	err := loadJSON(trustPath(root), &f)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return f.Trusts, err
}

func trustUsage() error {
	fmt.Print(`quilzo trust — let a CI job exchange its identity token for a short Quilzo token

  add NAME --github OWNER/REPO [--ref REF] [--environment ENV]
           --as PRINCIPAL --role ROLE [--on /path] [--for 15m] [--read-only] [--audience URL]
  add NAME --gitlab GROUP/PROJECT [--ref REF] ...
  add NAME --issuer URL --claim NAME=VALUE ... --audience URL --as PRINCIPAL --role ROLE ...
  list
  remove NAME

A job asks its platform for an identity token with this store's address as
the audience, and posts it to /token/exchange. Nothing secret is kept in the
repository. A value ending in * matches a prefix: --ref 'refs/heads/release/*'.
`)
	return nil
}

func cmdTrust(root string, args []string) error {
	if len(args) == 0 {
		return trustUsage()
	}
	switch args[0] {
	case "add":
		return trustAdd(root, args[1:])
	case "list":
		return trustList(root)
	case "remove":
		return trustRemove(root, args[1:])
	}
	return trustUsage()
}

type claimFlags map[string]string

func (c claimFlags) String() string { return fmt.Sprint(map[string]string(c)) }
func (c claimFlags) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || strings.TrimSpace(k) == "" {
		return errors.New("a claim is NAME=VALUE")
	}
	c[strings.TrimSpace(k)] = strings.TrimSpace(val)
	return nil
}

func trustAdd(root string, args []string) error {
	fs := flag.NewFlagSet("trust add", flag.ContinueOnError)
	github := fs.String("github", "", "a GitHub repository, OWNER/REPO, whose Actions jobs are trusted")
	gitlab := fs.String("gitlab", "", "a GitLab project, GROUP/PROJECT, whose CI jobs are trusted")
	issuer := fs.String("issuer", "", "another issuer's address")
	ref := fs.String("ref", "", "the branch or tag, such as refs/heads/main")
	env := fs.String("environment", "", "the deployment environment")
	audience := fs.String("audience", "", "the aud the job asks for; this store's address by default")
	as := fs.String("as", "", "the principal the job acts as, such as ci:docs")
	role := fs.String("role", "", "reader, author or publisher")
	on := fs.String("on", "/", "the part of the store it reaches")
	life := fs.Duration("for", 15*time.Minute, "how long its token lasts, at most an hour")
	readOnly := fs.Bool("read-only", false, "its token refuses every write")
	claims := claimFlags{}
	fs.Var(claims, "claim", "a claim the token must carry, NAME=VALUE; repeat for more")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("usage: quilzo trust add NAME --github OWNER/REPO --as PRINCIPAL --role ROLE")
	}
	t := federate.Trust{Name: rest[0], Issuer: *issuer, Audience: *audience, Claims: claims,
		Principal: *as, Role: auth.Role(*role), Resource: *on, ReadOnly: *readOnly, TTL: life.String(),
		CreatedBy: resolveCaller(root, flagToken).Name, CreatedAt: time.Now().UTC()}
	switch {
	case *github != "" && *gitlab != "":
		return errors.New("a trust is for one platform: --github or --gitlab")
	case *github != "":
		t.Issuer, t.Claims["repository"] = federate.GitHub, *github
	case *gitlab != "":
		t.Issuer, t.Claims["project_path"] = federate.GitLab, *gitlab
	}
	if *ref != "" {
		t.Claims["ref"] = *ref
	}
	if *env != "" {
		t.Claims["environment"] = *env
	}
	if t.Audience == "" {
		t.Audience = strings.TrimSuffix(mustConfig(root).Raw("admin.base_url"), "/")
	}
	if err := t.Validate(); err != nil {
		return err
	}
	trusts, err := loadTrusts(root)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(trusts, func(x federate.Trust) bool { return x.Name == t.Name }) {
		return fmt.Errorf("a trust called %s exists; remove it first", t.Name)
	}
	trusts = append(trusts, t)
	if err := saveJSON(trustPath(root), trustFile{trusts}); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	record(root, caller.auditRecord("trust.added", t.Resource, audit.Success, map[string]string{
		"trust": t.Name, "issuer": t.Issuer, "subject": t.Principal, "role": string(t.Role), "life": t.TTL}))
	w.Human("trusted %s: jobs of %s whose token says %s act as %s, %s on %s, for %s\n",
		t.Name, t.Issuer, describeClaims(t.Claims), t.Principal, t.Role, t.Resource, t.TTL)
	w.Human("  %sin the job: ask for an identity token with audience %s and post it to %s/token/exchange%s\n",
		dim, t.Audience, t.Audience, reset)
	if pol, err := loadPolicy(root); err == nil && strongestRole(pol, t.Principal, t.Resource) == auth.RoleNone {
		w.Human("  %s%s holds no role yet; grant one: quilzo auth grant %s %s --on %s%s\n", yellow, t.Principal,
			t.Principal, t.Role, t.Resource, reset)
	}
	return nil
}

func describeClaims(c map[string]string) string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + c[k]
	}
	return strings.Join(parts, ", ")
}

func trustList(root string) error {
	trusts, err := loadTrusts(root)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"trusts": trusts}) {
		return nil
	}
	if len(trusts) == 0 {
		w.Human("no trusts; programs use tokens issued here\n")
		return nil
	}
	for _, t := range trusts {
		ro := ""
		if t.ReadOnly {
			ro = ", read-only"
		}
		w.Human("%s%s%s  %s  %s\n    as %s, %s on %s%s, for %s; audience %s\n", bold, t.Name, reset, t.Issuer,
			describeClaims(t.Claims), t.Principal, t.Role, t.Resource, ro, t.TTL, t.Audience)
	}
	return nil
}

func trustRemove(root string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: quilzo trust remove NAME")
	}
	trusts, err := loadTrusts(root)
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(slices.Clone(trusts), func(t federate.Trust) bool { return t.Name == args[0] })
	if len(kept) == len(trusts) {
		return fmt.Errorf("no trust called %s", args[0])
	}
	if err := saveJSON(trustPath(root), trustFile{kept}); err != nil {
		return err
	}
	record(root, resolveCaller(root, flagToken).auditRecord("trust.removed", "/", audit.Success,
		map[string]string{"trust": args[0]}))
	w.Human("removed %s; tokens its jobs already hold last until they expire, at most an hour\n", args[0])
	return nil
}

// trustKeys reads an issuer's signing keys from its discovery document,
// kept for an hour, through the trust egress purpose.
type trustKeys struct {
	mu   sync.Mutex
	sets map[string]trustKeySet
}

type trustKeySet struct {
	keys *oidc.Provider
	algs []oidc.Algorithm
	at   time.Time
}

func (k *trustKeys) For(ctx context.Context, issuer string) (oidc.KeySource, []oidc.Algorithm, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if s, ok := k.sets[issuer]; ok && time.Since(s.at) < time.Hour {
		return s.keys, s.algs, nil
	}
	client := fetch.For("trust")
	res, err := client.Get(ctx, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, nil, err
	}
	var d struct {
		Issuer string   `json:"issuer"`
		JWKS   string   `json:"jwks_uri"`
		Algs   []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.Unmarshal(res.Body, &d); err != nil {
		return nil, nil, fmt.Errorf("the discovery document is not JSON: %w", err)
	}
	if d.Issuer != issuer || d.JWKS == "" {
		return nil, nil, fmt.Errorf("the discovery document names the issuer %q and keys %q", d.Issuer, d.JWKS)
	}
	keys, err := oidc.NewKeySet(d.JWKS, func(ctx context.Context, u string) ([]byte, error) {
		r, err := client.Get(ctx, u)
		if err != nil {
			return nil, err
		}
		return r.Body, nil
	})
	if err != nil {
		return nil, nil, err
	}
	var algs []oidc.Algorithm
	for _, a := range d.Algs {
		if slices.Contains(oidc.Supported(), a) {
			algs = append(algs, oidc.Algorithm(a))
		}
	}
	if len(d.Algs) == 0 {
		algs = []oidc.Algorithm{oidc.RS256}
	}
	if k.sets == nil {
		k.sets = map[string]trustKeySet{}
	}
	k.sets[issuer] = trustKeySet{keys: keys, algs: algs, at: time.Now()}
	return keys, algs, nil
}

func federation(root string) *admin.Federation {
	keys := &trustKeys{}
	return &admin.Federation{Trusts: func() ([]federate.Trust, error) { return loadTrusts(root) }, Keys: keys.For}
}
