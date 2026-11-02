// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package provider is the model providers Quilzo knows how to reach, as
// data.
//
// # Why data
//
// Nearly every provider in the world serves the same protocol (OpenAI's
// chat completions) at an address of its own, with its own header for the
// key and its own terms for what it keeps. What differs is a few fields,
// not code, and those fields change: hosts move, regions are added,
// retention changes. So each provider is a profile, in providers.json, built
// in and overridable by an operator's own file, and a gateway route names
// one instead of a bare address. Research behind each: the profile's
// verified field says whether its address came from the provider's own
// documentation or code ("primary"), from widely used integration code, or
// is unverified.
//
// # What a profile pins
//
// A route made from a profile may reach that provider's own hosts and
// nothing else: a model's key is never sent anywhere the profile does not
// name, and a typo or a planted address cannot carry it off. A hosted
// provider is reached only at public addresses; a local runtime only on
// this machine or its network. A profile's parameters (an Azure resource,
// an AWS region, a Cloudflare account) are checked against a pattern
// before they are put into a host name, so a parameter cannot become a
// different host.
package provider

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

//go:embed providers.json
var builtIn []byte

// Provider is one provider's profile.
type Provider struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Group string `json:"group"`
	// Where is where it serves from, in a person's words.
	Where string `json:"where"`
	// Wire is the protocol: openai-chat today.
	Wire string `json:"wire"`
	// Base is the address calls go to, with {param} for a parameter.
	Base   string  `json:"base"`
	Params []Param `json:"params,omitempty"`
	// Auth is how the key is sent: bearer, header:NAME, or none.
	Auth string `json:"auth"`
	// Headers are sent on every call, beside the key.
	Headers map[string]string `json:"headers,omitempty"`
	// Local is a runtime on this machine or its network.
	Local bool `json:"local,omitempty"`
	// Key is the credential name a route suggests (quilzo secret set NAME).
	Key string `json:"key,omitempty"`
	// MaxTokens is the output-limit field its current models take, when it
	// is not max_tokens.
	MaxTokens string `json:"max_tokens,omitempty"`
	Data      Data   `json:"data"`
	// Verified says where its address came from: primary (its own
	// documentation or code), integration code, or unverified.
	Verified string `json:"verified"`
	Docs     string `json:"docs,omitempty"`
}

// Param is a value a provider's address needs: a resource, a region, an
// account.
type Param struct {
	Name string `json:"name"`
	Hint string `json:"hint"`
	// Pattern is what the value must match; a DNS label when empty.
	Pattern string `json:"pattern,omitempty"`
}

// Data is what a provider does with what it is sent, as it says.
type Data struct {
	Trains        string `json:"trains"`
	Retention     string `json:"retention"`
	ZeroRetention string `json:"zero_retention,omitempty"`
	Residency     string `json:"residency"`
}

// Groups, in the order a person choosing one reads them.
var Groups = []struct{ ID, Name string }{
	{"local", "On this machine or your network"},
	{"lab", "Model makers"},
	{"host", "Open-model hosts"},
	{"router", "Routers to many providers"},
	{"cloud", "Cloud platforms"},
	{"region", "Regional providers"},
}

var (
	reID     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	reHeader = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)
	reLabel  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reParam  = regexp.MustCompile(`\{([a-z]+)\}`)
)

// Check says what is wrong with a profile, or nil.
func (p Provider) Check() error {
	if !reID.MatchString(p.ID) {
		return fmt.Errorf("%q is not a provider id", p.ID)
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("%s has no name", p.ID)
	}
	if p.Wire != "openai-chat" {
		return fmt.Errorf("%s speaks %q, which this build does not", p.ID, p.Wire)
	}
	switch {
	case p.Auth == "bearer", p.Auth == "none":
	case strings.HasPrefix(p.Auth, "header:") && reHeader.MatchString(strings.TrimPrefix(p.Auth, "header:")):
	default:
		return fmt.Errorf("%s sends its key %q; bearer, header:NAME or none", p.ID, p.Auth)
	}
	if p.Auth == "none" && !p.Local {
		return fmt.Errorf("%s is hosted and takes no key, which no hosted provider is", p.ID)
	}
	for k := range p.Headers {
		if !reHeader.MatchString(k) || strings.EqualFold(k, "authorization") || strings.EqualFold(k, "host") {
			return fmt.Errorf("%s sends a header %q it may not", p.ID, k)
		}
	}
	// Every {param} in the address is declared, and every declared one used.
	used := map[string]bool{}
	for _, m := range reParam.FindAllStringSubmatch(p.Base, -1) {
		used[m[1]] = true
	}
	for _, prm := range p.Params {
		if !used[prm.Name] {
			return fmt.Errorf("%s declares %s and its address does not use it", p.ID, prm.Name)
		}
		if prm.Pattern != "" {
			if _, err := regexp.Compile(prm.Pattern); err != nil {
				return fmt.Errorf("%s's pattern for %s does not compile", p.ID, prm.Name)
			}
		}
		delete(used, prm.Name)
	}
	for n := range used {
		return fmt.Errorf("%s's address uses {%s} and declares no such parameter", p.ID, n)
	}
	// An address that parses, with a sample value for each parameter.
	sample := map[string]string{}
	for _, prm := range p.Params {
		sample[prm.Name] = "x0"
		if prm.Pattern == "^[0-9a-f]{32}$" {
			sample[prm.Name] = strings.Repeat("0", 32)
		}
	}
	base, err := p.expand(sample)
	if err != nil {
		return err
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s's address %q is not a plain address", p.ID, p.Base)
	}
	if u.Scheme != "https" && !(p.Local && u.Scheme == "http") {
		return fmt.Errorf("%s is hosted and reached over %s; a key is sent only over https", p.ID, u.Scheme)
	}
	switch p.Verified {
	case "primary", "integration code", "unverified":
	default:
		return fmt.Errorf("%s does not say where its address came from", p.ID)
	}
	return nil
}

// expand puts parameter values into the address, each checked first.
func (p Provider) expand(values map[string]string) (string, error) {
	base := p.Base
	for _, prm := range p.Params {
		v := strings.TrimSpace(values[prm.Name])
		if v == "" {
			return "", fmt.Errorf("%s needs %s: %s", p.Name, prm.Name, prm.Hint)
		}
		ok := reLabel.MatchString(v)
		if prm.Pattern != "" {
			ok = regexp.MustCompile(prm.Pattern).MatchString(v)
		}
		if !ok {
			return "", fmt.Errorf("%q is not %s", v, prm.Hint)
		}
		base = strings.ReplaceAll(base, "{"+prm.Name+"}", v)
	}
	return base, nil
}

// Endpoint is a provider's address for these parameter values, and the
// one host calls through it may reach.
func (p Provider) Endpoint(values map[string]string) (base, host string, err error) {
	base, err = p.expand(values)
	if err != nil {
		return "", "", err
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("%s's address is not usable", p.ID)
	}
	return strings.TrimSuffix(base, "/"), u.Host, nil
}

// Catalogue is the providers known here.
type Catalogue struct {
	byID  map[string]Provider
	order []string
}

// Load is the built-in catalogue, with the operator's own file laid over
// it when there is one: a profile there with a built-in's id replaces it,
// and any other is added. Every profile is checked, and one that fails
// fails the load, saying which: a catalogue half-read is a route quietly
// pointed somewhere else.
func Load(overridePath string) (*Catalogue, error) {
	c := &Catalogue{byID: map[string]Provider{}}
	if err := c.add(builtIn, "the built-in catalogue"); err != nil {
		return nil, err
	}
	if overridePath != "" {
		b, err := os.ReadFile(overridePath)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, err
		default:
			if err := c.add(b, overridePath); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

func (c *Catalogue) add(b []byte, from string) error {
	var doc struct {
		Providers []Provider `json:"providers"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("%s: %w", from, err)
	}
	seen := map[string]bool{}
	for _, p := range doc.Providers {
		if err := p.Check(); err != nil {
			return fmt.Errorf("%s: %w", from, err)
		}
		if seen[p.ID] {
			return fmt.Errorf("%s lists %s twice", from, p.ID)
		}
		seen[p.ID] = true
		if _, had := c.byID[p.ID]; !had {
			c.order = append(c.order, p.ID)
		}
		c.byID[p.ID] = p
	}
	return nil
}

// Get is one provider.
func (c *Catalogue) Get(id string) (Provider, bool) {
	p, ok := c.byID[id]
	return p, ok
}

// All is every provider, by group in Groups' order and then by name.
func (c *Catalogue) All() []Provider {
	rank := map[string]int{}
	for i, g := range Groups {
		rank[g.ID] = i
	}
	out := make([]Provider, 0, len(c.order))
	for _, id := range c.order {
		out = append(out, c.byID[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Group] != rank[out[j].Group] {
			return rank[out[i].Group] < rank[out[j].Group]
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// GroupName is a group in a person's words.
func GroupName(id string) string {
	for _, g := range Groups {
		if g.ID == id {
			return g.Name
		}
	}
	return "Other"
}
