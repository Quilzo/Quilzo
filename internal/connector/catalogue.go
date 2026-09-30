// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package connector

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// The connectors that ship with the program.
//
// Each is a manifest like any other, with its hosts left for the region to
// fill: KnowBe4 runs five, ManageEngine seven, and an account on the wrong
// one answers 401 or returns nothing, which reads exactly like an empty
// estate. The region is chosen when the connector is added, the concrete
// hosts are written into the installed file, and from then on it is an
// ordinary manifest somebody can read — the catalogue is where a reviewed
// file comes from, not a second way to run one.
//
// A region is closed: a name chosen from this list, never a hostname typed
// in. Letting the host be typed would make "add the KnowBe4 connector" a way
// to point a credential at any machine.

//go:embed catalogue/*.json
var catalogueFS embed.FS

// Region is where one account of a tool lives.
type Region struct {
	Host string `json:"host"`
	// Token is the host that issues tokens, for the OAuth kinds.
	Token string `json:"token,omitempty"`
}

// Entry is one connector the program ships.
type Entry struct {
	Tool string `json:"tool"`
	// About says what the connector brings back, for a person choosing.
	About    string            `json:"about"`
	Regions  map[string]Region `json:"regions"`
	Default  string            `json:"default"`
	Manifest Manifest          `json:"manifest"`
	// Credentials names every credential the connector needs, with what
	// each one is and where in the tool it is made.
	Credentials map[string]string `json:"credentials"`
	// Params are values a customer supplies that go into a host or a path:
	// tenant, an Entra tenant ID; org, an Okta organisation's subdomain.
	// Each is checked by its own pattern, so neither can make a host or a
	// path point anywhere but the tool.
	Params map[string]string `json:"params,omitempty"`
}

// paramPatterns are the only parameters there are, and what each must be.
var paramPatterns = map[string]*regexp.Regexp{
	// A GUID. Not "common" or "organizations", which accept any tenant's
	// accounts, and not a domain name, whose issuer does not match.
	"tenant": regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
	// One DNS label: it becomes the part before .okta.com and nothing more.
	"org": regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`),
	// A contract or account on an EVM chain: forty hex digits.
	"address": regexp.MustCompile(`^0x[0-9a-f]{40}$`),
}

// Catalogue returns the shipped connectors by name.
func Catalogue() (map[string]Entry, error) {
	files, err := catalogueFS.ReadDir("catalogue")
	if err != nil {
		return nil, err
	}
	out := map[string]Entry{}
	for _, f := range files {
		b, rerr := catalogueFS.ReadFile(path.Join("catalogue", f.Name()))
		if rerr != nil {
			return nil, rerr
		}
		var e Entry
		dec := json.NewDecoder(strings.NewReader(string(b)))
		// A field the loader does not know is a mistake in the file, and
		// ignoring it means the mistake does something other than intended
		// — a misspelt "explode" would silently read the wrong records.
		dec.DisallowUnknownFields()
		if derr := dec.Decode(&e); derr != nil {
			return nil, fmt.Errorf("catalogue/%s: %w", f.Name(), derr)
		}
		name := strings.TrimSuffix(f.Name(), ".json")
		if e.Manifest.Name != name {
			return nil, fmt.Errorf("catalogue/%s describes %q", f.Name(),
				e.Manifest.Name)
		}
		out[name] = e
	}
	return out, nil
}

// RegionNames lists an entry's regions, default first.
func (e Entry) RegionNames() []string {
	var names []string
	for n := range e.Regions {
		if n != e.Default {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return append([]string{e.Default}, names...)
}

// For returns the manifest for one region, checked.
func (e Entry) For(region string) (Manifest, error) {
	return e.With(region, nil)
}

// With returns the manifest for one region with the entry's parameters
// filled in, checked.
func (e Entry) With(region string, params map[string]string) (Manifest,
	error) {

	if region == "" {
		region = e.Default
	}
	r, ok := e.Regions[region]
	if !ok {
		return Manifest{}, fmt.Errorf("%s has no region %q; it runs in %s",
			e.Tool, region, strings.Join(e.RegionNames(), ", "))
	}
	fill := func(s string) (string, error) {
		for name := range e.Params {
			v := strings.ToLower(strings.TrimSpace(params[name]))
			pat, known := paramPatterns[name]
			if !known {
				return "", fmt.Errorf("%s declares a parameter %q that "+
					"nothing checks", e.Tool, name)
			}
			if !pat.MatchString(v) {
				return "", fmt.Errorf("%s needs --%s: %s", e.Tool, name,
					e.Params[name])
			}
			s = strings.ReplaceAll(s, "{"+name+"}", v)
		}
		if strings.ContainsAny(s, "{}") {
			return "", fmt.Errorf("%s leaves %q unfilled", e.Tool, s)
		}
		return s, nil
	}
	m := e.Manifest
	var err error
	if m.Host, err = fill(r.Host); err != nil {
		return Manifest{}, err
	}
	if m.Auth.Token != nil {
		t := *m.Auth.Token
		if t.Host, err = fill(r.Token); err != nil {
			return Manifest{}, err
		}
		if t.Path, err = fill(t.Path); err != nil {
			return Manifest{}, err
		}
		m.Auth.Token = &t
	}
	// The endpoints are shared with the entry; copy them so a caller that
	// edits the result does not edit the catalogue.
	m.Endpoints = append([]Endpoint(nil), m.Endpoints...)
	for i := range m.Endpoints {
		// A parameter may also be part of a path: an organisation's audit
		// log, one contract's events. It was matched against its pattern
		// above, so it is one segment and nothing else.
		// {key} is not a parameter: it is each parent record's key, filled
		// when the endpoint is read.
		const key = "\x00key\x00"
		path := strings.ReplaceAll(m.Endpoints[i].Path, "{key}", key)
		if path, err = fill(path); err != nil {
			return Manifest{}, err
		}
		m.Endpoints[i].Path = strings.ReplaceAll(path, key, "{key}")
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
