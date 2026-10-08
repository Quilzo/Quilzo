// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package indicator holds things somebody else has said are bad — an
// address, a domain, a hash — and finds them in events.
//
// # An indicator is a claim with an author and an end
//
// "This address is malicious" is true of whoever held the address when it
// was written. Addresses are reassigned, domains lapse and are bought by
// somebody else, and a list with no dates on it turns, over a year or two,
// into a list of other people's infrastructure. So every indicator here
// says who said so and when it stops being believed, and one past its date
// stops matching. There is a ceiling on how far ahead that date can be.
//
// # Some things are never indicators
//
// A private address, a loopback, the hash of the empty file, a bare
// top-level domain. Feeds carry these — scraped from a sandbox's own
// network, or from a sample that wrote an empty file — and each one matches
// thousands of ordinary events. They are refused at the door, counted, and
// the count is reported: an import that silently dropped them would look
// the same as a feed that never had them.
//
// # Looking backwards is the point
//
// A rule finds what happens after it is written. An indicator is usually
// learned after the fact: the campaign was last month and the report came
// out today. So the first thing done with a new indicator is to read the
// events already held for it.
package indicator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// Kind is what an indicator is.
type Kind string

const (
	IP     Kind = "ip"
	Domain Kind = "domain"
	URL    Kind = "url"
	Hash   Kind = "hash"
	Email  Kind = "email"
)

// Kinds lists them.
var Kinds = []Kind{IP, Domain, URL, Hash, Email}

// MaxLife is the longest an indicator is believed from the day it was
// added. A year: past that the claim is about a different world.
const MaxLife = 365 * 24 * time.Hour

// DefaultLife is how long one with no stated end is believed.
//
// Ninety days. Most feeds give no end at all, which is how lists grow for
// ever, and the honest reading of "no end stated" is not "for ever".
const DefaultLife = 90 * 24 * time.Hour

// MaxValue bounds one indicator's value.
const MaxValue = 2048

// Indicator is one thing somebody said is bad.
type Indicator struct {
	// ID is derived from the kind and value, so the same indicator from
	// two feeds is one entry.
	ID    string `json:"id"`
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
	// Sources is who said so. More than one is corroboration.
	Sources []string `json:"sources"`
	// Note is what it is said to be: a family, a campaign.
	Note string `json:"note,omitempty"`
	// Added is when it arrived here. From is the earliest moment it is
	// claimed about, when the source gave one; zero means any past event.
	Added time.Time `json:"added"`
	From  time.Time `json:"from,omitzero"`
	// Until is when it stops being believed.
	Until time.Time `json:"until"`
}

// Live reports whether the indicator is still believed at a moment.
func (i Indicator) Live(at time.Time) bool { return at.Before(i.Until) }

// Covers reports whether an event at a moment is inside what the indicator
// claims about.
func (i Indicator) Covers(at time.Time) bool {
	return !at.After(i.Until) && (i.From.IsZero() || !at.Before(i.From))
}

// idOf names an indicator from what it is.
func idOf(k Kind, value string) string {
	sum := sha256.Sum256([]byte(string(k) + "\x00" + value))
	return hex.EncodeToString(sum[:8])
}

// Refang undoes the ways indicators are written so they cannot be clicked.
func Refang(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range [][2]string{{"[.]", "."}, {"(.)", "."}, {"[dot]", "."},
		{"[:]", ":"}, {"[@]", "@"}, {"[at]", "@"}, {"hxxps://", "https://"},
		{"hxxp://", "http://"}, {"hXXps://", "https://"}, {"hXXp://", "http://"}} {
		s = strings.ReplaceAll(s, p[0], p[1])
	}
	return s
}

// emptyHashes are the digests of nothing: MD5, SHA-1 and SHA-256 of the
// empty file. Every system has that file.
var emptyHashes = map[string]bool{
	"d41d8cd98f00b204e9800998ecf8427e":                                 true,
	"da39a3ee5e6b4b0d3255bfef95601890afd80709":                         true,
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": true,
}

// shared are domains so many unrelated people use that one as an indicator
// is a finding about everybody. A feed lists one when malware was hosted
// under it; the thing to list is the name under it, and that is accepted.
var shared = map[string]bool{}

func init() {
	for _, d := range strings.Fields(`google.com googleapis.com gstatic.com
		googleusercontent.com gmail.com youtube.com microsoft.com office.com
		office365.com live.com outlook.com windows.net azurewebsites.net
		sharepoint.com microsoftonline.com apple.com icloud.com amazon.com
		amazonaws.com cloudfront.net cloudflare.com cloudflare.net
		workers.dev pages.dev akamai.net akamaihd.net akamaized.net
		fastly.net github.com github.io githubusercontent.com gitlab.com
		slack.com zoom.us dropbox.com dropboxusercontent.com discord.com
		discordapp.com telegram.org t.me bit.ly herokuapp.com netlify.app
		vercel.app web.app firebaseapp.com blogspot.com wordpress.com
		co.uk com.au co.jp com.br co.in org.uk`) {
		shared[d] = true
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != ""
}

// normDomain lower-cases a domain and checks it is one.
func normDomain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" || len(s) > 253 {
		return "", fmt.Errorf("not a domain")
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		// A bare name or a whole top-level domain. Matching "com" is
		// matching the internet.
		return "", fmt.Errorf("%q is a single label, which would match "+
			"everything under it", s)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return "", fmt.Errorf("%q is not a domain", s)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' ||
				c == '_' || c > 127) {
				return "", fmt.Errorf("%q is not a domain", s)
			}
		}
	}
	return s, nil
}

// Normalise puts a value in the one form it is stored and compared in, and
// refuses the ones that are never indicators.
func Normalise(k Kind, value string) (string, error) {
	value = Refang(value)
	if value == "" {
		return "", fmt.Errorf("an indicator with no value")
	}
	if len(value) > MaxValue {
		return "", fmt.Errorf("an indicator of %d characters", len(value))
	}
	switch k {
	case IP:
		a, err := netip.ParseAddr(value)
		if err != nil {
			return "", fmt.Errorf("%q is not an address", value)
		}
		a = a.Unmap()
		switch {
		case a.IsPrivate(), a.IsLoopback(), a.IsUnspecified(),
			a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
			a.IsMulticast(), a.IsInterfaceLocalMulticast():
			return "", fmt.Errorf("%s is a private or local address. It "+
				"names a machine on somebody's own network — often the "+
				"sandbox that produced the feed — and here it would match "+
				"whatever happens to hold it", a)
		}
		return a.String(), nil
	case Domain:
		if _, err := netip.ParseAddr(value); err == nil {
			return "", fmt.Errorf("%q is an address, not a domain", value)
		}
		d, err := normDomain(value)
		if err != nil {
			return "", err
		}
		if shared[d] {
			return "", fmt.Errorf("%s is shared by a great many unrelated "+
				"people, and a domain indicator covers everything under "+
				"it. List the name under it that is actually bad", d)
		}
		return d, nil
	case URL:
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") ||
			u.Host == "" {
			return "", fmt.Errorf("%q is not an http or https URL", value)
		}
		if u.Path == "" || u.Path == "/" {
			if u.RawQuery == "" {
				return "", fmt.Errorf("%q names a whole site. Add the "+
					"domain as a domain indicator, which says so", value)
			}
		}
		u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
		u.Fragment, u.User = "", nil
		return u.String(), nil
	case Hash:
		h := strings.ToLower(value)
		if n := len(h); (n != 32 && n != 40 && n != 64) || !isHex(h) {
			return "", fmt.Errorf("%q is not an MD5, SHA-1 or SHA-256 "+
				"digest", value)
		}
		if emptyHashes[h] {
			return "", fmt.Errorf("%s is the digest of the empty file, "+
				"which every machine has", h)
		}
		return h, nil
	case Email:
		v := strings.ToLower(value)
		local, domain, ok := strings.Cut(v, "@")
		if !ok || local == "" || strings.ContainsAny(local, " <>") {
			return "", fmt.Errorf("%q is not an address", value)
		}
		d, err := normDomain(domain)
		if err != nil {
			return "", fmt.Errorf("%q is not an address", value)
		}
		return local + "@" + d, nil
	}
	return "", fmt.Errorf("%q is not a kind of indicator", k)
}

// Guess works out what a bare value is, for a list with one per line.
func Guess(value string) (Kind, bool) {
	v := Refang(value)
	switch {
	case v == "":
		return "", false
	case strings.HasPrefix(strings.ToLower(v), "http://"),
		strings.HasPrefix(strings.ToLower(v), "https://"):
		return URL, true
	case strings.Contains(v, "@"):
		return Email, true
	}
	if _, err := netip.ParseAddr(v); err == nil {
		return IP, true
	}
	if n := len(v); (n == 32 || n == 40 || n == 64) && isHex(strings.ToLower(v)) {
		return Hash, true
	}
	if strings.Contains(v, ".") && !strings.ContainsAny(v, " /\\") {
		return Domain, true
	}
	return "", false
}

// New makes an indicator, normalised and bounded.
//
// until zero means DefaultLife from now; a date further off than MaxLife
// is brought back to it, and one already past is refused — it would be
// stored and never match, which reads as cover.
func New(k Kind, value, source, note string, from, until,
	now time.Time) (Indicator, error) {

	v, err := Normalise(k, value)
	if err != nil {
		return Indicator{}, err
	}
	source = strings.TrimSpace(source)
	if source == "" {
		return Indicator{}, fmt.Errorf("%s: an indicator is somebody's "+
			"claim, and this one names nobody", v)
	}
	if len(source) > 200 || len(note) > 500 {
		return Indicator{}, fmt.Errorf("%s: the source or the note is too "+
			"long", v)
	}
	now = now.UTC()
	switch {
	case until.IsZero():
		until = now.Add(DefaultLife)
	case !until.After(now):
		return Indicator{}, fmt.Errorf("%s stopped being believed on %s",
			v, until.UTC().Format("2006-01-02"))
	case until.Sub(now) > MaxLife:
		until = now.Add(MaxLife)
	}
	return Indicator{ID: idOf(k, v), Kind: k, Value: v,
		Sources: []string{source}, Note: strings.TrimSpace(note),
		Added: now, From: from.UTC(), Until: until.UTC()}, nil
}

// Set is the indicators held, indexed for matching.
type Set struct {
	byID  map[string]*Indicator
	byVal map[Kind]map[string]*Indicator
}

// NewSet indexes a list.
func NewSet(in []Indicator) *Set {
	s := &Set{byID: map[string]*Indicator{}, byVal: map[Kind]map[string]*Indicator{}}
	for _, i := range in {
		s.put(i)
	}
	return s
}

func (s *Set) put(i Indicator) {
	if s.byVal[i.Kind] == nil {
		s.byVal[i.Kind] = map[string]*Indicator{}
	}
	c := i
	s.byID[i.ID] = &c
	s.byVal[i.Kind][i.Value] = &c
}

// Len is how many are held.
func (s *Set) Len() int { return len(s.byID) }

// Get finds one by identifier.
func (s *Set) Get(id string) (Indicator, bool) {
	i, ok := s.byID[id]
	if !ok {
		return Indicator{}, false
	}
	return *i, true
}

// Add merges one in. The same indicator from a second source gains the
// source and the later end; it does not become a second entry. It reports
// whether the indicator was new.
func (s *Set) Add(i Indicator) bool {
	old, have := s.byID[i.ID]
	if !have {
		s.put(i)
		return true
	}
	for _, src := range i.Sources {
		seen := false
		for _, o := range old.Sources {
			seen = seen || o == src
		}
		if !seen && len(old.Sources) < 20 {
			old.Sources = append(old.Sources, src)
		}
	}
	sort.Strings(old.Sources)
	if i.Until.After(old.Until) {
		old.Until = i.Until
	}
	if !i.From.IsZero() && (old.From.IsZero() || i.From.Before(old.From)) {
		old.From = i.From
	}
	if old.Note == "" {
		old.Note = i.Note
	}
	return false
}

// Remove takes one out, and reports whether it was there.
func (s *Set) Remove(id string) bool {
	i, ok := s.byID[id]
	if !ok {
		return false
	}
	delete(s.byID, id)
	delete(s.byVal[i.Kind], i.Value)
	return true
}

// All lists them: soonest to lapse first, then by value.
func (s *Set) All() []Indicator {
	out := make([]Indicator, 0, len(s.byID))
	for _, i := range s.byID {
		out = append(out, *i)
	}
	sort.Slice(out, func(a, b int) bool {
		if !out[a].Until.Equal(out[b].Until) {
			return out[a].Until.Before(out[b].Until)
		}
		if out[a].Kind != out[b].Kind {
			return out[a].Kind < out[b].Kind
		}
		return out[a].Value < out[b].Value
	})
	return out
}

// Hit is one indicator found in one event.
type Hit struct {
	Indicator Indicator
	// Seen is the value as the event carried it, and Field where.
	Seen  string
	Field string
}

// Match finds every indicator an event carries that covers the event's own
// time.
//
// Only in the typed observables, never in the message. The message is text
// written by whoever could reach the log, and matching inside it would let
// anybody raise a finding about anybody by getting a string logged.
func (s *Set) Match(e telemetry.Event) []Hit {
	if len(s.byID) == 0 || len(e.Observables) == 0 {
		return nil
	}
	var out []Hit
	seen := map[string]bool{}
	add := func(i *Indicator, o telemetry.Observable) {
		if i == nil || seen[i.ID] || !i.Covers(e.Time) {
			return
		}
		seen[i.ID] = true
		out = append(out, Hit{Indicator: *i, Seen: o.Value, Field: o.Name})
	}
	domain := func(host string, o telemetry.Observable) {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		// The domain itself and every parent of it, on label boundaries:
		// evil.example covers a.evil.example and not notevil.example.
		for host != "" {
			add(s.byVal[Domain][host], o)
			_, rest, more := strings.Cut(host, ".")
			if !more {
				break
			}
			host = rest
		}
	}
	for _, o := range e.Observables {
		v := strings.TrimSpace(o.Value)
		if v == "" || len(v) > MaxValue {
			continue
		}
		switch o.Kind {
		case telemetry.ObservableIP:
			if a, err := netip.ParseAddr(v); err == nil {
				add(s.byVal[IP][a.Unmap().String()], o)
			}
		case telemetry.ObservableDomain, telemetry.ObservableHostname:
			domain(v, o)
		case telemetry.ObservableURL:
			u, err := url.Parse(v)
			if err != nil || u.Host == "" {
				continue
			}
			u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
			u.Fragment, u.User = "", nil
			add(s.byVal[URL][u.String()], o)
			if a, aerr := netip.ParseAddr(u.Hostname()); aerr == nil {
				add(s.byVal[IP][a.Unmap().String()], o)
			} else {
				domain(u.Hostname(), o)
			}
		case telemetry.ObservableHash:
			add(s.byVal[Hash][strings.ToLower(v)], o)
		case telemetry.ObservableEmail:
			add(s.byVal[Email][strings.ToLower(v)], o)
		}
	}
	return out
}
