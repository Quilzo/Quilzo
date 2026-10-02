// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package travel keeps each person's recent sign-ins and says when a new one
// does not fit them: further from the last than anybody can travel in the
// time between, from a country they have not signed in from, or from a
// device they have not used.
//
// # The thresholds, and where they come from
//
// Impossible travel is a speed above 805 km/h — Okta's default, roughly a
// commercial flight — between two sign-ins more than 500 km apart. The
// distance floor is there because a city-level guess for a mobile or
// residential address is often a region out, and two guesses a region out
// in opposite directions, minutes apart, would otherwise be a flight.
//
// Microsoft's version learns for seven days before it alerts and ignores
// VPNs and places the organisation uses. Here a VPN network the
// organisation has declared is left out of every check (its exit is not
// where anybody is), and the signals say how much history they were judged
// against, so a rule can ask for a learned baseline before it acts.
//
// A new country is one not seen in the last twenty sign-ins, a new device
// one not seen in the last fifty — the look-backs Okta's behaviour
// detection uses — and neither is claimed until there are five sign-ins
// to compare with.
package travel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/geo"
)

// Thresholds, as above.
const (
	MaxKmH        = 805.0
	MinKm         = 500.0
	CountryLook   = 20
	DeviceLook    = 50
	Learning      = 5
	KeepPerPerson = 50
)

// SignIn is one successful sign-in.
type SignIn struct {
	At    time.Time `json:"at"`
	IP    string    `json:"ip,omitempty"`
	Place geo.Place `json:"place"`
	// Device is the kind of browser and system the request named — "Chrome
	// on Windows" — not the version, which changes with every update and
	// would make every person a new device each month (see DeviceClass).
	Device string `json:"device,omitempty"`
	// How is the way they signed in: token, passkey, sso.
	How string `json:"how,omitempty"`
	// ASN and Network are the autonomous system the address belongs to and
	// the name of whoever runs it; Anon says it is Tor or a hosting
	// provider, when that is known.
	ASN     uint32 `json:"asn,omitempty"`
	Network string `json:"network,omitempty"`
	Anon    string `json:"anon,omitempty"`
	// Signals, Risk and Score are what was judged of it, kept so a person
	// reading the history sees why it was treated as it was.
	Signals []string `json:"signals,omitempty"`
	Risk    string   `json:"risk,omitempty"`
	Score   float64  `json:"score,omitempty"`
}

// Signal is one way a sign-in does not fit.
type Signal struct {
	Kind string `json:"kind"` // impossible-travel, new-country, new-device
	// From and To are the two places, for travel; Km and KmH how far and
	// how fast; Minutes between them.
	From    geo.Place `json:"from,omitempty"`
	To      geo.Place `json:"to,omitempty"`
	Km      float64   `json:"km,omitempty"`
	KmH     float64   `json:"kmh,omitempty"`
	Minutes float64   `json:"minutes,omitempty"`
	// History is how many earlier sign-ins it was judged against.
	History int    `json:"history"`
	Detail  string `json:"detail"`
}

// Severity of each signal kind: what is physics or a known way in is
// high, a change of habit lower.
func (s Signal) Severity() string { return Severity(s.Kind) }

// Severity is a signal kind's weight.
func Severity(kind string) string {
	switch kind {
	case "impossible-travel", "anonymous-network", "session-moved":
		return "high"
	case "new-country", "new-network", "hosting-network", "dormant", "verification-failing":
		return "medium"
	}
	return "low"
}

// Level is how risky a sign-in is from its signals: the worst of them,
// one step higher when three or more agree, because several unfamiliar
// properties at once are what an attacker on somebody else's account
// looks like (the combination unfamiliar-sign-in-properties detections
// weigh, and the reason the LinkedIn model multiplies its features).
func Level(signals []Signal) string {
	rank := map[string]int{"": 0, "low": 1, "medium": 2, "high": 3}
	worst := 0
	for _, s := range signals {
		if r := rank[s.Severity()]; r > worst {
			worst = r
		}
	}
	if len(signals) >= 3 && worst < 3 {
		worst++
	}
	return []string{"none", "low", "medium", "high"}[worst]
}

// DeviceClass names the kind of browser and system a user agent says,
// without its version: "Chrome on Windows", "Safari on iPhone". Empty when
// there is no user agent; "Other" when it says nothing recognisable.
func DeviceClass(ua string) string {
	u := strings.ToLower(ua)
	if strings.TrimSpace(u) == "" {
		return ""
	}
	browser := "Other browser"
	switch {
	case strings.Contains(u, "edg/"):
		browser = "Edge"
	case strings.Contains(u, "opr/") || strings.Contains(u, "opera"):
		browser = "Opera"
	case strings.Contains(u, "firefox/") || strings.Contains(u, "fxios/"):
		browser = "Firefox"
	case strings.Contains(u, "chrome/") || strings.Contains(u, "crios/") || strings.Contains(u, "chromium"):
		browser = "Chrome"
	case strings.Contains(u, "safari/"):
		browser = "Safari"
	case strings.Contains(u, "curl/") || strings.Contains(u, "python") || strings.Contains(u, "go-http-client") || strings.Contains(u, "headless"):
		browser = "a script"
	}
	system := "another system"
	switch {
	case strings.Contains(u, "iphone"):
		system = "iPhone"
	case strings.Contains(u, "ipad"):
		system = "iPad"
	case strings.Contains(u, "android"):
		system = "Android"
	case strings.Contains(u, "windows"):
		system = "Windows"
	case strings.Contains(u, "mac os") || strings.Contains(u, "macintosh"):
		system = "macOS"
	case strings.Contains(u, "cros"):
		system = "ChromeOS"
	case strings.Contains(u, "linux"):
		system = "Linux"
	}
	return browser + " on " + system
}

// Device is DeviceClass, kept by its old name for callers.
func Device(userAgent string) string { return DeviceClass(userAgent) }

// Look-backs for the newer signals, as Okta's behaviour detection uses for
// IP and ASN; the dormant gap; and how much history an hour needs.
const (
	IPLook      = 50
	DormantGap  = 60 * 24 * time.Hour
	HourHistory = 20
)

// Assess says how a sign-in fits the ones before it, newest first.
func Assess(before []SignIn, cur SignIn) []Signal {
	var out []Signal
	n := len(before)
	// Travel: from the last sign-in whose place is a real one.
	if usable(cur.Place) {
		for _, prev := range before {
			if !usable(prev.Place) {
				continue
			}
			km := geo.Km(prev.Place, cur.Place)
			hours := cur.At.Sub(prev.At).Hours()
			kmh := math.Inf(1)
			if hours > 0 {
				kmh = km / hours
			}
			if km > MinKm && kmh > MaxKmH {
				s := Signal{Kind: "impossible-travel", From: prev.Place, To: cur.Place,
					Km: math.Round(km), Minutes: math.Round(cur.At.Sub(prev.At).Minutes()), History: n}
				if !math.IsInf(kmh, 1) {
					s.KmH = math.Round(kmh)
				}
				s.Detail = fmt.Sprintf("%s, %.0f km from %s %s earlier: %s", cur.Place, km, prev.Place,
					since(cur.At.Sub(prev.At)), speed(kmh))
				out = append(out, s)
			}
			break
		}
	}
	if n >= Learning && cur.Place.Country != "" && cur.Place.Kind != "vpn" {
		seen := false
		for i, prev := range before {
			if i >= CountryLook {
				break
			}
			if prev.Place.Country == cur.Place.Country {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, Signal{Kind: "new-country", To: cur.Place, History: n,
				Detail: fmt.Sprintf("the first sign-in from %s in the last %d", cur.Place.Country, min(n, CountryLook))})
		}
	}
	if cur.Anon == "tor" {
		out = append(out, Signal{Kind: "anonymous-network", History: n,
			Detail: "through Tor, which hides where anybody is"})
	}
	if cur.Anon == "hosting" && cur.Place.Kind != "vpn" && cur.Place.Kind != "office" {
		out = append(out, Signal{Kind: "hosting-network", History: n,
			Detail: fmt.Sprintf("from a hosting provider's network (%s), where phishing proxies and scripts run, not people", firstOf(cur.Network, "unnamed"))})
	}
	if n >= 1 && cur.At.Sub(before[0].At) > DormantGap {
		out = append(out, Signal{Kind: "dormant", History: n,
			Detail: fmt.Sprintf("the first sign-in in %s", since(cur.At.Sub(before[0].At)))})
	}
	if n >= Learning && cur.ASN != 0 && cur.Place.Kind == "" {
		seen := false
		for i, prev := range before {
			if i >= IPLook {
				break
			}
			if prev.ASN == cur.ASN {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, Signal{Kind: "new-network", History: n,
				Detail: fmt.Sprintf("a network provider not used in the last %d sign-ins: %s (AS%d)", min(n, IPLook), firstOf(cur.Network, "unnamed"), cur.ASN)})
		}
	}
	if n >= Learning && cur.IP != "" && cur.Place.Kind == "" {
		seen := false
		for i, prev := range before {
			if i >= IPLook {
				break
			}
			if prev.IP == cur.IP {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, Signal{Kind: "new-ip", History: n,
				Detail: fmt.Sprintf("an address not used in the last %d sign-ins", min(n, IPLook))})
		}
	}
	if n >= HourHistory {
		h := cur.At.UTC().Hour()
		near := false
		for _, prev := range before {
			d := prev.At.UTC().Hour() - h
			if d < 0 {
				d = -d
			}
			if d <= 1 || d >= 23 {
				near = true
				break
			}
		}
		if !near {
			out = append(out, Signal{Kind: "unusual-hour", History: n,
				Detail: fmt.Sprintf("at %02d:00 UTC, an hour this person has not signed in near", h)})
		}
	}
	if n >= Learning && cur.Device != "" {
		seen := false
		for i, prev := range before {
			if i >= DeviceLook {
				break
			}
			if prev.Device == cur.Device {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, Signal{Kind: "new-device", History: n,
				Detail: fmt.Sprintf("a browser and system not used in the last %d sign-ins", min(n, DeviceLook))})
		}
	}
	return out
}

func firstOf(v ...string) string {
	for _, x := range v {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

// usable is a place travel can be measured from: known, with coordinates,
// and not a VPN, whose exit is not where anybody is.
func usable(p geo.Place) bool {
	return p.HasCoordinates() && p.Kind != "vpn"
}

func since(d time.Duration) string {
	switch {
	case d < 2*time.Minute:
		return "moments"
	case d < 2*time.Hour:
		return fmt.Sprintf("%.0f minutes", d.Minutes())
	case d < 48*time.Hour:
		return fmt.Sprintf("%.0f hours", d.Hours())
	}
	return fmt.Sprintf("%.0f days", d.Hours()/24)
}

func speed(kmh float64) string {
	if math.IsInf(kmh, 1) || kmh > 100000 {
		return "no time at all to travel"
	}
	return fmt.Sprintf("%.0f km/h, faster than a plane", kmh)
}

// Keep is how long a sign-in is kept. Where somebody was, and from which
// address, is personal data: kept long enough to judge the next sign-in
// against and to look back over an incident, and no longer.
const Keep = 90 * 24 * time.Hour

// Store keeps the recent sign-ins, one small file per person, named by a
// hash of who they are so the listing does not say who signs in. One file
// per person rather than one for everybody, because a sign-in rewrites
// only its own person's history.
type Store struct {
	Dir   string
	Now   func() time.Time
	mu    sync.Mutex
	cache Stats
}

type personFile struct {
	Person  string   `json:"person"`
	SignIns []SignIn `json:"signins"`
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) path(person string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(person))))
	return filepath.Join(s.Dir, hex.EncodeToString(sum[:12])+".json")
}

func (s *Store) read(path string) (personFile, error) {
	var f personFile
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// kept drops what is past Keep, newest first already.
func (s *Store) kept(list []SignIn) []SignIn {
	cut := s.now().Add(-Keep)
	out := list[:0]
	for _, in := range list {
		if in.At.After(cut) {
			out = append(out, in)
		}
	}
	return out
}

// Record judges a sign-in against the person's history, then keeps it.
// Names compare without case, as an identity provider's do. A history that
// cannot be read is judged as empty and replaced, and the error returned:
// the sign-in still happened, and the next one has something to compare.
func (s *Store) Record(person string, in SignIn) ([]Signal, error) {
	j, err := s.Check(person, in)
	return j.Signals, err
}

// Judged is everything said of one sign-in.
type Judged struct {
	Signals []Signal
	Risk    string
	Score   float64
}

// Check is Record, returning the whole judgement: the signals, the level
// they come to, and the score.
func (s *Store) Check(person string, in SignIn) (Judged, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return Judged{}, err
	}
	path := s.path(person)
	f, readErr := s.read(path)
	before := s.kept(f.SignIns)
	signals := Assess(before, in)
	in.Score = Score(before, in, s.stats())
	in.Risk = Level(signals)
	for _, sg := range signals {
		in.Signals = append(in.Signals, sg.Kind)
	}
	list := append([]SignIn{in}, before...)
	if len(list) > KeepPerPerson {
		list = list[:KeepPerPerson]
	}
	j := Judged{Signals: signals, Risk: in.Risk, Score: in.Score}
	b, err := json.Marshal(personFile{Person: strings.ToLower(strings.TrimSpace(person)), SignIns: list})
	if err != nil {
		return j, err
	}
	if err := atomicfile.Write(path, b, 0o600); err != nil {
		return j, err
	}
	return j, readErr
}

// Recent is one person's sign-in.
type Recent struct {
	Person string
	SignIn
}

// Since lists sign-ins after t across everybody, newest first, and deletes
// the files of people with nothing left inside Keep.
func (s *Store) Since(t time.Time) ([]Recent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Recent
	for _, en := range entries {
		if en.IsDir() || !strings.HasSuffix(en.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.Dir, en.Name())
		f, err := s.read(path)
		if err != nil {
			continue
		}
		list := s.kept(f.SignIns)
		if len(list) == 0 {
			_ = os.Remove(path)
			continue
		}
		for _, in := range list {
			if in.At.After(t) {
				out = append(out, Recent{Person: f.Person, SignIn: in})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out, nil
}
