// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package analytics counts what visitors do on the published site, without a
// script, a cookie or a stored address.
//
// # How, and what it costs
//
// Every analytics product asks the page to run a script that reports home.
// That is a script from somewhere else running on every page, a cookie
// banner, and a dataset of people. This counts at the server instead, from
// the requests the site was already answering.
//
// A visitor is a hash of a daily random salt, the address and the browser's
// user agent — the approach Plausible documented. The salt is generated in
// memory, never written down, and replaced at midnight, so the hash cannot be
// reversed, cannot be joined across days, and is gone when the process stops.
// What is written to disk is totals: views and visitors per page per day,
// referring sites, and conversions. Nothing that identifies anybody.
//
// The honest limits, said on the screen too:
//
//   - A visitor who changes network or browser in a day counts twice; two
//     people behind one address with the same browser count once.
//   - This site prefetches the page a reader is about to open (see
//     speculation.go). A prefetched page is shown without a second request,
//     so the server never learns it was viewed. Prefetches are counted
//     separately rather than guessed into views.
//   - After a restart the day's visitor set starts empty, so a visitor who
//     returns later that day is counted again.
//
// Crawlers are not visitors: a user agent that says it is a bot, a library
// or a monitor is not counted, and neither is one that sends none.
package analytics

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/quilzo/quilzo/internal/clientip"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Bounds on what one day holds in memory and on disk. A site with more
// distinct pages than this in a day records the rest as "(other)", and a
// flood of fabricated referrers cannot grow the file past its cap.
const (
	MaxPaths     = 2000
	MaxReferrers = 500
	MaxVisitors  = 200_000
	MaxGoals     = 200
	Other        = "(other)"
)

// Page is one path's day.
type Page struct {
	Views    int `json:"views"`
	Visitors int `json:"visitors"`
}

// Day is one day's totals, as written to disk.
type Day struct {
	Date      string          `json:"date"`
	Views     int             `json:"views"`
	Visitors  int             `json:"visitors"`
	Prefetch  int             `json:"prefetched"`
	Pages     map[string]Page `json:"pages"`
	Referrers map[string]int  `json:"referrers"`
	// Goals are conversions: how many distinct visitors reached each.
	Goals map[string]int `json:"goals"`
}

func newDay(date string) Day {
	return Day{Date: date, Pages: map[string]Page{}, Referrers: map[string]int{},
		Goals: map[string]int{}}
}

// Counter records a day and writes it out.
type Counter struct {
	dir string
	now func() time.Time

	mu    sync.Mutex
	day   Day
	salt  []byte
	seen  map[uint64]bool            // visitors today
	pages map[string]map[uint64]bool // visitors per page today
	goals map[string]map[uint64]bool // visitors per goal today
	dirty bool
}

// Open starts counting into dir, carrying on from today's file if there is
// one.
func Open(dir string, now func() time.Time) (*Counter, error) {
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	c := &Counter{dir: dir, now: now}
	c.reset(now().UTC().Format("2006-01-02"))
	if b, err := os.ReadFile(c.path(c.day.Date)); err == nil {
		var d Day
		if json.Unmarshal(b, &d) == nil && d.Date == c.day.Date {
			fill(&d)
			c.day = d
		}
	}
	return c, nil
}

func fill(d *Day) {
	if d.Pages == nil {
		d.Pages = map[string]Page{}
	}
	if d.Referrers == nil {
		d.Referrers = map[string]int{}
	}
	if d.Goals == nil {
		d.Goals = map[string]int{}
	}
}

func (c *Counter) reset(date string) {
	c.day = newDay(date)
	c.salt = make([]byte, 32)
	if _, err := rand.Read(c.salt); err != nil {
		panic("analytics: no randomness for the daily salt")
	}
	c.seen = map[uint64]bool{}
	c.pages = map[string]map[uint64]bool{}
	c.goals = map[string]map[uint64]bool{}
}

func (c *Counter) path(date string) string { return filepath.Join(c.dir, date+".json") }

// roll moves to a new day, writing the old one first. Called with the lock.
func (c *Counter) roll() {
	date := c.now().UTC().Format("2006-01-02")
	if date == c.day.Date {
		return
	}
	if c.dirty {
		_ = c.write()
	}
	c.reset(date)
}

// visitor is the day's hash for a request.
func (c *Counter) visitor(r *http.Request) uint64 {
	host := clientip.AddrFrom(r)
	h := sha256.New()
	h.Write(c.salt)
	h.Write([]byte(host))
	h.Write([]byte{0})
	h.Write([]byte(r.UserAgent()))
	return binary.BigEndian.Uint64(h.Sum(nil)[:8])
}

var reBot = regexp.MustCompile(`(?i)bot|crawl|spider|slurp|scrape|fetch|preview|monitor|` +
	`uptime|headless|curl|wget|python|go-http|java/|okhttp|axios|node-fetch|libwww|httpclient`)

// Human reports whether a request looks like a person's browser.
func Human(r *http.Request) bool {
	ua := r.UserAgent()
	return ua != "" && !reBot.MatchString(ua)
}

// Prefetch reports whether the browser is fetching ahead rather than showing.
func Prefetch(r *http.Request) bool {
	p := strings.ToLower(r.Header.Get("Sec-Purpose") + " " + r.Header.Get("Purpose"))
	return strings.Contains(p, "prefetch") || strings.Contains(p, "prerender")
}

// Visit counts one page view.
func (c *Counter) Visit(r *http.Request, path string) {
	if r.Method != http.MethodGet || !Human(r) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roll()
	c.dirty = true
	if Prefetch(r) {
		c.day.Prefetch++
		return
	}
	v := c.visitor(r)
	c.day.Views++
	if !c.seen[v] && len(c.seen) < MaxVisitors {
		c.seen[v] = true
		c.day.Visitors++
	}
	if _, known := c.day.Pages[path]; !known && len(c.day.Pages) >= MaxPaths {
		path = Other
	}
	pg := c.day.Pages[path]
	pg.Views++
	set := c.pages[path]
	if set == nil {
		set = map[uint64]bool{}
		c.pages[path] = set
	}
	if !set[v] && len(set) < MaxVisitors {
		set[v] = true
		pg.Visitors++
	}
	c.day.Pages[path] = pg
	if ref := referrer(r); ref != "" {
		if _, known := c.day.Referrers[ref]; !known && len(c.day.Referrers) >= MaxReferrers {
			ref = Other
		}
		c.day.Referrers[ref]++
	}
}

// referrer is where a visitor came from: a campaign's utm_source when the
// link carried one, otherwise the referring host when it is another site.
func referrer(r *http.Request) string {
	if src := strings.TrimSpace(r.URL.Query().Get("utm_source")); src != "" {
		return clean(src)
	}
	ref := r.Referer()
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if own, _, err := net.SplitHostPort(r.Host); (err == nil && strings.EqualFold(own, host)) ||
		strings.EqualFold(r.Host, host) {
		return ""
	}
	return clean(host)
}

// clean bounds a label that came from a request.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// Convert records that a visitor reached a goal: sent a form, asked a
// chatbot, opened a page an owner marked. Counted once per visitor per day.
func (c *Counter) Convert(r *http.Request, goal string) {
	if !Human(r) || Prefetch(r) {
		return
	}
	goal = clean(goal)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roll()
	c.dirty = true
	if _, known := c.day.Goals[goal]; !known && len(c.day.Goals) >= MaxGoals {
		goal = Other
	}
	v := c.visitor(r)
	set := c.goals[goal]
	if set == nil {
		set = map[uint64]bool{}
		c.goals[goal] = set
	}
	if set[v] {
		return
	}
	set[v] = true
	c.day.Goals[goal]++
}

// Today is a copy of the day so far.
func (c *Counter) Today() Day {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roll()
	b, _ := json.Marshal(c.day)
	var d Day
	_ = json.Unmarshal(b, &d)
	fill(&d)
	return d
}

// Flush writes today's totals.
func (c *Counter) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roll()
	if !c.dirty {
		return nil
	}
	return c.write()
}

func (c *Counter) write() error {
	b, err := json.Marshal(c.day)
	if err != nil {
		return err
	}
	if err := atomicfile.Write(c.path(c.day.Date), b, 0o600); err != nil {
		return err
	}
	c.dirty = false
	return nil
}

// Read returns up to days of totals ending today, oldest first, with a zero
// day for any day nothing was recorded.
func Read(dir string, days int, now time.Time) ([]Day, error) {
	if days <= 0 || days > 400 {
		return nil, fmt.Errorf("between 1 and 400 days")
	}
	var out []Day
	for i := days - 1; i >= 0; i-- {
		date := now.UTC().AddDate(0, 0, -i).Format("2006-01-02")
		d := newDay(date)
		b, err := os.ReadFile(filepath.Join(dir, date+".json"))
		if err == nil {
			var got Day
			if json.Unmarshal(b, &got) == nil && got.Date == date {
				fill(&got)
				d = got
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// Ranked is a name and a count, for a table.
type Ranked struct {
	Name  string
	Count int
	Extra int
}

// Summary is several days added up for a screen.
type Summary struct {
	Days      []Day
	Views     int
	Visitors  int
	Prefetch  int
	Pages     []Ranked
	Referrers []Ranked
	Goals     []Ranked
}

// Summarise adds days up. Visitors across days are a sum of daily visitors,
// because the daily salt makes them impossible to join — which is the point.
func Summarise(days []Day) Summary {
	s := Summary{Days: days}
	pages, refs, goals := map[string]*Ranked{}, map[string]int{}, map[string]int{}
	for _, d := range days {
		s.Views += d.Views
		s.Visitors += d.Visitors
		s.Prefetch += d.Prefetch
		for p, v := range d.Pages {
			r := pages[p]
			if r == nil {
				r = &Ranked{Name: p}
				pages[p] = r
			}
			r.Count += v.Views
			r.Extra += v.Visitors
		}
		for k, v := range d.Referrers {
			refs[k] += v
		}
		for k, v := range d.Goals {
			goals[k] += v
		}
	}
	for _, r := range pages {
		s.Pages = append(s.Pages, *r)
	}
	for k, v := range refs {
		s.Referrers = append(s.Referrers, Ranked{Name: k, Count: v})
	}
	for k, v := range goals {
		s.Goals = append(s.Goals, Ranked{Name: k, Count: v})
	}
	for _, l := range [][]Ranked{s.Pages, s.Referrers, s.Goals} {
		sort.Slice(l, func(i, j int) bool {
			if l[i].Count != l[j].Count {
				return l[i].Count > l[j].Count
			}
			return l[i].Name < l[j].Name
		})
	}
	return s
}

// Bucket assigns a request to one of several weighted arms, stably for the
// day and with nothing stored: the daily visitor hash, keyed by the
// experiment so that two experiments do not split the same visitors the same
// way. Returns 0 — the first arm — for anything that is not a person, so a
// crawler always sees the control.
func (c *Counter) Bucket(r *http.Request, key string, weights []int) int {
	total := 0
	for _, w := range weights {
		if w > 0 {
			total += w
		}
	}
	if total == 0 || !Human(r) {
		return 0
	}
	c.mu.Lock()
	c.roll()
	salt := c.salt
	c.mu.Unlock()
	host := clientip.AddrFrom(r)
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(host))
	h.Write([]byte{0})
	h.Write([]byte(r.UserAgent()))
	h.Write([]byte{0})
	h.Write([]byte(key))
	n := int(binary.BigEndian.Uint64(h.Sum(nil)[:8]) % uint64(total))
	for i, w := range weights {
		if w <= 0 {
			continue
		}
		if n < w {
			return i
		}
		n -= w
	}
	return 0
}

// Reached reports whether this request's visitor has already reached a goal
// today. An experiment attributes a conversion only to a visitor it showed a
// variant to; one who converts without ever seeing the page would otherwise
// count as a win for whichever arm the hash names. After a restart the day's
// sets are empty, so a conversion is missed rather than invented.
func (c *Counter) Reached(r *http.Request, goal string) bool {
	if !Human(r) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roll()
	set := c.goals[clean(goal)]
	return set != nil && set[c.visitor(r)]
}
