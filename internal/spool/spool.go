// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package spool is where events land before anything reasons about them.
//
// Append-only segments, partitioned by arrival, retained by two limits at
// once, and sealed with a digest cheap enough to compute on volume data.
// Nothing here is a database. A spool answers one question — what arrived
// between these two moments — and the design is entirely about the four ways
// that question is usually answered wrongly.
//
// # Partition by arrival, not by the timestamp in the event
//
// Every event carries two clocks: when the source says it happened, and when
// this program took delivery. Almost every store partitions by the first,
// because that is what an analyst asks about, and it is the wrong choice for
// a security store for a reason that has nothing to do with performance.
//
// The first clock belongs to whoever wrote the event. Set it a week forward
// and the record lands in a partition that has already been swept, indexed
// and reported on; set it a week back and it lands in one that retention has
// already dropped, or is about to. Either way the event is in the store and
// out of every window that would have looked at it — and nothing anywhere
// reports an error, because writing into a past partition is exactly what a
// late event legitimately does.
//
// The second clock is ours. It cannot be moved by the thing being recorded.
// So segments are cut on arrival, and the timestamp in the event is an
// ordinary field a query filters on. Both are kept; only one decides where
// the bytes go.
//
// # Two retention limits, because one is a promise you cannot keep
//
// "Ninety days" on its own is a disk that fills up. Volume is not flat — it
// spikes during exactly the incident whose evidence you needed — so an age
// limit alone means the store stops accepting writes at the worst possible
// moment, or silently starts dropping. A byte cap alone means a quiet month
// keeps two years and a noisy week keeps four days, and nobody can say what
// the store will answer for. Both are set, Oldest() says what the store
// currently covers, and that number is the honest answer to "how far back can
// we look", rather than the configured one.
//
// # Deleting is never a side effect
//
// Retention is two calls. Plan says what would go and what the store would
// then cover; Apply takes a plan and does it. A store that deletes while
// answering a query is one that deleted evidence during an investigation, and
// the investigation is the moment somebody is most likely to run a query and
// least likely to be watching the log. Holds pin segments against any plan,
// which is the same mechanism a legal hold needs and is worth having before
// anybody asks for one.
//
// # Integrity you can afford
//
// The audit log signs every record with Ed25519 and ML-DSA-65, which is right
// for decisions and unaffordable for a million events a day. Here a sealed
// segment gets one SHA-256 over its bytes. That is cheap enough to be
// unconditional, and anchoring those digests in the audit log — which is
// signed — gives the whole spool tamper-evidence at the cost of one hash per
// segment rather than two signatures per event.
package spool

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Defaults. Every one of them is a number somebody will want to change, and
// every one is stated here rather than discovered by reading behaviour.
const (
	// DefaultSegmentBytes rolls a segment at 64 MiB. Small enough that a
	// retention delete frees a useful amount, large enough that a busy day is
	// tens of files rather than thousands.
	DefaultSegmentBytes = 64 << 20
	// DefaultKeep is ninety days, which is what most frameworks ask for.
	DefaultKeep = 90 * 24 * time.Hour
	// DefaultCap is 16 GiB of events. Paired with DefaultKeep, never alone.
	DefaultCap = 16 << 30
	// MaxLine bounds one event, as everywhere else that reads telemetry.
	MaxLine = 1 << 20
)

// Options configure a spool.
type Options struct {
	// SegmentBytes is when to roll. A segment also rolls when the arrival day
	// changes, so retention can drop whole files on a day boundary.
	SegmentBytes int64
	// Keep is the age limit and Cap the size limit. Both apply.
	Keep time.Duration
	Cap  int64
	// Now is the clock, injectable so a test can age a store without
	// sleeping. Nil means time.Now.
	Now func() time.Time
}

func (o Options) withDefaults() Options {
	if o.SegmentBytes <= 0 {
		o.SegmentBytes = DefaultSegmentBytes
	}
	if o.Keep <= 0 {
		o.Keep = DefaultKeep
	}
	if o.Cap <= 0 {
		o.Cap = DefaultCap
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	return o
}

// Segment is one append-only file of events.
type Segment struct {
	Name string `json:"name"`
	// First and Last are arrival times, not event times. They are what Range
	// skips files on, and the distinction is the package's whole thesis.
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	// Earliest and Latest are the event times inside, kept so a query for a
	// period can skip a segment whose contents are entirely outside it
	// without reading it. Advisory: a source with a wrong clock widens these
	// and costs a read, which is the right way round.
	Earliest time.Time `json:"earliest"`
	Latest   time.Time `json:"latest"`

	Events int   `json:"events"`
	Bytes  int64 `json:"bytes"`
	// Digest is SHA-256 over the sealed file. Empty while the segment is
	// still open, because a digest of a file still being appended to is a
	// claim that stops being true a millisecond later.
	Digest string `json:"digest,omitempty"`
}

// Sealed reports whether the segment is closed and digested.
func (s Segment) Sealed() bool { return s.Digest != "" }

// Hold pins segments against retention.
type Hold struct {
	Name  string    `json:"name"`
	By    string    `json:"by"`
	At    time.Time `json:"at"`
	Until time.Time `json:"until"`
	// Why the hold exists. Required: a hold nobody can explain is one nobody
	// will ever dare lift, and a store that can never delete anything fails
	// its retention commitments as surely as one that deletes too early.
	Why string `json:"why"`
}

// Active reports whether a hold still applies.
func (h Hold) Active(now time.Time) bool {
	return h.Until.IsZero() || now.Before(h.Until)
}

// index is the spool's metadata, written atomically beside the segments.
type index struct {
	Segments []Segment `json:"segments"`
	Holds    []Hold    `json:"holds,omitempty"`
	// Late is a histogram of observed arrival delay, in log2 seconds. Kept
	// because the watermark has to be measured rather than configured; see
	// Watermark.
	Late map[int]int64 `json:"late,omitempty"`
	// Ahead counts events whose source clock ran ahead of ours. Counted
	// separately rather than folded into Late as a negative, because a fleet
	// running fast is an operational fact and averaging it into the arrival
	// delay hides both.
	Ahead int64 `json:"ahead,omitempty"`
}

// Spool is an open store.
type Spool struct {
	dir  string
	opt  Options
	idx  index
	open *os.File
	cur  int
}

// Open prepares a spool in dir, creating it if absent.
func Open(dir string, o Options) (*Spool, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("a spool needs a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, opt: o.withDefaults(), cur: -1}
	b, err := os.ReadFile(filepath.Join(dir, "index.json"))
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return nil, err
	default:
		if uerr := json.Unmarshal(b, &s.idx); uerr != nil {
			return nil, fmt.Errorf("%s/index.json is unreadable: %w", dir, uerr)
		}
	}
	if s.idx.Late == nil {
		s.idx.Late = map[int]int64{}
	}
	return s, nil
}

// Append writes one event and returns the segment it landed in.
//
// Received is stamped here when the caller left it zero, because the spool is
// the moment of delivery and nothing upstream is better placed to say so.
func (s *Spool) Append(e telemetry.Event) (string, error) {
	if e.Received.IsZero() {
		e.Received = s.opt.Now()
	}
	if err := e.Validate(); err != nil {
		return "", err
	}
	line, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	if len(line)+1 > MaxLine {
		return "", fmt.Errorf(
			"one event is %d bytes, over the %d-byte line limit; a source "+
				"that can write an unbounded record can fill the disk",
			len(line), MaxLine)
	}
	if err := s.ensure(e.Received); err != nil {
		return "", err
	}
	if _, err := s.open.Write(append(line, '\n')); err != nil {
		return "", err
	}

	seg := &s.idx.Segments[s.cur]
	seg.Events++
	seg.Bytes += int64(len(line)) + 1
	seg.Last = e.Received
	if seg.Earliest.IsZero() || e.Time.Before(seg.Earliest) {
		seg.Earliest = e.Time
	}
	if e.Time.After(seg.Latest) {
		seg.Latest = e.Time
	}
	s.observe(e.Lateness())
	return seg.Name, s.save()
}

// observe records one arrival delay in the histogram.
func (s *Spool) observe(d time.Duration) {
	if d < 0 {
		s.idx.Ahead++
		return
	}
	s.idx.Late[bucket(d)]++
}

// bucket is the log2 of a delay in seconds, floored at zero.
//
// Log-bucketed because the distribution spans six orders of magnitude — a
// local agent arrives in milliseconds, a cloud audit trail in fifteen minutes,
// a daily export in a day — and a linear histogram over that range is either
// useless at the bottom or enormous at the top.
func bucket(d time.Duration) int {
	secs := int64(d / time.Second)
	n := 0
	for secs > 0 {
		secs >>= 1
		n++
	}
	return n
}

// ensure opens or rolls the segment that an arrival at t belongs in.
func (s *Spool) ensure(at time.Time) error {
	if s.open != nil {
		seg := s.idx.Segments[s.cur]
		sameDay := seg.First.UTC().Format("20060102") ==
			at.UTC().Format("20060102")
		if sameDay && seg.Bytes < s.opt.SegmentBytes {
			return nil
		}
		if err := s.Seal(); err != nil {
			return err
		}
	}
	name := fmt.Sprintf("%s-%04d.jsonl", at.UTC().Format("20060102"),
		len(s.idx.Segments))
	f, err := os.OpenFile(filepath.Join(s.dir, name),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	s.open = f
	s.idx.Segments = append(s.idx.Segments,
		Segment{Name: name, First: at, Last: at})
	s.cur = len(s.idx.Segments) - 1
	return nil
}

// Seal closes the open segment and digests it.
func (s *Spool) Seal() error {
	if s.open == nil {
		return nil
	}
	if err := s.open.Sync(); err != nil {
		return err
	}
	if err := s.open.Close(); err != nil {
		return err
	}
	s.open = nil
	digest, err := digestOf(filepath.Join(s.dir, s.idx.Segments[s.cur].Name))
	if err != nil {
		return err
	}
	s.idx.Segments[s.cur].Digest = digest
	s.cur = -1
	return s.save()
}

// Close seals and releases the spool.
func (s *Spool) Close() error { return s.Seal() }

func digestOf(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Spool) save() error {
	b, err := json.MarshalIndent(s.idx, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(s.dir, "index.json"), b, 0o600)
}

// Segments returns what the spool holds, oldest arrival first.
func (s *Spool) Segments() []Segment {
	out := append([]Segment(nil), s.idx.Segments...)
	sort.Slice(out, func(i, j int) bool { return out[i].First.Before(out[j].First) })
	return out
}

// Oldest is the earliest arrival the spool can still answer for.
//
// The honest answer to "how far back can we look", which is not the same as
// the configured retention and is the number to put in a policy document.
func (s *Spool) Oldest() time.Time {
	var out time.Time
	for _, seg := range s.idx.Segments {
		if out.IsZero() || seg.First.Before(out) {
			out = seg.First
		}
	}
	return out
}

// Bytes is how much the spool currently holds.
func (s *Spool) Bytes() int64 {
	var n int64
	for _, seg := range s.idx.Segments {
		n += seg.Bytes
	}
	return n
}

// Events is how many events the spool holds.
func (s *Spool) Events() int {
	var n int
	for _, seg := range s.idx.Segments {
		n += seg.Events
	}
	return n
}

// Range calls fn for every event that arrived in [from, to).
//
// By arrival, because that is what the spool is ordered by and what it can
// answer without reading everything. A caller wanting a period of event time
// filters inside fn; the segment's Earliest and Latest let Range skip files
// that cannot contain anything in the period, which is the only place the
// source's clock is allowed to influence what gets read — and the worst a
// wrong clock can do there is cost a read.
func (s *Spool) Range(from, to time.Time, fn func(telemetry.Event) error) error {
	if s.open != nil {
		// Flushed, not sealed. A reader that missed the events written a
		// second ago is a reader that will report an incident as quiet.
		if err := s.open.Sync(); err != nil {
			return err
		}
	}
	for _, seg := range s.Segments() {
		if !to.IsZero() && !seg.First.Before(to) {
			continue
		}
		if !from.IsZero() && seg.Last.Before(from) {
			continue
		}
		if err := s.each(seg, func(e telemetry.Event) error {
			if !from.IsZero() && e.Received.Before(from) {
				return nil
			}
			if !to.IsZero() && !e.Received.Before(to) {
				return nil
			}
			return fn(e)
		}); err != nil {
			return err
		}
	}
	return nil
}

// During calls fn for every event whose own timestamp is in [from, to).
//
// The query an analyst means. Separate from Range so that the choice between
// the two clocks is made at the call site by somebody who knows which one
// their question is about, rather than by a default nobody remembers.
func (s *Spool) During(from, to time.Time, fn func(telemetry.Event) error) error {
	for _, seg := range s.Segments() {
		if !to.IsZero() && !seg.Earliest.IsZero() && !seg.Earliest.Before(to) {
			continue
		}
		if !from.IsZero() && !seg.Latest.IsZero() && seg.Latest.Before(from) {
			continue
		}
		if err := s.each(seg, func(e telemetry.Event) error {
			if !from.IsZero() && e.Time.Before(from) {
				return nil
			}
			if !to.IsZero() && !e.Time.Before(to) {
				return nil
			}
			return fn(e)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Spool) each(seg Segment, fn func(telemetry.Event) error) error {
	f, err := os.Open(filepath.Join(s.dir, seg.Name))
	if os.IsNotExist(err) {
		return fmt.Errorf(
			"%s is in the index and not on disk. The spool is reporting "+
				"coverage it does not have", seg.Name)
	}
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLine)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var e telemetry.Event
		if uerr := json.Unmarshal([]byte(text), &e); uerr != nil {
			return fmt.Errorf("%s line %d: %w", seg.Name, line, uerr)
		}
		if ferr := fn(e); ferr != nil {
			return ferr
		}
	}
	return sc.Err()
}

// Verify recomputes every sealed segment's digest and names what changed.
//
// An open segment is skipped rather than reported: it is still being appended
// to and has no digest to check against, which is a fact about when Verify
// ran and not a finding.
func (s *Spool) Verify() ([]string, error) {
	var bad []string
	for _, seg := range s.Segments() {
		if !seg.Sealed() {
			continue
		}
		got, err := digestOf(filepath.Join(s.dir, seg.Name))
		if os.IsNotExist(err) {
			bad = append(bad, seg.Name+" is gone")
			continue
		}
		if err != nil {
			return nil, err
		}
		if got != seg.Digest {
			bad = append(bad, seg.Name+" does not match its digest")
		}
	}
	return bad, nil
}

// Anchor returns the sealed segments' digests, for recording somewhere signed.
//
// The spool does not reach into the audit log itself. Keeping the dependency
// pointing one way means a store that fills up cannot stall the log that
// records who did what, and the caller that wants tamper-evidence over volume
// data writes one audit record per seal.
func (s *Spool) Anchor() map[string]string {
	out := map[string]string{}
	for _, seg := range s.idx.Segments {
		if seg.Sealed() {
			out[seg.Name] = seg.Digest
		}
	}
	return out
}
