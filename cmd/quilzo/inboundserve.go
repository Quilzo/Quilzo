// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/automate"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/inbound"
	"github.com/quilzo/quilzo/internal/oidc"
	"github.com/quilzo/quilzo/internal/source"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/ssf"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Events pushed to the server, the moment they happen.
//
// A feed's endpoint is /feeds/NAME on the admin. What arrives is proved
// (internal/inbound, internal/ssf), stored in the event store like anything
// collected, read by the rules at once, and — when it says something a rule
// can act on — put to the automations as a signal. See internal/inbound for
// how each kind proves where it came from.

// spoolMu is the server's one way to the event store. Everything in this
// process that writes there takes it, because two handles on one store each
// keep their own index, and whichever saves last would lose the other's
// segments.
var spoolMu sync.Mutex

// withSpool opens the store, does fn and lets the store go without sealing
// the segment, so the next writer adds to it rather than starting another.
func withSpool(root string, fn func(*spool.Spool) error) error {
	spoolMu.Lock()
	defer spoolMu.Unlock()
	return useSpool(root, fn)
}

func useSpool(root string, fn func(*spool.Spool) error) error {
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		return err
	}
	ferr := fn(sp)
	if rerr := sp.Release(); ferr == nil {
		ferr = rerr
	}
	return ferr
}

// detectInServer runs the rules over what has arrived and gives what they
// raise to the automations. A site with no rules has nothing to run, which
// is not a failure here; anything else that stops the pass is recorded.
func detectInServer(root string, sp *spool.Spool) {
	caller := &Caller{Name: "detect-on-arrival", Kind: audit.KindService, Verified: true}
	sum, err := detectPass(root, "", 0, caller, sp)
	if errors.Is(err, errNoRules) {
		return
	}
	if err != nil {
		record(root, audit.Record{Action: "detect.run", Resource: "/findings", Outcome: audit.Failure,
			Principal: caller.Name, Kind: caller.Kind, Verified: true,
			Detail: map[string]string{"error": onOneLine(err.Error())}})
		return
	}
	automateFindings(root, sum.New)
}

// -- feeds, kept --------------------------------------------------------------

func inboundDir(root string) string        { return filepath.Join(root, "inbound") }
func feedsPath(root string) string         { return filepath.Join(inboundDir(root), "feeds.json") }
func feedStatusPath(root string) string    { return filepath.Join(inboundDir(root), "status.json") }
func feedSecretName(name string) string    { return "inbound-" + name }
func feedSourceName(f inbound.Feed) string { return "feed/" + f.Name }

var feedsMu sync.Mutex

func loadFeeds(root string) (map[string]inbound.Feed, error) {
	out := map[string]inbound.Feed{}
	b, err := os.ReadFile(feedsPath(root))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s is unreadable: %w", feedsPath(root), err)
	}
	return out, nil
}

func saveFeeds(root string, m map[string]inbound.Feed) error {
	if err := os.MkdirAll(inboundDir(root), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(feedsPath(root), b, 0o600)
}

// changeFeed reads, changes and writes one feed under the lock.
func changeFeed(root, name string, fn func(*inbound.Feed) error) error {
	feedsMu.Lock()
	defer feedsMu.Unlock()
	m, err := loadFeeds(root)
	if err != nil {
		return err
	}
	f, ok := m[name]
	if !ok {
		return fmt.Errorf("there is no feed %q (quilzo inbound list)", name)
	}
	if err := fn(&f); err != nil {
		return err
	}
	m[name] = f
	return saveFeeds(root, m)
}

// inboundStatus is what a feed has done, for the screen and the command.
type inboundStatus struct {
	Deliveries int         `json:"deliveries"`
	Records    int         `json:"records"`
	Stored     int         `json:"stored"`
	Known      int         `json:"known"`
	Missed     int         `json:"missed"`
	Field      string      `json:"field,omitempty"`
	Signals    int         `json:"signals"`
	Refused    int         `json:"refused"`
	LastAt     time.Time   `json:"last_at,omitempty"`
	LastRefuse time.Time   `json:"last_refused,omitempty"`
	Why        string      `json:"why,omitempty"`
	Error      string      `json:"error,omitempty"`
	Seen       []string    `json:"seen,omitempty"`
	Recent     []signalRow `json:"recent,omitempty"`
}

// signalRow is one signal as the screen lists it.
type signalRow struct {
	At       time.Time `json:"at"`
	Type     string    `json:"type"`
	Person   string    `json:"person"`
	Severity string    `json:"severity"`
	Reason   string    `json:"reason,omitempty"`
}

func loadFeedStatus(root string) (map[string]*inboundStatus, error) {
	out := map[string]*inboundStatus{}
	b, err := os.ReadFile(feedStatusPath(root))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s is unreadable: %w", feedStatusPath(root), err)
	}
	return out, nil
}

// -- the endpoint -------------------------------------------------------------

// inboundServer answers /feeds/NAME.
type inboundServer struct {
	root string
	now  func() time.Time
	seen inbound.Seen
	// keyClient reads a transmitter's keys.
	keyClient *fetch.Client

	mu        sync.Mutex
	status    map[string]*inboundStatus
	receivers map[string]cachedReceiver
	queue     []pushed
	signals   []automate.Event
	rate      map[string]*rateWindow
	work      chan struct{}
	dirty     bool
	// fresh is that events were stored since the rules last ran, by the
	// worker or by a delivery that found the store free.
	fresh bool
}

type cachedReceiver struct {
	key string
	r   *ssf.Receiver
}

// pushed is one delivery waiting for the store.
type pushed struct {
	feed inbound.Feed
	docs []any
	set  *ssf.SET
	at   time.Time
}

type rateWindow struct {
	start time.Time
	n     int
}

// feedRate is how many deliveries a feed may make in a minute. Okta's cap
// is 400,000 events a day across every hook, a few a second; this is far
// above anything legitimate and far below what fills a disk.
const feedRate = 3000

// queueCap bounds what waits in memory while the store is busy.
const queueCap = 10_000

func newInboundServer(root string) *inboundServer {
	c := fetch.New()
	c.Purpose = "signals"
	c.UserAgent = "quilzo/1 (+shared signals receiver)"
	s := &inboundServer{root: root, now: time.Now, keyClient: c, receivers: map[string]cachedReceiver{},
		rate: map[string]*rateWindow{}, work: make(chan struct{}, 1)}
	if st, err := loadFeedStatus(root); err == nil {
		s.status = st
	} else {
		s.status = map[string]*inboundStatus{}
	}
	return s
}

// run is the worker: it takes what waits, stores it, runs the rules and the
// automations, and writes the status. It stops with ctx.
func (s *inboundServer) run(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			s.process()
			s.flush()
			return
		case <-s.work:
			// A burst arrives as several deliveries; one pass takes them all.
			select {
			case <-ctx.Done():
			case <-time.After(300 * time.Millisecond):
			}
			s.process()
			s.flush()
		case <-tick.C:
			s.flush()
		}
	}
}

func (s *inboundServer) poke() {
	select {
	case s.work <- struct{}{}:
	default:
	}
}

// process stores what waits, runs the rules over it, then the automations.
func (s *inboundServer) process() {
	err := withSpool(s.root, func(sp *spool.Spool) error {
		s.drain(sp)
		s.mu.Lock()
		fresh := s.fresh
		s.fresh = false
		s.mu.Unlock()
		if fresh {
			detectInServer(s.root, sp)
		}
		return nil
	})
	if err != nil {
		record(s.root, audit.Record{Action: "inbound.store", Resource: "/feeds", Outcome: audit.Failure,
			Principal: automateBy, Kind: audit.KindService, Verified: true,
			Detail: map[string]string{"error": onOneLine(err.Error())}})
	}
	s.mu.Lock()
	sigs := s.signals
	s.signals = nil
	s.mu.Unlock()
	if len(sigs) == 0 {
		return
	}
	engine := automationEngine(s.root)
	for _, ev := range sigs {
		_, _ = engine.Handle(ev)
	}
}

// drain writes what waits into sp, under spoolMu, and reports how many
// events it stored.
func (s *inboundServer) drain(sp *spool.Spool) int {
	s.mu.Lock()
	q := s.queue
	s.queue = nil
	s.mu.Unlock()
	if len(q) == 0 {
		return 0
	}
	aliases, _ := loadAliases(s.root)
	if aliases == nil {
		aliases = map[string]alias{}
	}
	stored, learned := 0, false
	for _, p := range q {
		n, l := s.store(sp, p, aliases)
		stored += n
		learned = learned || l
	}
	if learned {
		_ = saveAliases(s.root, aliases)
	}
	if stored > 0 {
		s.mu.Lock()
		s.fresh = true
		s.mu.Unlock()
	}
	return stored
}

// store maps one delivery into events and appends them, and turns what it
// says into signals for the automations.
func (s *inboundServer) store(sp *spool.Spool, p pushed, aliases map[string]alias) (int, bool) {
	s.mu.Lock()
	st := s.statusOf(p.feed.Name)
	s.mu.Unlock()
	var events []telemetry.Event
	var sigs []automate.Event
	learned := false
	switch {
	case p.set != nil:
		e, sig := setEvent(p.feed, p.set, aliases, p.at)
		events = append(events, e)
		if sig != nil {
			sigs = append(sigs, *sig)
		}
	default:
		src, err := s.mapping(p.feed)
		if err != nil {
			s.mu.Lock()
			st.Error = err.Error()
			s.dirty = true
			s.mu.Unlock()
			return 0, false
		}
		cs := collectStatus{Seen: st.Seen}
		events = mapRecords(src, p.docs, &cs, aliases, p.at)
		learned = cs.learned
		s.mu.Lock()
		st.Seen, st.Records, st.Known, st.Missed = cs.Seen, st.Records+cs.Records, st.Known+cs.Known, st.Missed+cs.Missed
		if cs.Field != "" {
			st.Field = cs.Field
		}
		s.mu.Unlock()
		if p.feed.Kind == inbound.Okta {
			for _, d := range p.docs {
				m, _ := d.(map[string]any)
				if sig := oktaSignalEvent(p.feed, m, p.at); sig != nil {
					sigs = append(sigs, *sig)
				}
			}
		}
	}
	stored := 0
	var serr error
	for _, e := range events {
		if _, err := sp.Append(e); err != nil {
			serr = err
			break
		}
		stored++
	}
	s.mu.Lock()
	st.Stored += stored
	if serr != nil {
		st.Error = serr.Error()
	} else {
		st.Error = ""
	}
	for _, sig := range sigs {
		st.Signals++
		st.Recent = append([]signalRow{{At: p.at, Type: sig.Fields["type"], Person: sig.Subject,
			Severity: sig.Fields["severity"], Reason: sig.Fields["reason"]}}, st.Recent...)
		if len(st.Recent) > 50 {
			st.Recent = st.Recent[:50]
		}
	}
	s.signals = append(s.signals, sigs...)
	s.dirty = true
	s.mu.Unlock()
	return stored, learned
}

// mapping is the source mapping a feed's records go through.
func (s *inboundServer) mapping(f inbound.Feed) (source.Source, error) {
	name := f.Mapping
	if f.Kind == inbound.Okta {
		name = "okta/system"
	}
	return findSource(s.root, name)
}

func (s *inboundServer) statusOf(name string) *inboundStatus {
	st := s.status[name]
	if st == nil {
		st = &inboundStatus{}
		s.status[name] = st
	}
	return st
}

func (s *inboundServer) flush() {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return
	}
	b, err := json.MarshalIndent(s.status, "", " ")
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return
	}
	if os.MkdirAll(inboundDir(s.root), 0o700) == nil {
		_ = atomicfile.Write(feedStatusPath(s.root), b, 0o600)
	}
}

// refused counts a delivery that did not prove itself. Not written to the
// audit log one by one: whoever is failing would be choosing how fast it
// grows. The count and the last reason are on the feed's status.
func (s *inboundServer) refused(name, why string) {
	s.mu.Lock()
	st := s.statusOf(name)
	st.Refused++
	st.LastRefuse = s.now().UTC()
	st.Why = why
	s.dirty = true
	s.mu.Unlock()
}

func (s *inboundServer) allow(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	w := s.rate[name]
	if w == nil || now.Sub(w.start) >= time.Minute {
		w = &rateWindow{start: now}
		s.rate[name] = w
	}
	w.n++
	return w.n <= feedRate
}

// accept queues a delivery and stores it now if the store is free.
func (s *inboundServer) accept(p pushed) error {
	s.mu.Lock()
	if len(s.queue) >= queueCap {
		s.mu.Unlock()
		return errors.New("busy")
	}
	s.queue = append(s.queue, p)
	st := s.statusOf(p.feed.Name)
	st.Deliveries++
	st.LastAt = p.at
	s.dirty = true
	s.mu.Unlock()
	// Written before the answer when nothing else holds the store, so a
	// sender told "received" was; otherwise right after whoever holds it.
	if spoolMu.TryLock() {
		_ = useSpool(s.root, func(sp *spool.Spool) error {
			s.drain(sp)
			return nil
		})
		spoolMu.Unlock()
	}
	s.poke()
	return nil
}

func (s *inboundServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	name := strings.TrimPrefix(r.URL.Path, "/feeds/")
	if !inbound.ValidName(name) {
		http.NotFound(w, r)
		return
	}
	feeds, err := loadFeeds(s.root)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	f, ok := feeds[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if f.Off {
		http.Error(w, "this feed is switched off", http.StatusServiceUnavailable)
		return
	}
	if !s.allow(name) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many deliveries", http.StatusTooManyRequests)
		return
	}
	limit := int64(1 << 20)
	if f.Kind == inbound.SSF {
		limit = ssf.MaxToken
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		http.Error(w, "the body is too large", http.StatusRequestEntityTooLarge)
		return
	}
	switch f.Kind {
	case inbound.Okta:
		s.okta(w, r, f, body)
	case inbound.Webhook, inbound.GitHub:
		s.webhook(w, r, f, body)
	case inbound.SSF:
		s.shared(w, r, f, body)
	default:
		http.NotFound(w, r)
	}
}

func (s *inboundServer) okta(w http.ResponseWriter, r *http.Request, f inbound.Feed, body []byte) {
	if !inbound.StaticMatches(inbound.BearerOrRaw(r.Header.Get("Authorization")), f.TokenHash) {
		s.refused(f.Name, "the Authorization header does not hold this feed's secret")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		b, ok := inbound.OktaChallenge(r)
		if !ok {
			http.Error(w, "a GET here is Okta's verification, with its challenge header", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	case http.MethodPost:
		d, err := inbound.ParseOkta(body)
		if err != nil {
			s.refused(f.Name, err.Error())
			http.Error(w, "not an event hook delivery", http.StatusBadRequest)
			return
		}
		if d.EventID != "" && !s.seen.First(f.Name+":"+d.EventID, s.now()) {
			w.WriteHeader(http.StatusOK)
			return
		}
		docs := make([]any, 0, len(d.Data.Events))
		for _, e := range d.Data.Events {
			docs = append(docs, e)
		}
		if err := s.accept(pushed{feed: f, docs: docs, at: s.now().UTC()}); err != nil {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
	}
}

func (s *inboundServer) webhook(w http.ResponseWriter, r *http.Request, f inbound.Feed, body []byte) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	secrets, err := loadSecrets(s.root)
	secret := secrets[f.Secret]
	if err != nil || secret == "" {
		http.Error(w, "this feed has no secret to check against", http.StatusServiceUnavailable)
		return
	}
	var id string
	if f.Kind == inbound.GitHub {
		id, err = inbound.VerifyGitHub(r.Header, body, secret)
	} else {
		id, err = inbound.VerifyStandard(r.Header, body, secret, s.now())
	}
	if err != nil {
		s.refused(f.Name, err.Error())
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !s.seen.First(f.Name+":"+id, s.now()) {
		w.WriteHeader(http.StatusOK)
		return
	}
	docs, err := inbound.Records(body)
	if err != nil {
		s.refused(f.Name, err.Error())
		http.Error(w, "the body is not JSON records", http.StatusBadRequest)
		return
	}
	if err := s.accept(pushed{feed: f, docs: docs, at: s.now().UTC()}); err != nil {
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func setError(w http.ResponseWriter, status int, e *ssf.Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(e)
}

func (s *inboundServer) shared(w http.ResponseWriter, r *http.Request, f inbound.Feed, body []byte) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if f.TokenHash != "" && !inbound.StaticMatches(inbound.BearerOrRaw(r.Header.Get("Authorization")), f.TokenHash) {
		s.refused(f.Name, "the Authorization header does not hold this stream's secret")
		setError(w, http.StatusUnauthorized, &ssf.Error{Code: "authentication_failed", Description: "the push did not carry this stream's authorization"})
		return
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if ct != "application/secevent+jwt" && ct != "application/jwt" {
		setError(w, http.StatusBadRequest, &ssf.Error{Code: "invalid_request", Description: "a push is a security event token, content type application/secevent+jwt"})
		return
	}
	rcv, err := s.receiver(f)
	if err != nil {
		setError(w, http.StatusServiceUnavailable, &ssf.Error{Code: "access_denied", Description: "this receiver cannot verify events right now"})
		return
	}
	set, err := rcv.Verify(string(body))
	if err != nil {
		var e *ssf.Error
		if !errors.As(err, &e) {
			e = &ssf.Error{Code: "invalid_request", Description: err.Error()}
		}
		s.refused(f.Name, e.Error())
		setError(w, http.StatusBadRequest, e)
		return
	}
	if !s.seen.First(f.Name+":"+set.JTI, s.now()) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch set.Short {
	case "verification":
		state, _ := set.Claims["state"].(string)
		if set.Subject.ID == f.StreamID || f.StreamID == "" {
			_ = changeFeed(s.root, f.Name, func(x *inbound.Feed) error {
				if x.State != "" && state != "" && inbound.StaticMatches(state, x.State) {
					x.Verified, x.State = s.now().UTC(), ""
				}
				return nil
			})
		}
		w.WriteHeader(http.StatusAccepted)
		return
	case "stream-updated":
		status, _ := set.Claims["status"].(string)
		_ = changeFeed(s.root, f.Name, func(x *inbound.Feed) error {
			if status == "enabled" || status == "paused" || status == "disabled" {
				x.Status = status
			}
			return nil
		})
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if err := s.accept(pushed{feed: f, set: set, at: s.now().UTC()}); err != nil {
		setError(w, http.StatusServiceUnavailable, &ssf.Error{Code: "access_denied", Description: "busy; send it again"})
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// receiver is a stream's verifier, kept while its configuration stands.
func (s *inboundServer) receiver(f inbound.Feed) (*ssf.Receiver, error) {
	key := f.Issuer + "|" + f.Audience + "|" + f.JWKSURI
	s.mu.Lock()
	c, ok := s.receivers[f.Name]
	s.mu.Unlock()
	if ok && c.key == key {
		return c.r, nil
	}
	ks, err := oidc.NewKeySet(f.JWKSURI, func(ctx context.Context, u string) ([]byte, error) {
		res, err := s.keyClient.Get(ctx, u)
		if err != nil {
			return nil, err
		}
		return res.Body, nil
	})
	if err != nil {
		return nil, err
	}
	r := &ssf.Receiver{Issuer: f.Issuer, Audience: f.Audience, Keys: ks,
		Algorithms: []oidc.Algorithm{oidc.RS256, oidc.ES256, oidc.PS256}}
	s.mu.Lock()
	s.receivers[f.Name] = cachedReceiver{key: key, r: r}
	s.mu.Unlock()
	return r, nil
}

// -- what a delivery means ----------------------------------------------------

var signalWords = map[string]string{
	"session-revoked": "session ended", "credential-change": "credential changed",
	"device-compliance-change": "device compliance changed", "assurance-level-change": "assurance changed",
	"risk-level-change": "risk changed", "token-claims-change": "claims changed",
	"account-disabled": "account disabled", "account-enabled": "account enabled", "account-purged": "account deleted",
	"account-credential-change-required": "credential change required", "credential-compromise": "credential compromised",
	"identifier-changed": "identifier changed", "identifier-recycled": "identifier recycled",
	"recovery-activated": "account recovery started", "recovery-information-changed": "recovery details changed",
	"reported": "suspicious activity reported", "threat": "threat detected", "session-moved": "session context changed",
}

func signalSummary(feed, typ, person, reason string) string {
	words := signalWords[typ]
	if words == "" {
		words = typ
	}
	out := fmt.Sprintf("%s: %s for %s", feed, words, person)
	if reason != "" {
		out += " (" + reason + ")"
	}
	return out
}

// setEvent is a shared signal as an event for the store, and as a signal for
// the rules when it is about somebody.
func setEvent(f inbound.Feed, set *ssf.SET, aliases map[string]alias, at time.Time) (telemetry.Event, *automate.Event) {
	sig := set.Signal()
	issuer := f.Alias
	if issuer == "" {
		issuer = f.Name
	}
	person := set.Subject.Person()
	ref := set.Subject.Ref()
	if person == "" && ref != "" {
		if a, ok := aliases[issuer+":"+ref]; ok {
			person = a.Person
		}
	}
	who := person
	if who == "" {
		who = ref
	}
	if who == "" {
		who = "an unnamed subject"
	}
	when := set.IssuedAt
	if ts, ok := set.Claims["event_timestamp"].(float64); ok && ts > 0 {
		when = time.Unix(int64(ts), 0)
	}
	sev := map[string]telemetry.Severity{"high": telemetry.SeverityHigh, "medium": telemetry.SeverityMedium,
		"low": telemetry.SeverityLow}[sig.Severity]
	e := telemetry.Event{Time: when.UTC(), Received: at, Class: telemetry.ClassAccountChange, Activity: 99,
		Severity: sev, Source: feedSourceName(f), Message: signalSummary(f.Name, sig.Type, who, sig.Reason),
		Raw: map[string]string{"type": sig.Type, "jti": set.JTI, "event": set.Type}}
	if ref != "" || person != "" {
		v := ref
		if v == "" {
			v = person
		}
		e.Actor = telemetry.ID{Issuer: issuer, Value: v}
	}
	if person != "" {
		e.Raw[source.PersonField] = person
	}
	for k, v := range sig.Fields {
		e.Raw[k] = v
	}
	if person == "" {
		return e, nil
	}
	fields := map[string]string{"type": sig.Type, "severity": sig.Severity, "source": f.Name, "issuer": f.Issuer, "reason": sig.Reason}
	for _, k := range []string{"current_level", "previous_level", "change_type", "credential_type", "current_status", "principal"} {
		if v := sig.Fields[k]; v != "" {
			fields[k] = v
		}
	}
	if v := sig.Fields["initiating_entity"]; v != "" {
		fields["initiator"] = v
	}
	return e, &automate.Event{Kind: "signal", Subject: person, At: at, Fields: fields,
		Summary: e.Message}
}

// oktaSignalEvent is the signal an Okta event carries, if any.
func oktaSignalEvent(f inbound.Feed, ev map[string]any, at time.Time) *automate.Event {
	typ, person, fields, ok := inbound.OktaSignal(ev)
	if !ok {
		return nil
	}
	sev := inbound.OktaSeverity(typ, fields)
	out := map[string]string{"type": typ, "severity": sev, "source": f.Name, "issuer": "okta"}
	for k, v := range fields {
		if k == "okta_event" {
			out["reason"] = v
			continue
		}
		out[k] = v
	}
	return &automate.Event{Kind: "signal", Subject: person, At: at, Fields: out,
		Summary: signalSummary(f.Name, typ, person, fields["okta_event"])}
}

// feedNames lists feeds in order, for the command and the screen.
func feedNames(m map[string]inbound.Feed) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
