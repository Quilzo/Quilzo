// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/clientip"
)

// Signal is something a server saw, raised as it saw it.
type Signal struct {
	Name string
	// Source is the requester's address, as the edge decided it
	// (internal/clientip). It is turned into a handle, a network or a
	// provider here and is never stored.
	Source string
	// Handle stands in for Source when the address is not known, as in a
	// dry run over the audit log, which holds only handles.
	Handle string
	// Provider stands in for the address's provider when the address is
	// not known: the audit log records the provider's number beside the
	// handle, which is not personal data.
	Provider uint32
	// Subject is the chatbot, form, agent or address the signal is about.
	Subject string
	At      time.Time
}

// Response is what a playbook did, or would have done, about a signal.
type Response struct {
	At       time.Time `json:"at"`
	Playbook string    `json:"playbook"`
	Stage    int       `json:"stage"`
	// Mode is act; watch; held (every playbook is held to watching); or
	// limited (the playbook reached its hourly limit, did nothing, and is
	// quiet for the rest of the hour).
	Mode string   `json:"mode"`
	Key  string   `json:"key"`
	Did  []string `json:"did"`
	// Applied are the protections it put in force.
	Applied []string `json:"applied,omitempty"`
	// Tell marks a response a person must hear about even though its
	// playbook did not say so: a step the guardrails stopped, or the hourly
	// limit reached.
	Tell bool `json:"tell,omitempty"`
}

// Engine runs playbooks against signals as they arrive.
type Engine struct {
	Root  string
	Guard *Guard
	// Playbooks are the playbooks in force, read on each signal.
	Playbooks func() []Playbook
	// Notify and OpenCase are the two steps that reach people.
	Notify   func(r Response, s Signal)
	OpenCase func(r Response, s Signal)
	// Record writes to the audit log.
	Record func(action string, detail map[string]string)
	// CanLockdown reports whether some administrator could still sign in
	// during a lockdown, with a passkey or single sign-on. A lockdown nobody
	// can get past is not applied by a playbook; nil means it cannot be
	// told, which is the same.
	CanLockdown func() bool
	Now         func() time.Time

	mu     sync.Mutex
	counts map[string][]hit
	stages map[string][]mark
	quiet  map[string]time.Time
	hourly map[string][]time.Time
	touch  map[string]time.Time
}

type hit struct {
	at      time.Time
	subject string
}

// mark is a stage a key reached, and what it applied: a person lifting one
// of those protections early takes the stage back, so the next crossing
// does not escalate past a decision that was wrong.
type mark struct {
	at  time.Time
	ids []string
}

// Cooldown is how long a key is not counted after a stage fires for it.
// Every process counts on its own and a block reaches the others within a
// second, so without it one burst could run two stages at once.
const Cooldown = 5 * time.Minute

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) state(now time.Time) *State {
	if e.Guard == nil {
		return &State{}
	}
	return e.Guard.state(now)
}

func addrOf(s Signal) netip.Addr {
	if s.Source == "" {
		return netip.Addr{}
	}
	a, _ := clientip.Parse(s.Source)
	return a
}

// keyOf is what a trigger counts by, for this signal: a source's handle, a
// provider's number, a subject, or everything.
func (e *Engine) keyOf(per string, s Signal, addr netip.Addr) (string, bool) {
	switch per {
	case "source":
		h := s.Handle
		if h == "" && addr.IsValid() && e.Guard != nil {
			h = e.Guard.Handle(clientip.Source(addr))
		}
		return h, h != ""
	case "provider":
		n := s.Provider
		if n == 0 && addr.IsValid() && e.Guard != nil && e.Guard.ASN != nil {
			n, _ = e.Guard.ASN(addr)
		}
		if n == 0 {
			return "", false
		}
		return "asn:" + strconv.FormatUint(uint64(n), 10), true
	case "subject":
		return s.Subject, s.Subject != ""
	case "any":
		return "*", true
	}
	return "", false
}

func prune(ts []time.Time, since time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if t.After(since) {
			out = append(out, t)
		}
	}
	return out
}

func pruneHits(hs []hit, since time.Time) []hit {
	out := hs[:0]
	for _, h := range hs {
		if h.at.After(since) {
			out = append(out, h)
		}
	}
	return out
}

func distinct(hs []hit) int {
	seen := map[string]bool{}
	for _, h := range hs {
		seen[h.subject] = true
	}
	return len(seen)
}

// maxKeys bounds what the engine remembers, so signals from a great many
// sources cannot grow it without limit. Past it, the keys touched longest
// ago are forgotten first, down to nine tenths; one actor rotating sources
// forgets its own oldest keys, not everybody's escalation.
const maxKeys = 50000

func (e *Engine) sweep() {
	if len(e.touch) <= maxKeys {
		return
	}
	type kt struct {
		k string
		t time.Time
	}
	all := make([]kt, 0, len(e.touch))
	for k, t := range e.touch {
		all = append(all, kt{k, t})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	for _, x := range all[:len(all)-maxKeys*9/10] {
		delete(e.counts, x.k)
		delete(e.stages, x.k)
		delete(e.quiet, x.k)
		delete(e.touch, x.k)
	}
}

type crossing struct {
	pb    Playbook
	key   string
	ck    string
	addr  netip.Addr
	stage int
	mode  string
}

// liftedEarly reports whether a person ended any of these protections
// before their time: a decision that the stage was wrong.
func liftedEarly(st *State, ids []string) bool {
	for _, id := range ids {
		for _, list := range [][]Protection{st.Protections, st.Ended} {
			for _, p := range list {
				if p.ID == id && !p.Lifted.IsZero() && p.ReplacedBy == "" {
					return true
				}
			}
		}
	}
	return false
}

// cross counts a signal against every playbook and returns the ones whose
// trigger it met, with the stage each has reached.
func (e *Engine) cross(pbs []Playbook, s Signal, now time.Time, st *State) []crossing {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.counts == nil {
		e.counts, e.stages, e.hourly = map[string][]hit{}, map[string][]mark{}, map[string][]time.Time{}
		e.quiet, e.touch = map[string]time.Time{}, map[string]time.Time{}
	}
	e.sweep()
	addr := addrOf(s)
	var due []crossing
	for _, pb := range pbs {
		if pb.Mode == "off" || pb.On.Signal != s.Name {
			continue
		}
		key, ok := e.keyOf(pb.On.Per, s, addr)
		if !ok {
			continue
		}
		ck := pb.Name + "|" + key
		e.touch[ck] = s.At
		if q, ok := e.quiet[ck]; ok {
			if s.At.Before(q) {
				continue
			}
			delete(e.quiet, ck)
		}
		hs := append(pruneHits(e.counts[ck], s.At.Add(-time.Duration(pb.On.Within))), hit{s.At, s.Subject})
		if len(hs) > pb.On.Count*4+16 {
			hs = hs[len(hs)-(pb.On.Count*4+16):]
		}
		e.counts[ck] = hs
		n := len(hs)
		if pb.On.Distinct {
			n = distinct(hs)
		}
		if n < pb.On.Count {
			continue
		}
		delete(e.counts, ck) // the next stage needs the count again
		var marks []mark
		for _, m := range e.stages[ck] {
			if m.at.After(s.At.Add(-Escalate)) && !liftedEarly(st, m.ids) {
				marks = append(marks, m)
			}
		}
		e.stages[ck] = marks
		stage := min(len(marks), len(pb.Stages)-1)
		// The hourly limit, watching or acting: past it, the playbook says
		// so once and is then quiet until the hour has moved on, so a flood
		// blocks nobody more and writes nothing more.
		limit := pb.PerHour
		if limit == 0 {
			limit = DefaultPerHour
		}
		e.hourly[pb.Name] = prune(e.hourly[pb.Name], now.Add(-time.Hour))
		used := len(e.hourly[pb.Name])
		if used > limit {
			continue
		}
		e.hourly[pb.Name] = append(e.hourly[pb.Name], now)
		mode := pb.Mode
		switch {
		case used == limit:
			mode = "limited"
		case mode == "act" && st.Watching != nil:
			mode = "held"
		}
		e.quiet[ck] = s.At.Add(Cooldown)
		due = append(due, crossing{pb, key, ck, addr, stage, mode})
	}
	return due
}

// Observe runs every playbook a signal meets. It is called on the request
// that raised the signal, so a block is in force before the next one.
func (e *Engine) Observe(s Signal) []Response {
	if e == nil || e.Playbooks == nil {
		return nil
	}
	now := e.now()
	if s.At.IsZero() {
		s.At = now
	}
	st := e.state(now)
	var out []Response
	for _, d := range e.cross(e.Playbooks(), s, now, st) {
		r := e.respond(d, s, now, st)
		// The stage is remembered only once it has been answered, with what
		// it applied, so a person lifting that can take it back.
		e.mu.Lock()
		e.stages[d.ck] = append(e.stages[d.ck], mark{at: s.At, ids: r.Applied})
		e.mu.Unlock()
		told := false
		if d.mode == "act" {
			for _, step := range d.pb.Stages[d.stage].Do {
				switch {
				case step.Action == "notify" && e.Notify != nil:
					e.Notify(r, s)
					told = true
				case step.Action == "open-case" && e.OpenCase != nil:
					e.OpenCase(r, s)
				}
			}
		}
		if r.Tell && !told && e.Notify != nil {
			e.Notify(r, s)
		}
		if e.Record != nil {
			action := "shield.responded"
			if d.mode != "act" {
				action = "shield.would-respond"
			}
			e.Record(action, map[string]string{"playbook": d.pb.Name, "stage": strconv.Itoa(r.Stage),
				"signal": s.Name, "mode": d.mode, "did": strings.Join(r.Did, "; ")})
		}
		err := Change(e.Root, now, func(st *State) error {
			st.Responses = append(st.Responses, r)
			if len(st.Responses) > maxKept {
				st.Responses = st.Responses[len(st.Responses)-maxKept:]
			}
			return nil
		})
		if err != nil && e.Record != nil {
			e.Record("shield.unrecorded", map[string]string{"playbook": d.pb.Name, "error": err.Error()})
		}
		if e.Guard != nil {
			e.Guard.Refresh()
		}
		out = append(out, r)
	}
	return out
}

func (e *Engine) respond(d crossing, s Signal, now time.Time, st *State) Response {
	r := Response{At: now, Playbook: d.pb.Name, Stage: d.stage + 1, Mode: d.mode, Key: d.key}
	if d.mode == "limited" {
		r.Tell = true
	}
	for _, step := range d.pb.Stages[d.stage].Do {
		did, id, tell := e.step(d.pb, d.stage, step, d.mode, d.key, d.addr, s, now, st)
		r.Did = append(r.Did, did)
		if id != "" {
			r.Applied = append(r.Applied, id)
		}
		r.Tell = r.Tell || tell
	}
	return r
}

// step does one step, or says what it would do; it returns what it did in
// words, the protection it applied, and whether a person must be told.
func (e *Engine) step(pb Playbook, stage int, step Step, mode, key string, addr netip.Addr, s Signal, now time.Time, st *State) (string, string, bool) {
	p := Protection{Auto: true, By: "playbook:" + pb.Name, Playbook: pb.Name, Stage: stage + 1,
		Reason: fmt.Sprintf("%s (stage %d): %s", pb.Title, stage+1, Signals[s.Name]),
		At:     now, Until: now.Add(time.Duration(step.For)), Where: step.Where}
	note := ""
	if strings.HasPrefix(step.Action, "block-") {
		if addr.IsValid() && trusted(st, addr) {
			return "did not block: the source is on the inside or on a trusted network", "", false
		}
		// Never lock out somebody who runs this place: a source an
		// administrator signed in from strongly keeps the admin.
		if p.Where != Site && e.vouched(st, addr, s, now) {
			if p.Where == Admin {
				return "did not block the admin: an administrator signed in from here with a passkey or single sign-on in the last 30 days", "", true
			}
			p.Where = Site
			note = " (not the admin: an administrator signed in from here with a passkey or single sign-on in the last 30 days)"
		}
	}
	switch step.Action {
	case "block-source":
		handle := key
		if pb.On.Per != "source" {
			handle = s.Handle
			if handle == "" && addr.IsValid() && e.Guard != nil {
				handle = e.Guard.Handle(clientip.Source(addr))
			}
		}
		if handle == "" {
			return "could not block the source: its address is not known", "", false
		}
		p.Kind, p.Target = Block, "source:"+handle
	case "block-network":
		if !addr.IsValid() {
			if mode != "act" {
				return "would have blocked the source's network", "", false
			}
			return "could not block the network: the address is not known", "", false
		}
		bits := 24
		if addr.Is6() {
			bits = 48
		}
		pfx, _ := addr.Prefix(bits)
		p.Kind, p.Target = Block, "net:"+pfx.String()
	case "block-provider":
		n := s.Provider
		if n == 0 && addr.IsValid() && e.Guard != nil && e.Guard.ASN != nil {
			n, _ = e.Guard.ASN(addr)
		}
		if n == 0 {
			return "could not block the provider: it is not known", "", false
		}
		p.Kind, p.Target = Block, "asn:"+strconv.FormatUint(uint64(n), 10)
	case "shield-feature":
		target := step.Feature
		if target == "subject" {
			kind := map[string]string{"chatbot-injection": "chatbot", "form-spam": "form"}[s.Name]
			target = kind + ":" + s.Subject
		}
		p.Kind, p.Target, p.Level = Feature, target, step.Level
	case "lockdown":
		p.Kind = Lockdown
		if mode == "act" && (e.CanLockdown == nil || !e.CanLockdown()) {
			return "did not lock the admin down: no administrator has a passkey or single sign-on to get past it", "", true
		}
	case "freeze":
		p.Kind = Freeze
	case "pause-agent":
		p.Kind, p.Target = Agent, s.Subject
	case "notify":
		return "told the security contact", "", false
	case "open-case":
		return "opened a case", "", false
	default:
		return "nothing: " + step.Action + " is not an action", "", false
	}
	what := describe(p) + note
	switch mode {
	case "act":
	case "limited":
		return "would have " + what + ", but the playbook reached its hourly limit", "", false
	case "held":
		return "would have " + what + ", but every playbook is being held to watching", "", false
	default:
		return "would have " + what, "", false
	}
	applied, _, err := Apply(e.Root, p, now)
	if err != nil {
		return "did not " + what + ": " + err.Error(), "", true
	}
	return what, applied.ID, note != ""
}

// vouched reports whether the signal's source signed in strongly lately.
func (e *Engine) vouched(st *State, addr netip.Addr, s Signal, now time.Time) bool {
	var hs []string
	if addr.IsValid() && e.Guard != nil {
		hs = e.Guard.Handles(addr)
	}
	if s.Handle != "" {
		hs = append(hs, s.Handle)
	}
	return st.IsVouched(hs, now)
}

// describe is a protection in words, for a history.
func describe(p Protection) string {
	until := "until " + p.Until.UTC().Format("2 Jan 15:04 UTC")
	if !p.At.IsZero() {
		until = "for " + roughly(p.Until.Sub(p.At))
	}
	switch p.Kind {
	case Block:
		kind, value, _ := strings.Cut(p.Target, ":")
		what := map[string]string{"source": "the source", "net": "the network " + value, "asn": "provider AS" + value}[kind]
		return fmt.Sprintf("blocked %s on %s %s", what, map[string]string{Admin: "the admin", Site: "the site", All: "the admin and the site"}[p.Where], until)
	case Feature:
		if p.Level == Limited {
			return fmt.Sprintf("limited %s to quoting pages %s", p.Target, until)
		}
		return fmt.Sprintf("turned off %s %s", p.Target, until)
	case Lockdown:
		return "locked the admin to passkeys and single sign-on " + until
	case Freeze:
		return "froze publishing " + until
	case Agent:
		return "paused the agent " + p.Target + " " + until
	}
	return p.Kind
}

func roughly(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		if d == time.Hour {
			return "an hour"
		}
		return strconv.Itoa(int(d/time.Hour)) + " hours"
	case d >= time.Minute:
		return strconv.Itoa(int(d.Round(time.Minute)/time.Minute)) + " minutes"
	}
	return d.Round(time.Second).String()
}

// Describe is a protection in words.
func Describe(p Protection) string { return describe(p) }

// DryRun is what a playbook would have done over a run of past signals, in
// order: nothing is applied, and nothing is written. A source the playbook
// would have blocked sends nothing more while it would have been blocked,
// as it could not have; and an early lift, which only a person makes, is
// not imagined.
func DryRun(pb Playbook, signals []Signal) []Response {
	signals = append([]Signal(nil), signals...)
	sort.SliceStable(signals, func(i, j int) bool { return signals[i].At.Before(signals[j].At) })
	pb.Mode = "watch"
	e := &Engine{}
	st := &State{}
	blocked := map[string]time.Time{}
	var out []Response
	for _, s := range signals {
		if until, ok := blocked[s.Handle]; ok && s.Handle != "" && s.At.Before(until) {
			continue
		}
		for _, d := range e.cross([]Playbook{pb}, s, s.At, st) {
			r := e.respond(d, s, s.At, st)
			e.stages[d.ck] = append(e.stages[d.ck], mark{at: s.At})
			for _, step := range pb.Stages[d.stage].Do {
				if step.Action == "block-source" && s.Handle != "" {
					if u := s.At.Add(time.Duration(step.For)); u.After(blocked[s.Handle]) {
						blocked[s.Handle] = u
					}
				}
			}
			out = append(out, r)
		}
	}
	return out
}
