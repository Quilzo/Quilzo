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
)

// Signal is something a server saw, raised as it saw it.
type Signal struct {
	Name string
	// Source is the requester's address. It is turned into a handle, a
	// network or a provider here and is never stored.
	Source string
	// Handle stands in for Source when the address is not known, as in a
	// dry run over the audit log, which holds only handles.
	Handle string
	// Subject is the chatbot, form or agent the signal is about.
	Subject string
	At      time.Time
}

// Response is what a playbook did, or would have done, about a signal.
type Response struct {
	At       time.Time `json:"at"`
	Playbook string    `json:"playbook"`
	Stage    int       `json:"stage"`
	// Mode is act, watch, or limited: the playbook reached its hourly
	// limit, did nothing, and is quiet for the rest of the hour.
	Mode string   `json:"mode"`
	Key  string   `json:"key"`
	Did  []string `json:"did"`
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
	Now    func() time.Time

	mu     sync.Mutex
	counts map[string][]time.Time
	stages map[string][]time.Time
	hourly map[string][]time.Time
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// keyOf is what a trigger counts by, for this signal: a source's handle, a
// provider's number, a subject, or everything.
func (e *Engine) keyOf(per string, s Signal) (key string, addr netip.Addr, ok bool) {
	if s.Source != "" {
		a, err := netip.ParseAddr(strings.Trim(s.Source, "[]"))
		if err == nil {
			addr = a.Unmap()
		}
	}
	switch per {
	case "source":
		h := s.Handle
		if h == "" && addr.IsValid() && e.Guard != nil {
			h = e.Guard.Handle(addr.String())
		}
		return h, addr, h != ""
	case "provider":
		if !addr.IsValid() || e.Guard == nil || e.Guard.ASN == nil {
			return "", addr, false
		}
		n, ok := e.Guard.ASN(addr)
		if !ok {
			return "", addr, false
		}
		return "asn:" + strconv.FormatUint(uint64(n), 10), addr, true
	case "subject":
		return s.Subject, addr, s.Subject != ""
	case "any":
		return "*", addr, true
	}
	return "", addr, false
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

// maxKeys bounds what the engine remembers, so signals from a great many
// sources cannot grow it without limit. Past it, what is old is forgotten
// first, and then everything: counting starts again, which costs the
// attacker nothing they did not already have and the server nothing at all.
const maxKeys = 50000

func (e *Engine) sweep(now time.Time) {
	if len(e.counts)+len(e.stages) <= maxKeys {
		return
	}
	for k, ts := range e.counts {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > Escalate {
			delete(e.counts, k)
		}
	}
	for k, ts := range e.stages {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > Escalate {
			delete(e.stages, k)
		}
	}
	if len(e.counts)+len(e.stages) > maxKeys {
		e.counts, e.stages = map[string][]time.Time{}, map[string][]time.Time{}
	}
}

type crossing struct {
	pb    Playbook
	key   string
	addr  netip.Addr
	stage int
	mode  string
}

// cross counts a signal against every playbook and returns the ones whose
// trigger it met, with the stage each has reached.
func (e *Engine) cross(pbs []Playbook, s Signal, now time.Time) []crossing {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.counts == nil {
		e.counts, e.stages, e.hourly = map[string][]time.Time{}, map[string][]time.Time{}, map[string][]time.Time{}
	}
	e.sweep(now)
	var due []crossing
	for _, pb := range pbs {
		if pb.Mode == "off" || pb.On.Signal != s.Name {
			continue
		}
		key, addr, ok := e.keyOf(pb.On.Per, s)
		if !ok {
			continue
		}
		ck := pb.Name + "|" + key
		e.counts[ck] = append(prune(e.counts[ck], s.At.Add(-time.Duration(pb.On.Within))), s.At)
		if len(e.counts[ck]) < pb.On.Count {
			continue
		}
		delete(e.counts, ck) // the next stage needs the count again
		e.stages[ck] = append(prune(e.stages[ck], s.At.Add(-Escalate)), s.At)
		stage := min(len(e.stages[ck]), len(pb.Stages)) - 1
		// The hourly limit, watching or acting: past it, the playbook says
		// so once and is then quiet until the hour has moved on, so a flood
		// blocks nobody more and writes nothing more.
		limit := pb.PerHour
		if limit == 0 {
			limit = DefaultPerHour
		}
		e.hourly[pb.Name] = prune(e.hourly[pb.Name], now.Add(-time.Hour))
		n := len(e.hourly[pb.Name])
		if n > limit {
			continue
		}
		e.hourly[pb.Name] = append(e.hourly[pb.Name], now)
		mode := pb.Mode
		if n == limit {
			mode = "limited"
		}
		due = append(due, crossing{pb, key, addr, stage, mode})
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
	var out []Response
	for _, d := range e.cross(e.Playbooks(), s, now) {
		r := e.respond(d, s, now)
		if d.mode == "act" {
			for _, st := range d.pb.Stages[d.stage].Do {
				switch {
				case st.Action == "notify" && e.Notify != nil:
					e.Notify(r, s)
				case st.Action == "open-case" && e.OpenCase != nil:
					e.OpenCase(r, s)
				}
			}
		}
		if e.Record != nil {
			action := "shield.responded"
			if d.mode != "act" {
				action = "shield.would-respond"
			}
			e.Record(action, map[string]string{"playbook": d.pb.Name, "stage": strconv.Itoa(r.Stage),
				"signal": s.Name, "mode": d.mode, "did": strings.Join(r.Did, "; ")})
		}
		_ = Change(e.Root, now, func(st *State) error {
			st.Responses = append(st.Responses, r)
			if len(st.Responses) > maxKept {
				st.Responses = st.Responses[len(st.Responses)-maxKept:]
			}
			return nil
		})
		if e.Guard != nil {
			e.Guard.Refresh()
		}
		out = append(out, r)
	}
	return out
}

func (e *Engine) respond(d crossing, s Signal, now time.Time) Response {
	r := Response{At: now, Playbook: d.pb.Name, Stage: d.stage + 1, Mode: d.mode, Key: d.key}
	for _, st := range d.pb.Stages[d.stage].Do {
		r.Did = append(r.Did, e.step(d.pb, d.stage, st, d.mode, d.key, d.addr, s, now))
	}
	return r
}

// step does one step, or says what it would do.
func (e *Engine) step(pb Playbook, stage int, st Step, mode, key string, addr netip.Addr, s Signal, now time.Time) string {
	p := Protection{Auto: true, By: "playbook:" + pb.Name, Playbook: pb.Name, Stage: stage + 1,
		Reason: fmt.Sprintf("%s (stage %d): %s", pb.Title, stage+1, Signals[s.Name]),
		At:     now, Until: now.Add(time.Duration(st.For)), Where: st.Where}
	if strings.HasPrefix(st.Action, "block-") && addr.IsValid() && e.Guard != nil && trusted(e.Guard.state(now), addr) {
		return "did not block: the source is this machine or a trusted network"
	}
	switch st.Action {
	case "block-source":
		handle := key
		if pb.On.Per != "source" {
			handle = s.Handle
			if handle == "" && addr.IsValid() && e.Guard != nil {
				handle = e.Guard.Handle(addr.String())
			}
		}
		if handle == "" {
			return "could not block the source: its address is not known"
		}
		p.Kind, p.Target = Block, "source:"+handle
	case "block-network":
		if !addr.IsValid() {
			return "could not block the network: the address is not known"
		}
		bits := 24
		if addr.Is6() {
			bits = 48
		}
		pfx, _ := addr.Prefix(bits)
		p.Kind, p.Target = Block, "net:"+pfx.String()
	case "block-provider":
		if !addr.IsValid() || e.Guard == nil || e.Guard.ASN == nil {
			return "could not block the provider: it is not known"
		}
		n, ok := e.Guard.ASN(addr)
		if !ok {
			return "could not block the provider: it is not known"
		}
		p.Kind, p.Target = Block, "asn:"+strconv.FormatUint(uint64(n), 10)
	case "shield-feature":
		target := st.Feature
		if target == "subject" {
			kind := map[string]string{"chatbot-injection": "chatbot", "form-spam": "form"}[s.Name]
			target = kind + ":" + s.Subject
		}
		p.Kind, p.Target, p.Level = Feature, target, st.Level
	case "lockdown":
		p.Kind = Lockdown
	case "freeze":
		p.Kind = Freeze
	case "pause-agent":
		p.Kind, p.Target = Agent, s.Subject
	case "notify":
		return "told the security contact"
	case "open-case":
		return "opened a case"
	default:
		return "nothing: " + st.Action + " is not an action"
	}
	what := describe(p)
	if mode != "act" {
		if mode == "limited" {
			return "would have " + what + ", but the playbook reached its hourly limit"
		}
		return "would have " + what
	}
	if _, _, err := Apply(e.Root, p, now); err != nil {
		return "did not " + what + ": " + err.Error()
	}
	return what
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
// order: nothing is applied, and nothing is written.
func DryRun(pb Playbook, signals []Signal) []Response {
	signals = append([]Signal(nil), signals...)
	sort.SliceStable(signals, func(i, j int) bool { return signals[i].At.Before(signals[j].At) })
	pb.Mode = "watch"
	e := &Engine{}
	var out []Response
	for _, s := range signals {
		for _, d := range e.cross([]Playbook{pb}, s, s.At) {
			out = append(out, e.respond(d, s, s.At))
		}
	}
	return out
}
