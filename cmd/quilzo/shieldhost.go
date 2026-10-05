// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/automate"
	"github.com/quilzo/quilzo/internal/clientip"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/shield"
)

// shieldHost is the shield as one server process runs it: the guard every
// request is checked against, and the engine every signal is told to
// (internal/shield). The admin and the public site each build one over the
// same store, so a block either applies is in force in the other within a
// second.
//
// The command line on the machine builds none. It is the way out of
// anything the shield does, so nothing here is between it and the store.
type shieldHost struct {
	root   string
	guard  *shield.Guard
	engine *shield.Engine
	// where is the surface this process serves, for the signals it raises.
	where string
}

func newShieldHost(root string) *shieldHost {
	key, err := os.ReadFile(auditKeyPath(root))
	if err != nil {
		// Without the audit key no source has a handle, so nothing can be
		// blocked by source; the rest (features, lockdown, freeze, agents)
		// still works, and the posture check says why sources are not.
		key = nil
	}
	g := &shield.Guard{Root: root, Key: key, ASN: func(a netip.Addr) (uint32, bool) {
		loc, _, err := cachedGeo(root)
		if err != nil || loc == nil {
			return 0, false
		}
		n := loc.Net(a.String()).ASN
		return n, n != 0
	}}
	lib := &shield.Library{Root: root}
	h := &shieldHost{root: root, guard: g}
	acts := automationActions(root)
	tell := func(id string) func(r shield.Response, s shield.Signal) {
		return func(r shield.Response, s shield.Signal) {
			act, ok := acts[id]
			if !ok {
				return
			}
			title := r.Playbook
			for _, pb := range lib.Get() {
				if pb.Name == r.Playbook {
					title = pb.Title
				}
			}
			ev := automate.Event{Kind: "signal", Subject: "shield:" + r.Playbook, At: r.At,
				Summary: shieldSummary(title, r, s, g.State(r.At)),
				Fields:  map[string]string{"signal": s.Name, "playbook": r.Playbook, "severity": "high"}}
			out, err := act.Run(ev, map[string]string{"to": "security"})
			detail := map[string]string{"playbook": r.Playbook, "step": id, "did": out}
			outcome := audit.Success
			if err != nil {
				detail["error"], outcome = err.Error(), audit.Failure
			}
			record(root, audit.Record{Action: "shield." + id, Resource: "/", Outcome: outcome,
				Principal: "shield", Kind: audit.KindService, Verified: true, Detail: detail})
		}
	}
	h.engine = &shield.Engine{Root: root, Guard: g, Playbooks: lib.Get,
		Notify: tell("notify"), OpenCase: tell("open-case"),
		Record: func(action string, d map[string]string) {
			record(root, audit.Record{Action: action, Resource: "/", Outcome: audit.Success,
				Principal: "shield", Kind: audit.KindService, Verified: true, Detail: d})
		},
		CanLockdown: func() bool { return canSignInStrongly(root) },
	}
	return h
}

// shieldSummary is a response in a sentence or two, for a message and a
// case: what happened, what the shield did, and for a decoy where it was
// planted, which is where the leak is.
func shieldSummary(title string, r shield.Response, s shield.Signal, st *shield.State) string {
	out := fmt.Sprintf("Shield: %s (stage %d). %s.", title, r.Stage, sentence(strings.Join(r.Did, "; ")))
	if s.Name == "decoy" && st != nil {
		for _, d := range st.Decoys {
			if d.ID == s.Subject {
				out += fmt.Sprintf(" The decoy was the one planted in %s on %s: whoever presented it has a copy of what was kept there.",
					d.Note, d.At.UTC().Format("2 January 2006"))
			}
		}
	}
	return out
}

func sentence(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// canSignInStrongly reports whether some administrator could still sign in
// during a lockdown: one of the whole site's administrators with a passkey.
// Single sign-on alone does not count: the identity provider can be down,
// or be what the attack is about, and a lockdown that leaves only it leaves
// nothing.
func canSignInStrongly(root string) bool {
	pk := &admin.Passkeys{}
	if err := loadJSON(passkeysPath(root), pk); err != nil {
		return false
	}
	pol, err := loadPolicy(root)
	if err != nil {
		return false
	}
	for _, c := range pk.Credentials {
		if pol.Evaluate(c.Principal, auth.ActGrant, "/").Allowed {
			return true
		}
	}
	return false
}

// signal tells the engine something a request did. A request that only
// passed through named proxies has no source to count; one whose address
// cannot be trusted enough to block is counted and marked so.
func (h *shieldHost) signal(name, subject string, r *http.Request) {
	c := clientip.FromRequest(r)
	s := shield.Signal{Name: name, Subject: subject, Unverified: c.Unverified, Where: h.where}
	if c.Known() && !c.Internal {
		s.Source = c.Addr.String()
	}
	h.engine.Observe(s)
}

// violation is a page's policy violation a visitor's browser reported: a
// signal about the page, counted by how many different networks report it,
// never a reason to refuse whoever sent it.
func (h *shieldHost) violation(v public.Violation, r *http.Request) {
	c := clientip.FromRequest(r)
	by := ""
	if c.Known() {
		bits := 24
		if c.Addr.Is6() {
			bits = 48
		}
		if pfx, err := c.Addr.Prefix(bits); err == nil {
			by = h.guard.Handle(pfx.String())
		}
	}
	h.engine.Observe(shield.Signal{Name: "page-violation", Subject: v.Group(), By: by, Where: h.where})
}

// badToken is a credential that did not authenticate: a decoy is a decoy,
// whatever else; a secret shaped like a token that was never issued here is
// a guess. One that expired or was revoked is somebody's real credential
// used late, and a lockdown's refusal is the lockdown working, so neither
// is counted.
func (h *shieldHost) badToken(r *http.Request, presented string, err error) {
	now := time.Now()
	if d, ok := h.guard.Decoy(presented, now); ok {
		record(h.root, audit.Record{Action: "shield.decoy-touched", Resource: r.URL.Path,
			Outcome: audit.Denied, Principal: clientip.SourceFrom(r), Kind: audit.KindUnknown,
			Detail: map[string]string{"decoy": d.ID, "planted": d.Note}})
		h.signal("decoy", d.ID, r)
		return
	}
	if strings.HasPrefix(presented, auth.TokenPrefix) && auth.Unknown(err) {
		h.signal("signin-failures", "", r)
	}
}

// admit is the lockdown and the suspended tokens, as the token stores the
// servers load ask them.
func (h *shieldHost) admit(c auth.Credential) error {
	now := time.Now()
	if p, on := h.guard.Lockdown(now); on && shield.LockedOut(p, c.Issued, c.Vouched) {
		return fmt.Errorf("%w (until about %s)", auth.ErrLockedDown, p.Until.UTC().Format("15:04 UTC"))
	}
	for _, id := range []string{c.ID, c.Parent} {
		if id == "" {
			continue
		}
		if p, on := h.guard.Suspended(id, now); on {
			return fmt.Errorf("this token is suspended until about %s; an administrator can lift it", p.Until.UTC().Format("15:04 UTC"))
		}
	}
	return nil
}

// gate is a token store loaded by a server, with the lockdown on it.
func (h *shieldHost) gate(ts *auth.TokenStore) *auth.TokenStore {
	if ts != nil {
		ts.Admit = h.admit
	}
	return ts
}

// vouch records that an administrator signed in strongly from where this
// request came from. Only an administrator of the whole site: an author's
// passkey does not make an address one the shield keeps on the admin.
func (h *shieldHost) vouch(r *http.Request, principal string) {
	c := clientip.FromRequest(r)
	if !c.Known() || c.Unverified {
		return
	}
	pol, err := loadPolicy(h.root)
	if err != nil || !pol.Evaluate(principal, auth.ActGrant, "/").Allowed {
		return
	}
	if err := shield.Vouch(h.root, h.guard.Handles(c.Addr), time.Now()); err == nil {
		h.guard.Refresh()
	}
}

// feature reports a feature the shield turned down, for the public site.
func (h *shieldHost) feature(target string) (string, time.Time, bool) {
	p, on := h.guard.Feature(target, time.Now())
	return p.Level, p.Until, on
}

// off reports a feature the shield turned off, for the admin and the API.
func (h *shieldHost) off(target string) (time.Time, bool) {
	p, on := h.guard.Feature(target, time.Now())
	return p.Until, on && p.Level == shield.Off
}

// frozen is publishing refused while it is frozen, read from the store each
// time: publishing is rare, and a record that cannot be read keeps a freeze
// in force rather than lifting it.
func (h *shieldHost) frozen() error {
	if p, on := shield.Frozen(h.root, time.Now()); on {
		return &shield.FrozenError{P: p}
	}
	return nil
}

// refuseWhileFrozen is the freeze for the places that publish outside a
// server: the command line, a schedule, the machine interface, promoting
// an environment. Rolling back is never refused.
func refuseWhileFrozen(root string) error {
	if p, on := shield.Frozen(root, time.Now()); on {
		return &shield.FrozenError{P: p}
	}
	return nil
}

// refuseIfPaused is an agent the shield has paused.
func refuseIfPaused(root, agent string) error {
	if p, on := shield.Find(root, shield.Agent, agent, time.Now()); on {
		return fmt.Errorf("the agent %s is paused until about %s: %s. "+
			"An administrator can lift it on the Shield screen or with quilzo shield lift %s",
			agent, p.Until.UTC().Format("15:04 UTC on 2 January"), p.Reason, p.ID)
	}
	return nil
}
