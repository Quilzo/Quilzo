// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/shield"
)

// The Shield screen: what Quilzo is doing to protect itself, the playbooks
// that decide it, and the ways to undo it.
//
// Reading it is the security area's. Changing anything is the whole site's
// administrators', because the shield decides who gets in and what Quilzo
// does on its own; and a change to a playbook, or letting held playbooks
// act again, is proposed by one administrator and approved by another.
// Lifting a protection and holding every playbook to watching take one:
// they are the safe direction.

// ShieldAdmin is what the screen needs from the program.
type ShieldAdmin struct {
	// Root is the store the shield is kept in.
	Root string
	// OnlyAdmin reports whether a person is the only administrator there
	// is, who may then approve their own change; the history says so.
	OnlyAdmin func(name string) bool
	// History is the signals in the audit log over the last days, for a
	// dry run.
	History func(days int) ([]shield.Signal, error)
	// Changed tells this process's guard to read the record now.
	Changed func()
	// CanLockdown reports whether some administrator could still sign in
	// during a lockdown, with a passkey or single sign-on. Nil means it
	// cannot be told, and a lockdown is not set from the screen.
	CanLockdown func() bool
}

// shieldProtection is one protection, for the screen.
type shieldProtection struct {
	shield.Protection
	What, Ends, Started, Who, State, Tone string
	Judgeable                             bool
}

// shieldPlaybook is one playbook, for the screen.
type shieldPlaybook struct {
	shield.Playbook
	Trigger   string
	Stages    []string
	Precision string
	Waiting   bool
}

// shieldProposal is one change waiting for a second administrator.
type shieldProposal struct {
	shield.Proposal
	What, When string
	Mine       bool
}

func (s *Server) shieldSiteAdmin(p principal) bool {
	return s.Policy != nil && s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed
}

func (s *Server) handleShield(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Title": "Shield", "Nav": "shield", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"SiteAdmin": s.shieldSiteAdmin(p) && !p.Limits.ReadOnly, "Features": shieldFeatures()}
	if s.ShieldAdmin == nil {
		data["Unavailable"] = "This build was started without the shield."
		s.render(w, r, "shield.html", data)
		return
	}
	s.shieldData(data, p, r.URL.Query().Get("try"), r.URL.Query().Get("days"))
	s.render(w, r, "shield.html", data)
}

func shieldFeatures() []map[string]string {
	keys := []string{"chatbots", "search-answers", "forms", "boards", "signup", "uploads", "api", "mcp", "scim", "import", "feeds"}
	var out []map[string]string
	for _, k := range keys {
		out = append(out, map[string]string{"Key": k, "Words": shield.Features[k]})
	}
	return out
}

func (s *Server) shieldData(data map[string]any, p principal, try, daysParam string) {
	root := s.ShieldAdmin.Root
	now := time.Now()
	st, err := shield.Load(root)
	if err != nil {
		data["Broken"] = err.Error()
		return
	}
	bk, err := shield.LoadBook(root)
	if err != nil {
		data["BookBroken"] = err.Error()
		bk = &shield.Book{}
	}
	var active []shieldProtection
	for _, x := range st.Active(now) {
		active = append(active, shieldView(x, now))
	}
	data["Active"] = active
	if st.Watching != nil {
		data["Held"] = map[string]string{"By": st.Watching.By, "Reason": st.Watching.Reason,
			"At": st.Watching.At.UTC().Format("2 Jan 15:04 UTC")}
	}
	recs := map[string]shield.Record{}
	for _, r := range shield.Records(st) {
		recs[r.Playbook] = r
	}
	waiting := map[string]bool{}
	var pending []shieldProposal
	releaseWaiting := false
	for _, q := range bk.Pending {
		waiting[q.Playbook.Name] = true
		releaseWaiting = releaseWaiting || q.Release
		pending = append(pending, shieldProposal{Proposal: q, What: shieldProposalWords(q),
			When: q.At.UTC().Format("2 Jan 15:04 UTC"), Mine: strings.EqualFold(q.By, p.Name)})
	}
	data["Pending"], data["ReleaseWaiting"] = pending, releaseWaiting
	var pbs []shieldPlaybook
	for _, pb := range bk.InForce() {
		v := shieldPlaybook{Playbook: pb, Trigger: shieldTrigger(pb), Waiting: waiting[pb.Name] && pb.Name != ""}
		for i, stg := range pb.Stages {
			var steps []string
			for _, step := range stg.Do {
				steps = append(steps, shieldStepWords(step))
			}
			lead := "First"
			if i > 0 {
				lead = ordinal(i + 1)
			}
			v.Stages = append(v.Stages, lead+": "+strings.Join(steps, "; ")+".")
		}
		v.Precision = shieldPrecision(recs[pb.Name])
		pbs = append(pbs, v)
	}
	data["Playbooks"], data["Problems"] = pbs, bk.Problems()

	var recent []shieldProtection
	ended := st.Ended
	if len(ended) > 25 {
		ended = ended[len(ended)-25:]
	}
	for i := len(ended) - 1; i >= 0; i-- {
		recent = append(recent, shieldView(ended[i], now))
	}
	data["Ended"] = recent
	var responses []map[string]string
	rs := st.Responses
	if len(rs) > 25 {
		rs = rs[len(rs)-25:]
	}
	for i := len(rs) - 1; i >= 0; i-- {
		r := rs[i]
		tone := map[string]string{"act": "good", "watch": "unknown", "held": "warning", "limited": "warning"}[r.Mode]
		responses = append(responses, map[string]string{"When": r.At.UTC().Format("2 Jan 15:04"),
			"Playbook": r.Playbook, "Stage": strconv.Itoa(r.Stage), "Mode": r.Mode, "Tone": tone,
			"Did": strings.Join(r.Did, "; ")})
	}
	data["Responses"] = responses
	data["Trusted"], data["Vouched"] = st.Trusted, len(st.Vouched)
	var decoys []map[string]string
	for _, d := range st.Decoys {
		decoys = append(decoys, map[string]string{"ID": d.ID, "Note": d.Note, "By": d.By,
			"At": d.At.UTC().Format("2 Jan 2006")})
	}
	data["Decoys"] = decoys

	if try != "" && s.ShieldAdmin.History != nil {
		days, _ := strconv.Atoi(daysParam)
		if days < 1 || days > 400 {
			days = 30
		}
		var chosen []shield.Playbook
		for _, pb := range bk.InForce() {
			if try == "all" || pb.Name == try {
				chosen = append(chosen, pb)
			}
		}
		sigs, err := s.ShieldAdmin.History(days)
		if err != nil {
			data["TryError"] = err.Error()
		} else {
			data["Try"] = map[string]any{"Days": days, "Signals": len(sigs), "Runs": shield.Try(chosen, sigs, st, now)}
		}
	}
}

// ordinal is how a stage after the first is introduced: each counts from
// the same source, or thing, coming back within a day.
func ordinal(n int) string {
	return map[int]string{2: "Again within a day", 3: "A third time", 4: "A fourth time", 5: "A fifth time"}[n]
}

func shieldView(x shield.Protection, now time.Time) shieldProtection {
	v := shieldProtection{Protection: x, What: sentenceCase(shield.Describe(x)),
		Ends: x.Until.UTC().Format("2 Jan 15:04 UTC"), Started: x.At.UTC().Format("2 Jan 15:04 UTC")}
	if x.Auto {
		v.Who = fmt.Sprintf("Playbook %s, stage %d", x.Playbook, x.Stage)
	} else {
		v.Who = "Set by " + x.By
	}
	switch {
	case x.ActiveAt(now):
		v.State, v.Tone = "In force", "good"
	case x.ReplacedBy != "":
		v.State, v.Tone = "Replaced", "unknown"
	case !x.Lifted.IsZero():
		v.State, v.Tone = "Lifted by "+x.LiftedBy, "unknown"
	default:
		v.State, v.Tone = "Ended", "unknown"
	}
	if x.Verdict == shield.Mistake {
		v.State, v.Tone = v.State+"; a mistake", "warning"
	} else if x.Verdict == shield.Right {
		v.State += "; right"
	}
	v.Judgeable = x.Auto && x.Verdict == ""
	return v
}

func sentenceCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// shieldTrigger is a playbook's trigger in words: "When 5 guessed tokens
// come from one source within an hour."
func shieldTrigger(pb shield.Playbook) string {
	nouns, ok := shield.Counted[pb.On.Signal]
	if !ok {
		nouns = [2]string{pb.On.Signal, pb.On.Signal}
	}
	per := map[string]string{"source": "from one source", "provider": "from one provider's network",
		"subject": "about one chatbot, form or agent", "any": "from anywhere"}[pb.On.Per]
	what := "One " + nouns[0]
	switch {
	case pb.On.Count > 1 && pb.On.Distinct:
		what = fmt.Sprintf("%d different %s", pb.On.Count, nouns[1])
	case pb.On.Count > 1:
		what = fmt.Sprintf("%d %s", pb.On.Count, nouns[1])
	}
	return fmt.Sprintf("%s %s within %s.", what, per, roughDuration(time.Duration(pb.On.Within)))
}

func roughDuration(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		if d == time.Hour {
			return "an hour"
		}
		return fmt.Sprintf("%d hours", int(d/time.Hour))
	case d >= time.Minute:
		return fmt.Sprintf("%d minutes", int(d/time.Minute))
	}
	return d.String()
}

func shieldStepWords(st shield.Step) string {
	where := map[string]string{shield.Admin: "the admin", shield.Site: "the site", shield.All: "the admin and the site"}[st.Where]
	dur := roughDuration(time.Duration(st.For))
	switch st.Action {
	case "slow-source":
		return "slow the source on " + where + " for " + dur
	case "block-source":
		return "block the source from " + where + " for " + dur
	case "block-network":
		return "block its network from " + where + " for " + dur
	case "block-provider":
		return "block its provider from " + where + " for " + dur
	case "shield-feature":
		f := st.Feature
		if f == "subject" {
			f = "that one"
		}
		if st.Level == shield.Limited {
			return "limit " + f + " to quoting pages for " + dur
		}
		return "turn " + f + " off for " + dur
	case "lockdown":
		return "lock the admin to passkeys and single sign-on for " + dur
	case "freeze":
		return "stop publishing for " + dur
	case "pause-agent":
		return "pause the agent for " + dur
	case "notify":
		return "tell the security contact"
	case "open-case":
		return "open a case"
	}
	return st.Action
}

func shieldPrecision(r shield.Record) string {
	if r.Applied == 0 {
		return "Has not acted yet."
	}
	rate, low, high, enough := r.Precision()
	s := fmt.Sprintf("Applied %d.", r.Applied)
	switch {
	case r.Right+r.Mistakes == 0:
		s += " None judged yet."
	case !enough:
		s += fmt.Sprintf(" %d judged right, %d a mistake: %d verdicts are needed to say how often it is right.",
			r.Right, r.Mistakes, shield.MinVerdicts)
	default:
		s += fmt.Sprintf(" Right %.0f%% of the time (95%% interval %.0f–%.0f%%).", rate*100, low*100, high*100)
	}
	if r.LiftedEarly > 0 {
		s += fmt.Sprintf(" %d lifted early without a verdict.", r.LiftedEarly)
	}
	return s
}

func shieldProposalWords(p shield.Proposal) string {
	switch {
	case p.Release:
		return "Let every playbook act again"
	case p.Remove:
		return "Remove the playbook " + p.Playbook.Name
	}
	verb := map[string]string{"act": "act", "watch": "watch only", "off": "be off"}[p.Playbook.Mode]
	return fmt.Sprintf("Make %s %s", p.Playbook.Name, verb)
}

func (s *Server) handleShieldAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	back := func(k, v string) {
		http.Redirect(w, r, "/security/shield?"+url.Values{k: {v}}.Encode(), http.StatusSeeOther)
	}
	if s.ShieldAdmin == nil {
		back("e", "This build has no shield.")
		return
	}
	if p.Limits.ReadOnly {
		http.Error(w, "this token is read-only", http.StatusForbidden)
		return
	}
	// The shield decides who gets in and what Quilzo does on its own.
	if !s.shieldSiteAdmin(p) {
		back("e", "Changing the shield takes an administrator of the whole site.")
		return
	}
	root, now := s.ShieldAdmin.Root, time.Now()
	changed := func() {
		if s.ShieldAdmin.Changed != nil {
			s.ShieldAdmin.Changed()
		}
	}
	audit := func(action string, detail map[string]string) {
		detail["by"] = p.Name
		s.audit("shield."+action, "/security/shield", detail)
	}
	id := strings.TrimSpace(r.FormValue("id"))
	why := strings.TrimSpace(r.FormValue("why"))
	switch r.FormValue("do") {
	case "lift":
		lifted, err := shield.Lift(root, id, p.Name, now)
		if err != nil {
			back("e", err.Error())
			return
		}
		verdict := ""
		if r.FormValue("mistake") == "1" {
			verdict = shield.Mistake
			for _, x := range lifted {
				_, _ = shield.Judge(root, x.ID, shield.Mistake, p.Name, now)
			}
		}
		for _, x := range lifted {
			audit("lifted", map[string]string{"id": x.ID, "what": shield.Describe(x), "verdict": verdict})
		}
		changed()
		msg := fmt.Sprintf("Lifted %d protections.", len(lifted))
		if len(lifted) == 1 {
			msg = "Lifted the protection that " + shield.Describe(lifted[0]) + "."
		}
		if verdict != "" {
			msg += " Counted as a mistake against its playbook."
		}
		back("m", msg)
	case "judge":
		v := r.FormValue("verdict")
		x, err := shield.Judge(root, id, v, p.Name, now)
		if err != nil {
			back("e", err.Error())
			return
		}
		audit("judged", map[string]string{"id": x.ID, "verdict": v, "playbook": x.Playbook})
		back("m", "Recorded. It counts toward how often "+x.Playbook+" is right.")
	case "hold":
		if err := shield.HoldAll(root, p.Name, why, now); err != nil {
			back("e", err.Error())
			return
		}
		audit("held", map[string]string{"why": why})
		changed()
		back("m", "Every playbook now watches. Letting them act again takes a second administrator.")
	case "release":
		q, err := shield.ProposeRelease(root, why, p.Name, now)
		if err != nil {
			back("e", err.Error())
			return
		}
		audit("release-proposed", map[string]string{"proposal": q.ID, "why": why})
		back("m", "Proposed. Another administrator approves it here.")
	case "mode":
		bk, err := shield.LoadBook(root)
		if err != nil {
			back("e", err.Error())
			return
		}
		var pb shield.Playbook
		found := false
		for _, x := range bk.InForce() {
			if x.Name == r.FormValue("name") {
				pb, found = x, true
			}
		}
		if !found {
			back("e", "There is no such playbook.")
			return
		}
		pb.Mode = r.FormValue("mode")
		q, err := shield.Propose(root, pb, false, why, p.Name, now)
		if err != nil {
			back("e", err.Error())
			return
		}
		audit("playbook-proposed", map[string]string{"proposal": q.ID, "change": shieldProposalWords(q), "why": why})
		back("m", shieldProposalWords(q)+": proposed. Another administrator approves it here.")
	case "approve", "decline":
		only := s.ShieldAdmin.OnlyAdmin != nil && s.ShieldAdmin.OnlyAdmin(p.Name)
		q, err := shield.Decide(root, id, p.Name, r.FormValue("do") == "approve", only, now)
		if err != nil {
			back("e", err.Error())
			return
		}
		audit("playbook-"+q.Outcome, map[string]string{"proposal": q.ID, "change": shieldProposalWords(q),
			"proposed_by": q.By, "alone": strconv.FormatBool(q.Alone)})
		changed()
		back("m", shieldProposalWords(q)+": "+q.Outcome+".")
	case "withdraw":
		q, err := shield.Withdraw(root, id, p.Name, now)
		if err != nil {
			back("e", err.Error())
			return
		}
		audit("playbook-withdrawn", map[string]string{"proposal": q.ID})
		back("m", "Withdrawn.")
	case "apply":
		x, err := shieldFromForm(r, p.Name, now)
		if err != nil {
			back("e", err.Error())
			return
		}
		// A lockdown nobody can get past locks everybody out of the admin,
		// the person setting it first. The machine's command line still
		// can, for somebody who means it.
		if x.Kind == shield.Lockdown && (s.ShieldAdmin.CanLockdown == nil || !s.ShieldAdmin.CanLockdown()) {
			back("e", "Nobody here has a passkey or single sign-on, so a lockdown would lock everybody out of the admin, you included. Add a passkey on your profile first; on the machine, quilzo shield lockdown still works.")
			return
		}
		applied, _, err := shield.Apply(root, x, now)
		if err != nil {
			back("e", err.Error())
			return
		}
		audit("applied", map[string]string{"id": applied.ID, "kind": applied.Kind, "target": applied.Target,
			"where": applied.Where, "until": applied.Until.UTC().Format(time.RFC3339), "reason": applied.Reason})
		changed()
		back("m", sentenceCase(shield.Describe(applied))+".")
	case "trust-add", "trust-remove":
		network := strings.TrimSpace(r.FormValue("network"))
		add := r.FormValue("do") == "trust-add"
		if err := shield.Trust(root, network, add, now); err != nil {
			back("e", err.Error())
			return
		}
		audit(r.FormValue("do"), map[string]string{"network": network})
		changed()
		if add {
			back("m", network+" is never blocked.")
		} else {
			back("m", network+" is no longer trusted.")
		}
	case "decoy-add":
		secret, d, err := shield.AddDecoy(root, r.FormValue("where"), p.Name, now)
		if err != nil {
			back("e", err.Error())
			return
		}
		audit("decoy-planted", map[string]string{"decoy": d.ID, "planted": d.Note})
		changed()
		// Shown on this answer and nowhere else: never in a redirect, which
		// would put it in the address bar and the history.
		w.Header().Set("Cache-Control", "no-store")
		data := map[string]any{"Title": "Shield", "Nav": "shield", "Principal": p,
			"Planted": map[string]string{"ID": d.ID, "Note": d.Note, "Secret": secret}}
		s.render(w, r, "shield.html", data)
	case "decoy-remove":
		if err := shield.RemoveDecoy(root, id, now); err != nil {
			back("e", err.Error())
			return
		}
		audit("decoy-removed", map[string]string{"decoy": id})
		changed()
		back("m", "Removed. Presenting it is now an ordinary wrong token.")
	default:
		back("e", "Nothing to do.")
	}
}

// shieldFromForm is a protection a person set on the screen.
func shieldFromForm(r *http.Request, by string, now time.Time) (shield.Protection, error) {
	dur, err := time.ParseDuration(r.FormValue("for"))
	if err != nil {
		return shield.Protection{}, fmt.Errorf("%q is not a length of time", r.FormValue("for"))
	}
	x := shield.Protection{By: by, Reason: strings.TrimSpace(r.FormValue("reason")), Until: now.Add(dur)}
	target := strings.TrimSpace(r.FormValue("target"))
	switch r.FormValue("kind") {
	case "block", "slow":
		x.Kind, x.Where = shield.Block, r.FormValue("where")
		if r.FormValue("kind") == "slow" {
			x.Kind = shield.Slow
		}
		switch {
		case strings.HasPrefix(target, "p_"):
			x.Target = "source:" + target
		case strings.Contains(target, "/"):
			x.Target = "net:" + target
		case strings.HasPrefix(strings.ToUpper(target), "AS"):
			x.Target = "asn:" + strings.TrimPrefix(strings.ToUpper(target), "AS")
		default:
			return x, fmt.Errorf("block a source by its handle (p_… in the log), a network like 203.0.113.0/24, or a provider like AS64500")
		}
	case "feature":
		x.Kind, x.Target, x.Level = shield.Feature, target, r.FormValue("level")
		if x.Level == "" {
			x.Level = shield.Off
		}
	case "lockdown":
		x.Kind = shield.Lockdown
	case "freeze":
		x.Kind = shield.Freeze
	case "pause":
		x.Kind, x.Target = shield.Agent, target
	case "cut":
		x.Kind, x.Target = shield.Route, target
	case "suspend":
		x.Kind, x.Target = shield.Token, target
	case "quarantine":
		x.Kind, x.Target, x.Level = shield.Feature, "upload:"+target, shield.Off
	default:
		return x, fmt.Errorf("choose what to do")
	}
	return x, nil
}
