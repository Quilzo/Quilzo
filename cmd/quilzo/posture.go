// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/logd"
	"github.com/quilzo/quilzo/internal/oscal"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/agentwatch"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/frameworks"
	"github.com/quilzo/quilzo/internal/oauthas"
	"github.com/quilzo/quilzo/internal/odp"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/sandbox"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/tmpl"
)

func suppressPath(root string) string {
	return filepath.Join(root, "suppressions.json")
}

type suppressionFile struct {
	Suppressions []posture.Suppression `json:"suppressions"`
}

// Observe is the only place in this program that turns files, sockets and the
// clock into facts the scanner can see.
//
// Everything the rules reason about passes through here, which means the
// scanner's entire view of the world is one function long and can be read in a
// sitting. That is the point of keeping the rules pure: the answer to "what
// could this check possibly touch?" is this file, and nothing else.
//
// Errors are recorded as absence rather than propagated. A scanner that refuses
// to report anything because one input was unreadable is a scanner that goes
// quiet exactly when something is wrong — so a missing input becomes an entry in
// NotChecked, and the report says plainly what it could not see.
func Observe(root, tplDir string, srv posture.ServerFacts) posture.State {
	s := posture.State{Now: time.Now(), Server: srv}

	// Single sign-on: what each SAML provider's trust ends, and whether its
	// configuration still holds together.
	if all, err := loadSAML(root); err == nil {
		s.SSO.Checked = true
		for _, c := range all {
			p := posture.SSOProvider{Name: c.Name}
			if err := c.Validate(); err != nil {
				p.Problem = err.Error()
			}
			if certs, err := c.Certificates(); err == nil {
				for _, cert := range certs {
					p.Expires = append(p.Expires, cert.NotAfter)
				}
			}
			s.SSO.Providers = append(s.SSO.Providers, p)
		}
	}

	// The agent interface: whether it answers, which apps may connect, and
	// which connections hold administrator scope.
	{
		cfg := mustConfig(root)
		st := &oauthas.Store{Dir: oauthDir(root)}
		if _, hosts, err := st.Clients(); err == nil {
			s.Interface.Checked, s.Interface.On, s.Interface.Hosts = true, cfg.Bool("mcp.remote"), hosts
		}
		if grants, err := st.Grants(); err == nil {
			for _, g := range grants {
				if g.Live(s.Now) && oauthas.RoleFor(g.Scopes) == auth.RoleAdmin {
					s.Interface.Admin = append(s.Interface.Admin, g.ID+" ("+g.ClientName+" for "+g.Principal+")")
				}
			}
		}
	}

	// Extensions, and whether anything confines them.
	//
	// Checked is set whichever way the answer comes out, because the scanner
	// reports "not looked at" separately from "nothing found" — and an
	// unreadable registry reported as zero extensions is a clean bill of
	// health for a store nobody inspected.
	if reg, err := loadExts(root); err == nil {
		s.Ext = posture.ExtFacts{Registered: len(reg.Extensions), Checked: true}
		if sandbox.Supported() {
			s.Ext.Sandboxed = true
			// Below ABI 4 the kernel has no network rules, so the sandbox
			// bounds what an extension can read and not what it can send.
			s.Ext.NetworkOpen = sandbox.ABI() < 4
		} else {
			s.Ext.Why = "this kernel has no Landlock (Linux 5.13 or later)"
		}
	}

	// Whether any log head has been published outside this machine. Supplied
	// even when the answer is none, because an absent key means "not looked at"
	// and the scanner reports those separately — a finding about data nobody
	// gathered is the failure that makes a scanner ignorable.
	heads := &headFile{}
	if err := loadJSON(headsPath(root), heads); err == nil {
		s.Extra = map[string]string{
			"published_heads": fmt.Sprintf("%d", len(heads.Heads)),
		}
		if n := len(heads.Heads); n > 0 {
			s.Extra["published_head_size"] = fmt.Sprintf("%d", heads.Heads[n-1].Size)
		}

		// Whether the log writer is separated, and whether it is answering.
		// Reported as three states rather than a boolean, because "configured
		// and not answering" is worse than "not configured" and collapsing them
		// would hide the worse one.
		switch sock := logSocketPath(root); {
		case !fileExists(sock):
			s.Extra["log_writer"] = "none"
		default:
			if ok, _ := logd.CheckOwnership(auditPath(root), os.Geteuid()); ok {
				s.Extra["log_writer"] = "separated"
			} else {
				s.Extra["log_writer"] = "same-account"
			}
		}
	}

	if pol, err := loadPolicy(root); err == nil {
		s.Policy = pol
	}
	if toks, err := loadTokens(root); err == nil {
		s.Tokens = toks
	}
	if types, err := schema.Load(root); err == nil {
		s.Types = types
	}
	if events, err := audit.Read(auditPath(root)); err == nil {
		s.Audit, s.AuditRead = events, true
	}

	// File modes. Only files that hold something worth protecting: listing
	// every file would bury the three that matter.
	// The audit log and its key are group-shared when the writer has been
	// separated out, because the CMS has to read what it is not allowed to
	// write. Everything else stays private to one account.
	separated := auditDir(root) != root
	for _, f := range []struct {
		path, desc string
		shared     bool
	}{
		{tokensPath(root), "token hashes and their roles", false},
		{policyPath(root), "who can do what", false},
		{auditPath(root), "the tamper-evident record", separated},
		{auditKeyPath(root), "the pseudonymisation key", separated},
		{suppressPath(root), "accepted risks", false},
		{filepath.Join(root, "types.json"), "content types and validation records", false},
	} {
		fact := posture.FileFact{
			Path: f.path, Description: f.desc, SharedWithGroup: f.shared}
		if info, err := os.Stat(f.path); err == nil {
			fact.Exists = true
			fact.Mode = uint32(info.Mode().Perm())
		}
		s.Files = append(s.Files, fact)
	}

	// The organisation's policy, and every setting below it.
	if pol, err := odp.Load(paramsPath(root)); err != nil {
		s.Parameters = posture.ParameterFacts{Checked: true, Unreadable: err.Error()}
	} else if cfg, err := loadConfig(root); err == nil {
		s.Parameters.Checked = true
		for _, u := range cfg.Unmet() {
			s.Parameters.Unmet = append(s.Parameters.Unmet, posture.ParameterGap{Param: u.Floor.Param,
				Setting: u.Key, Value: u.Value, Declared: inline(u.Floor.Declared)})
		}
		for _, d := range pol.Declared {
			if d.Alone {
				s.Parameters.Alone = append(s.Parameters.Alone, d.Param)
			}
		}
	}

	if cfg, err := loadConfig(root); err == nil {
		for _, e := range cfg.Weakened() {
			ws := posture.WeakenedSetting{
				Key: e.Setting.Key, Value: e.Value, Why: e.Why,
				Expired: e.Expired,
			}
			if e.Accepted != nil {
				ws.Accepted, ws.Reason, ws.By = true, e.Accepted.Reason, e.Accepted.By
			}
			s.Weakened = append(s.Weakened, ws)
		}
	}

	st, err := open(root)
	if err != nil {
		return s
	}
	s.Content = observeContent(root, tplDir, st)
	s.Agents = observeAgents(root, st, tplDir)
	s.AI = observeAI(root, tplDir, s.Audit)
	s.Upkeep = observeUpkeep(root, st)
	return s
}

// observeUpkeep counts the work that was supposed to have happened by now.
//
// Both counts are read off the disk rather than from a record of whether a
// timer ran. A rule that asks "did cron fire" needs somewhere to write down
// that it did, and then calls a healthy store broken the first time that
// record is lost. Asking "is there a submission older than its form allows"
// needs no bookkeeping and answers the question somebody actually has.
func observeUpkeep(root string, st *store.Store) posture.UpkeepFacts {
	var u posture.UpkeepFacts
	now := time.Now()

	// Submissions past the ceiling their own form declares.
	if subs, err := openSubmissions(root); err == nil {
		if set, ferr := loadForms(root); ferr == nil && set != nil {
			u.Checked = true
			for _, f := range set.Forms {
				list, lerr := subs.List(f.Name)
				if lerr != nil {
					continue
				}
				cutoff := now.Add(-f.Retention()).Unix()
				for _, sub := range list {
					if sub.At < cutoff {
						u.ExpiredSubmissions++
					}
				}
			}
		}
	}

	// Publishes whose moment has passed. An entry whose commit is no longer
	// the draft is skipped: scheduleRun refuses that one on purpose, so
	// counting it here would report a permanent finding for something working
	// as designed.
	if sch, err := loadSchedule(root); err == nil && sch != nil {
		u.Checked = true
		draft := st.GetRef(site.RefDraft)
		for _, e := range sch.Due(now) {
			if draft != "" && e.Commit != draft {
				continue
			}
			u.OverdueEntries++
			if waited := now.Sub(time.Unix(e.At, 0)); waited > u.OldestOverdue {
				u.OldestOverdue = waited
			}
		}
	}
	return u
}

func observeContent(root, tplDir string, st *store.Store) posture.ContentFacts {
	var c posture.ContentFacts
	if set, err := loadForms(root); err == nil && set != nil {
		for _, f := range set.Forms {
			if !f.Closed && !f.Lawful() {
				c.FormsWithoutBasis = append(c.FormsWithoutBasis, f.Name)
			}
		}
		sort.Strings(c.FormsWithoutBasis)
	}

	live := st.GetRef(site.RefLive)
	if live == "" {
		return c
	}
	if commit, err := st.GetCommit(live); err == nil {
		c.PublishedAt = commit.At
	}

	pages, err := site.PagesAt(st, live)
	if err != nil {
		return c
	}
	for name := range pages {
		c.LivePages = append(c.LivePages, name)
	}
	sort.Strings(c.LivePages)

	// Provenance. The published tree gives page name to content id, which is
	// exactly what Check compares against.
	if tree, err := pageHashes(st, live); err == nil {
		if idx, err := loadProvenance(root); err == nil {
			for _, s := range provenance.Check(idx, tree) {
				switch {
				case !s.Have:
					c.UnmarkedPages = append(c.UnmarkedPages, s.Page)
				case s.Stale:
					c.StalePages = append(c.StalePages, s.Page)
				}
			}
		}
	}

	// Templates that disable escaping.
	if tplDir != "" {
		_ = filepath.Walk(tplDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".html") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if sites := tmpl.RawSites(string(raw)); len(sites) > 0 {
				c.RawTemplates = append(c.RawTemplates, path)
			}
			return nil
		})
		sort.Strings(c.RawTemplates)

		// Accessibility of what is actually live. The gate runs before publish;
		// this asks whether anything got past it.
		if reports, err := checkAccessibility(root, st, live, tplDir); err == nil {
			c.BlockingA11y = a11y.BlockingCount(reports)
		} else {
			// Not run is not passing: a live site this cannot render is
			// one whose accessibility nobody knows.
			c.A11yUnchecked = err.Error()
		}
	}

	// The stamp is taken over the live root, so that is what is looked up.
	if stamps, err := loadStamps(root); err == nil {
		if stamp, ok := stamps.Latest(live); ok {
			if at, err := time.Parse(time.RFC3339, stamp.RequestedAt); err == nil {
				c.LastTimestamped = at.Unix()
			}
		}
	}
	return c
}

// observeAgents reports on the machine-facing surface by building the same
// server the mcp command serves and inspecting what it registered.
//
// Asking the real registry rather than keeping a second list is deliberate: two
// lists drift, and the one that drifts is always the one used for checking.
func observeAgents(root string, st *store.Store, tplDir string) posture.AgentFacts {
	facts := posture.AgentFacts{Enabled: true}
	// A caller is needed to build the server, but not to enumerate what it
	// registered: the registration is static and the authorisation happens
	// inside each handler.
	srv := buildMCP(root, st, &Caller{Name: "posture-scan"}, tplDir)
	for _, op := range srv.Operations() {
		if op.Writes && op.NeedsRole == "" {
			facts.WriteOpsWithoutRole = append(facts.WriteOpsWithoutRole, op.Name)
		}
	}
	sort.Strings(facts.WriteOpsWithoutRole)
	return facts
}

func loadSuppressions(root string) ([]posture.Suppression, error) {
	f := &suppressionFile{}
	if err := loadJSON(suppressPath(root), f); err != nil {
		return nil, err
	}
	return f.Suppressions, nil
}

func cmdPosture(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"scan"}
	}
	switch args[0] {
	case "scan":
		return postureScan(root, args[1:])
	case "explain":
		return postureExplain(args[1:])
	case "rules":
		return postureRules()
	case "suppress":
		return postureSuppress(root, args[1:])
	case "frameworks":
		return postureFrameworks(root, args[1:])
	default:
		return fmt.Errorf("unknown posture command %q; try scan, explain, "+
			"rules, frameworks or suppress", args[0])
	}
}

func postureScan(root string, args []string) error {
	pos, flags := leadingArgs(args, 0)
	_ = pos
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	tplDir := fs.String("templates", "templates", "template directory")
	minSev := fs.String("min", "low", "lowest severity to report")
	failOn := fs.String("fail-on", "high", "severity that makes this exit non-zero")
	adminAddr := fs.String("admin-addr", "", "how the admin is exposed, if running")
	publicAddr := fs.String("public-addr", "", "how the site is exposed, if running")
	proxy := fs.Bool("behind-proxy", false, "a reverse proxy terminates TLS")
	asOSCAL := fs.Bool("oscal", false,
		"emit OSCAL assessment results instead of a report")
	if err := fs.Parse(flags); err != nil {
		return err
	}

	state := Observe(root, *tplDir, posture.ServerFacts{
		AdminAddr: *adminAddr, PublicAddr: *publicAddr, BehindProxy: *proxy,
	})
	sup, _ := loadSuppressions(root)
	rep := posture.Scan(state, sup)

	floor := posture.Severity(*minSev)
	var shown []posture.Finding
	for _, f := range rep.Findings {
		if f.Severity.AtLeast(floor) {
			shown = append(shown, f)
		}
	}

	// OSCAL, for a package an assessor's tooling ingests.
	//
	// FedRAMP 20x wants machine-checked evidence against a running system, and
	// new packages must carry OSCAL from 30 September 2026. This scan already
	// reads the deployment and already names the controls each rule bears on;
	// what was missing was the format. So this is a different rendering of the
	// same scan, not a second scan with different rules.
	if *asOSCAL {
		at, terr := time.Parse(time.RFC3339, rep.At)
		if terr != nil {
			at = time.Now()
		}
		doc, oerr := assessmentResults(root, rep, at)
		if oerr != nil {
			return oerr
		}
		body, merr := json.MarshalIndent(doc, "", "  ")
		if merr != nil {
			return merr
		}
		fmt.Println(string(body))
		return exitFor(rep, posture.Severity(*failOn))
	}

	if w.Mode == out.JSON {
		w.JSON(map[string]any{
			"at": rep.At, "score": rep.Score, "findings": shown,
			"counts": rep.Counts, "rules_checked": rep.Checked,
			"not_checked": rep.NotChecked, "suppressed": len(rep.Suppressed),
		})
		return exitFor(rep, posture.Severity(*failOn))
	}

	w.Human("%sposture %d/100%s   %s\n", bold, rep.Score, reset,
		summarise(rep))
	w.Human("  %s%d rules, %d suppressed%s\n\n",
		dim, rep.Checked, len(rep.Suppressed), reset)

	if len(shown) == 0 {
		w.Human("  %snothing at %s or above%s\n", green, floor, reset)
	}
	for _, f := range shown {
		w.Human("  %s%-8s%s %s\n", colourFor(f.Severity), f.Severity, reset, f.Title)
		w.Human("           %s\n", f.Detail)
		if f.Fix != "" {
			w.Human("           %sfix:%s %s\n", dim, reset, f.Fix)
		}
		meta := f.Rule
		if len(f.Controls) > 0 {
			meta += "  " + strings.Join(f.Controls, " ")
		}
		if f.OWASP != "" {
			meta += "  " + f.OWASP
		}
		w.Human("           %s%s%s\n\n", dim, meta, reset)
	}

	// What was not looked at, always, and last so it is the thing left on
	// screen. A report that lists three findings and stays quiet about the
	// inputs it never received reads as "everything else is fine".
	if len(rep.NotChecked) > 0 {
		w.Human("  %snot checked:%s\n", yellow, reset)
		for _, n := range rep.NotChecked {
			w.Human("    %s%s%s\n", dim, n, reset)
		}
	}
	return exitFor(rep, posture.Severity(*failOn))
}

func exitFor(rep posture.Report, threshold posture.Severity) error {
	for _, f := range rep.Findings {
		if f.Severity.AtLeast(threshold) {
			return errBlocked{fmt.Errorf(
				"%d finding(s) at %s or above", countAtLeast(rep, threshold), threshold)}
		}
	}
	return nil
}

func countAtLeast(rep posture.Report, s posture.Severity) int {
	n := 0
	for _, f := range rep.Findings {
		if f.Severity.AtLeast(s) {
			n++
		}
	}
	return n
}

func summarise(rep posture.Report) string {
	if len(rep.Findings) == 0 {
		return green + "no findings" + reset
	}
	var parts []string
	for _, s := range []posture.Severity{
		posture.Critical, posture.High, posture.Medium, posture.Low} {
		if n := rep.Counts[string(s)]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s%d %s%s",
				colourFor(s), n, s, reset))
		}
	}
	return strings.Join(parts, "  ")
}

func colourFor(s posture.Severity) string {
	switch s {
	case posture.Critical, posture.High:
		return red
	case posture.Medium:
		return yellow
	default:
		return dim
	}
}

func postureExplain(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo posture explain <rule-id>")
	}
	r, ok := posture.Explain(args[0])
	if !ok {
		return fmt.Errorf("there is no rule %q; run quilzo posture rules", args[0])
	}
	if w.JSON(map[string]any{
		"id": r.ID, "title": r.Title, "severity": r.Severity,
		"why": r.Why, "controls": r.Controls, "owasp": r.OWASP,
	}) {
		return nil
	}
	w.Human("%s%s%s  %s%s%s\n\n", bold, r.ID, reset, colourFor(r.Severity),
		r.Severity, reset)
	w.Human("%s\n\n", r.Title)
	w.Human("%s\n\n", wrap(r.Why, 74))
	w.Human("  %sNIST SP 800-53:%s %s\n", dim, reset, strings.Join(r.Controls, ", "))
	if r.OWASP != "" {
		w.Human("  %sOWASP:%s %s\n", dim, reset, r.OWASP)
	}
	return nil
}

func postureRules() error {
	rules := posture.Rules()
	if w.JSON(rules) {
		return nil
	}
	for _, r := range rules {
		w.Human("%s%-32s%s %s%-8s%s %s\n", bold, r.ID, reset,
			colourFor(r.Severity), r.Severity, reset, r.Title)
		w.Human("  %s%s%s\n", dim, strings.Join(r.Controls, " "), reset)
	}
	w.Human("\n%s%d rules. quilzo posture explain <id> for the reasoning.%s\n",
		dim, len(rules), reset)
	return nil
}

func postureSuppress(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("suppress", flag.ContinueOnError)
	reason := fs.String("reason", "", "why this is being accepted")
	by := fs.String("by", "", "who is accepting it")
	daysFor := fs.Int("days", 30, "how long, at most 90")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo posture suppress <finding-id> " +
			"--reason ... --by ... [--days N]")
	}
	if strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("a suppression needs a reason. An exception nobody " +
			"wrote down is indistinguishable from an oversight")
	}
	if strings.TrimSpace(*by) == "" {
		return fmt.Errorf("a suppression needs a name. Somebody is accepting " +
			"this risk and the record should say who")
	}
	limit := int(posture.MaxSuppression.Hours() / 24)
	if *daysFor > limit {
		return fmt.Errorf("%d days is past the %d-day limit. A longer exception "+
			"is a decision to stop looking, and the person making it will not be "+
			"the person who inherits it", *daysFor, limit)
	}

	f := &suppressionFile{}
	if err := loadJSON(suppressPath(root), f); err != nil {
		return err
	}
	now := time.Now()
	next := append([]posture.Suppression{}, f.Suppressions...)
	replaced := false
	for i, s := range next {
		if s.ID == pos[0] {
			next[i] = posture.Suppression{ID: pos[0], Reason: *reason, By: *by,
				Until: now.AddDate(0, 0, *daysFor).Unix(), AddedAt: now.Unix()}
			replaced = true
		}
	}
	if !replaced {
		next = append(next, posture.Suppression{ID: pos[0], Reason: *reason,
			By: *by, Until: now.AddDate(0, 0, *daysFor).Unix(), AddedAt: now.Unix()})
	}
	f.Suppressions = next
	if err := saveJSON(suppressPath(root), f); err != nil {
		return err
	}

	record(root, audit.Record{
		Action: "posture.suppress", Resource: pos[0], Outcome: audit.Success,
		Principal: *by, Kind: audit.KindHuman,
		Detail: map[string]string{
			"reason": truncate(*reason, 120),
			"until":  now.AddDate(0, 0, *daysFor).UTC().Format("2006-01-02"),
		},
	})

	w.Human("%s is silenced until %s\n", pos[0],
		now.AddDate(0, 0, *daysFor).UTC().Format("2006-01-02"))
	w.Human("  %sit will come back as a finding of its own when that passes%s\n",
		dim, reset)
	return nil
}

// wrap breaks text at a column, for the explain output.
func wrap(s string, width int) string {
	words := strings.Fields(s)
	var b strings.Builder
	col := 0
	for i, word := range words {
		if col+len(word) > width && i > 0 {
			b.WriteString("\n")
			col = 0
		} else if i > 0 {
			b.WriteString(" ")
			col++
		}
		b.WriteString(word)
		col += len(word)
	}
	return b.String()
}

// organisationOf is who runs this deployment, for an assessment document.
//
// Falls back to the site name rather than to a placeholder: an OSCAL party
// called "Unknown Organization" is worse than one named after the site, because
// an assessor reading the second knows what they are looking at.
func organisationOf(root string) string {
	cfg, err := loadConfig(root)
	if err != nil {
		return siteName(root)
	}
	if org := strings.TrimSpace(cfg.Raw("site.provider")); org != "" {
		return org
	}
	return siteName(root)
}

// observeAI gathers what the AI and privacy checks need: the chatbots, when
// each was last measured and whether its page says it is automated, where a
// model is reached, and which agents the watchdog has flagged.
func observeAI(root, tplDir string, events []audit.Event) posture.AIFacts {
	facts := posture.AIFacts{}
	set, err := assistant.Load(assistantsPath(root))
	if err != nil {
		return facts
	}
	lastEval := map[string]time.Time{}
	for _, e := range events {
		if e.Action != "assistant.evaluated" {
			continue
		}
		if at, perr := time.Parse(time.RFC3339Nano, e.At); perr == nil {
			name := strings.TrimPrefix(e.Resource, "/ask/")
			if at.After(lastEval[name]) {
				lastEval[name] = at
			}
		}
	}
	disclosed := askPageDiscloses(root, tplDir)
	for _, a := range set.Assistants {
		facts.Chatbots = append(facts.Chatbots, posture.ChatbotFact{
			Name: a.Name, Public: a.Public, UseModel: a.UseModel,
			Disclosed: disclosed, LastEval: lastEval[a.Name]})
	}
	if agents, aerr := loadAgents(root); aerr == nil {
		facts.Agents = len(agents.Agents)
		for name := range agents.Agents {
			f := posture.AgentEvalFact{Name: name}
			if cases, cerr := loadEvalCases(root, name); cerr == nil {
				f.Cases = len(cases)
			}
			if reps, rerr := evalReports(root, name, 1); rerr == nil && len(reps) > 0 {
				f.At, f.Hijacked = reps[0].At, reps[0].Hijacked
			}
			facts.Evals = append(facts.Evals, f)
			idf := posture.AgentIdentityFact{Name: name}
			if id := agents.identityOf(name); id != nil {
				idf.Sponsor, idf.Expires = id.Sponsor, id.Expires
				idf.SponsorActive = hasStanding(root, id.Sponsor)
			}
			facts.Identities = append(facts.Identities, idf)
		}
		facts.Tools = agentToolFacts(root, agents)
		sort.Slice(facts.Identities, func(i, j int) bool { return facts.Identities[i].Name < facts.Identities[j].Name })
		sort.Slice(facts.Evals, func(i, j int) bool { return facts.Evals[i].Name < facts.Evals[j].Name })
	}
	facts.ModelHost, facts.ModelLocal = modelHostOf(root)
	for _, r := range agentwatch.Flagged(agentwatch.Look(events, time.Now())) {
		facts.Flagged = append(facts.Flagged, r.Principal)
	}
	facts.Checked = true
	return facts
}

// agentToolFacts is every declared agent's tools on installed
// integrations: whether each is pinned, and what it became if its server
// changed it since and nobody has pinned it again.
func agentToolFacts(root string, agents *agentSet) []posture.AgentToolFact {
	installed, err := loadIntegrations(root)
	if err != nil || installed == nil {
		return nil
	}
	changes := loadToolChanges(root)
	var out []posture.AgentToolFact
	for name, m := range agents.Agents {
		for _, t := range m.Tools {
			in, err := installed.Resolve(t.Name)
			if err != nil {
				continue
			}
			pin := in.Pins[t.Name]
			f := posture.AgentToolFact{Agent: name, Integration: in.Name, Tool: t.Name, Pinned: pin != ""}
			if c, ok := changes[in.Name+"/"+t.Name]; ok && pin != "" && c.Pinned == pin {
				f.Changed = c.Now
			}
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Agent != out[j].Agent {
			return out[i].Agent < out[j].Agent
		}
		return out[i].Tool < out[j].Tool
	})
	return out
}

// askPageDiscloses reports whether the pages visitors see answers on say
// they come from an automated assistant. The built-in pages always do; an
// owner's published "ask" page does when its layout carries
// {{ ask.disclosure }}, and an owner's "search" page, which shows AI answers
// too, when its layout carries {{ answer.disclosure }}.
//
// What cannot be read is not disclosed: a store or a layout this cannot
// read is a check that did not run, and reporting it as passing is the
// direction that hides a breach of Article 50.
func askPageDiscloses(root, tplDir string) bool {
	st, err := open(root)
	if err != nil {
		return false
	}
	pages, err := site.PagesAt(st, site.RefLive)
	if err != nil {
		return false
	}
	if body, custom := pages["search"]; custom && !layoutCarries(tplDir, body, "answer.disclosure") {
		return false
	}
	body, custom := pages["ask"]
	if !custom {
		return true
	}
	return layoutCarries(tplDir, body, "ask.disclosure")
}

// layoutCarries reports whether the layout a page uses mentions a variable.
func layoutCarries(tplDir string, body any, variable string) bool {
	design, derr := loadDesign(tplDir)
	if derr != nil || design == nil {
		return false
	}
	page, _ := body.(map[string]any)
	_, src, lerr := design.Layouts.For(page)
	if lerr != nil {
		return false
	}
	return strings.Contains(strings.ReplaceAll(src, " ", ""), variable)
}

// modelHostOf is the host a model is reached on, and whether it is local:
// the first gateway route that is not, or the configured endpoint.
func modelHostOf(root string) (string, bool) {
	var urls []string
	if _, cfg, err := modelGateway(root); err == nil && cfg != nil {
		for _, r := range cfg.Routes {
			urls = append(urls, r.URL)
		}
	} else if base := os.Getenv("QUILZO_MODEL_URL"); base != "" {
		urls = append(urls, base)
	} else if os.Getenv("QUILZO_MODEL_KEY") != "" || os.Getenv("OLLAMA_API_KEY") != "" {
		urls = append(urls, "https://ollama.com/v1")
	}
	first, local := "", true
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		if first == "" {
			first = u.Host
		}
		if !hostIsLocal(u.Hostname()) {
			return u.Host, false
		}
	}
	return first, local
}

// hostIsLocal is this machine or a private network: somewhere what is sent
// does not leave the organisation running Quilzo.
func hostIsLocal(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// postureFrameworks reads the posture against the frameworks: every one
// with how many of its requirements are failing, passing and unchecked, or
// one framework requirement by requirement.
func postureFrameworks(root string, args []string) error {
	fs := flag.NewFlagSet("posture frameworks", flag.ContinueOnError)
	tplDir := fs.String("templates", "templates", "template directory")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	sup, _ := loadSuppressions(root)
	rep := posture.Scan(Observe(root, *tplDir, posture.ServerFacts{}), sup)
	if len(pos) == 0 {
		if w.JSON(frameworkSummaries(rep)) {
			return nil
		}
		for _, sm := range frameworkSummaries(rep) {
			fmt.Printf("  %-18s %s%3d failing%s  %3d passing  %3d not checked  %s%s%s\n",
				sm.ID, red, sm.Failing, reset, sm.Passing, sm.NotChecked,
				dim, sm.Name, reset)
		}
		fmt.Printf("\n  %sa requirement no check bears on is not listed: not "+
			"claimed, rather than passing. quilzo posture frameworks ID for one%s\n",
			dim, reset)
		return nil
	}
	fw, ok := frameworks.Get(pos[0])
	if !ok {
		var ids []string
		for _, f := range frameworks.Catalogue {
			ids = append(ids, f.ID)
		}
		return fmt.Errorf("no framework %q; one of %s", pos[0], strings.Join(ids, ", "))
	}
	view := posture.ByFramework(rep, fw.ID)
	if w.JSON(view) {
		return nil
	}
	fmt.Printf("%s%s%s  %s\n  %s%s%s\n\n", bold, fw.Name, reset, fw.Version, dim, fw.About, reset)
	for _, st := range view {
		colour := green
		switch st.State {
		case "failing":
			colour = red
		case "not checked":
			colour = yellow
		}
		fmt.Printf("  %-14s %s%-11s%s %s\n", st.Ref.ID, colour, st.State, reset,
			strings.Join(st.Rules, ", "))
		for _, f := range st.Findings {
			fmt.Printf("                 %s%s%s\n", dim, onOneLine(f.Detail), reset)
		}
	}
	return nil
}

// frameworkSummary is one framework in a line.
type frameworkSummary struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Failing    int    `json:"failing"`
	Passing    int    `json:"passing"`
	NotChecked int    `json:"not_checked"`
}

func frameworkSummaries(rep posture.Report) []frameworkSummary {
	var out []frameworkSummary
	for _, f := range frameworks.Catalogue {
		sm := frameworkSummary{ID: f.ID, Name: f.Name}
		for _, st := range posture.ByFramework(rep, f.ID) {
			switch st.State {
			case "failing":
				sm.Failing++
			case "passing":
				sm.Passing++
			default:
				sm.NotChecked++
			}
		}
		out = append(out, sm)
	}
	return out
}

// assessmentResults is a scan as OSCAL assessment results: every finding,
// and only the rules that ran. --min is for reading — a document that
// dropped a finding below it would list that rule's controls as reviewed
// and clean — and a rule whose input was never supplied reviewed nothing.
func assessmentResults(root string, rep posture.Report, at time.Time) (oscal.Results, error) {
	ran := posture.RuleIndex()
	for _, id := range rep.Skipped {
		delete(ran, id)
	}
	return oscal.From(rep.Findings, ran, at, oscal.Options{
		System:       siteName(root),
		Organisation: organisationOf(root),
		Version:      version,
	})
}
