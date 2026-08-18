package main

import (
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/logd"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/provenance"
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
		s.Audit = events
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
	return s
}

func observeContent(root, tplDir string, st *store.Store) posture.ContentFacts {
	var c posture.ContentFacts

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
	default:
		return fmt.Errorf("unknown posture command %q; try scan, explain, rules "+
			"or suppress", args[0])
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
