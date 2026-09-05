package main

import (
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/marking"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The deployment's classification scheme, read from configuration.
//
// Nil when nothing is configured, which is the default and is most
// deployments. A scheme that is half configured — levels and no banner, or a
// banner naming a level that is not in the list — is refused rather than
// applied, because a banner that silently failed to apply is the exact
// outcome the whole mechanism exists to prevent.

func markingFrom(cfg *config.Config) (*marking.Policy, error) {
	levels := splitList(cfg.Raw("marking.levels"))
	banner := strings.TrimSpace(cfg.Raw("marking.banner"))
	controls := splitList(cfg.Raw("marking.controls"))

	if len(levels) == 0 && banner == "" {
		return nil, nil
	}
	if len(levels) == 0 {
		return nil, fmt.Errorf(
			"marking.banner is set and marking.levels is empty, so there is " +
				"no order to compare against and nothing can be refused for " +
				"being above the banner. Set the levels, lowest first")
	}
	if banner == "" {
		return nil, fmt.Errorf(
			"marking.levels is set and marking.banner is empty, so no page " +
				"would carry a banner. Set the marking this deployment " +
				"carries as a whole")
	}

	p := &marking.Policy{Levels: levels, Banner: banner, Controls: controls}
	// The deployment's own banner has to parse against its own register. It
	// is the one marking every page carries, so a typo in it is a typo on
	// everything.
	if _, err := p.Parse(banner); err != nil {
		return nil, fmt.Errorf("marking.banner does not parse: %w", err)
	}
	return p, nil
}

// cmdMarking prints the scheme and what it would refuse.
func cmdMarking(root string, args []string) error {
	if len(args) > 1 || (len(args) == 1 && args[0] != "show" && args[0] != "check") {
		return fmt.Errorf("usage: quilzo marking [show|check PAGE-BANNER]")
	}

	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	p, err := markingFrom(cfg)
	if err != nil {
		return err
	}
	if p == nil {
		if w.JSON(map[string]any{"marking": false}) {
			return nil
		}
		w.Human("%sthis deployment does not mark%s\n", bold, reset)
		w.Human("\n  %sset marking.levels and marking.banner to turn it on. "+
			"Nothing\n  ships with a vocabulary: the levels and controls are "+
			"read from your\n  own register, because a copy of somebody's "+
			"controlled register that\n  goes stale accepts markings it "+
			"should refuse.%s\n", dim, reset)
		return nil
	}

	if w.JSON(map[string]any{
		"marking": true, "banner": p.Banner,
		"levels": p.Levels, "controls": p.Controls,
	}) {
		return nil
	}
	w.Human("%s%s%s\n", bold, p.Banner, reset)
	w.Human("  %son every page, top and bottom, and in every export%s\n",
		dim, reset)
	w.Human("\n  levels    %s\n", strings.Join(p.Levels, " < "))
	if len(p.Controls) > 0 {
		w.Human("  controls  %s\n", strings.Join(p.Controls, ", "))
	}
	w.Human("\n  %sa page marked above %s is refused at publish. That is the%s\n",
		dim, p.Banner, reset)
	w.Human("  %scontrol; everything else here is placement%s\n", dim, reset)
	return nil
}

// checkMarking refuses a publication that would put content above the banner.
//
// The one control here that is not placement. Everything else — the banner on
// every page, in every export — is making the marking visible. This is
// stopping content reaching a network accredited for less than it carries,
// and it is silent otherwise: the page renders, the banner at the top says
// the site's level, and the content underneath is higher than the banner
// claims.
//
// A page declares its own marking in a "classification" field. Absent means
// the page is at the deployment's level, which is true of most of them —
// requiring every page to repeat it is how people start pasting markings
// without reading them, which is the failure the scheme exists to prevent.
func checkMarking(root string, s *store.Store, target string) error {
	cfg, err := loadConfig(root)
	if err != nil {
		return nil // a store with no config marks nothing
	}
	p, err := markingFrom(cfg)
	if err != nil {
		return err
	}
	if p == nil {
		return nil
	}

	commit := target
	if commit == "" {
		commit = s.GetRef(site.RefDraft)
	}
	if commit == "" {
		return nil
	}
	pages, err := site.PagesAt(s, commit)
	if err != nil {
		return nil
	}

	var refused []string
	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		fields, ok := pages[name].(map[string]any)
		if !ok {
			continue
		}
		declared, _ := fields["classification"].(string)

		// A field may carry its own marking, named for the field it marks:
		// body_classification marks body. Checked upward only — a portion
		// below the page's banner is ordinary, and one above it is content
		// the banner does not cover.
		var portions []marking.Portion
		fieldNames := make([]string, 0, len(fields))
		for k := range fields {
			fieldNames = append(fieldNames, k)
		}
		sort.Strings(fieldNames)
		for _, k := range fieldNames {
			base, found := strings.CutSuffix(k, "_classification")
			if !found || base == "" {
				continue
			}
			if m, ok := fields[k].(string); ok && strings.TrimSpace(m) != "" {
				portions = append(portions,
					marking.Portion{Field: base, Marking: m})
			}
		}

		if err := p.CheckPortions(declared, portions); err != nil {
			refused = append(refused, fmt.Sprintf("  %s — %s", name, err))
		}
	}
	if len(refused) == 0 {
		return nil
	}
	return fmt.Errorf(
		"this publication is refused on classification:\n%s\n\n"+
			"  The deployment's banner is %s. Nothing here can be skipped "+
			"with a flag:\n  a page above the banner reaching a reader is "+
			"what marking exists to prevent.",
		strings.Join(refused, "\n"), p.Banner)
}

// cmdTransfer records or verifies a cross-domain transfer.
//
// An export already produces a directory somebody can carry across on
// removable media. What it was missing is the paperwork, and on an isolated
// network the paperwork is most of the control: what was transferred, when,
// who approved it, who carried it, and why.
func cmdTransfer(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(
			"usage: quilzo transfer record DIR --approved-by WHO " +
				"--carried-by WHO --reason WHY\n" +
				"       quilzo transfer verify DIR")
	}
	switch args[0] {
	case "record":
		return transferRecord(root, args[1:])
	case "verify":
		return transferVerify(args[1:])
	default:
		return fmt.Errorf("unknown transfer command %q; try record or verify",
			args[0])
	}
}

func transferRecord(root string, args []string) error {
	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	approved := fs.String("approved-by", "", "who authorised this transfer")
	carried := fs.String("carried-by", "", "who is carrying the media")
	reason := fs.String("reason", "", "why this is crossing")
	from := fs.String("from", "", "the network it leaves")
	to := fs.String("to", "", "the network it arrives on")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: quilzo transfer record DIR --approved-by " +
			"WHO --carried-by WHO --reason WHY")
	}

	banner := ""
	if cfg, err := loadConfig(root); err == nil {
		if p, perr := markingFrom(cfg); perr == nil && p != nil {
			banner = p.Banner
		}
	}

	rec, err := marking.RecordTransfer(rest[0], marking.Transfer{
		Banner: banner, Approved: *approved, Carried: *carried,
		Reason: *reason, From: *from, To: *to,
	}, time.Now())
	if err != nil {
		return err
	}

	if w.JSON(map[string]any{
		"files": len(rec.Files), "bytes": rec.Bytes, "banner": rec.Banner,
	}) {
		return nil
	}
	w.Human("%s%d file(s), %d kB%s\n", bold, len(rec.Files), rec.Bytes/1000, reset)
	if rec.Banner != "" {
		w.Human("  %s\n", rec.Banner)
	}
	w.Human("  approved by %s, carried by %s\n", rec.Approved, rec.Carried)
	w.Human("\n  %sthe manifest travels with it. On the other side:%s\n",
		dim, reset)
	w.Human("    quilzo transfer verify DIR\n")
	return nil
}

func transferVerify(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo transfer verify DIR")
	}
	rec, problems, err := marking.VerifyTransfer(args[0])
	if err != nil {
		return err
	}

	if w.JSON(map[string]any{
		"verified": len(problems) == 0, "problems": problems,
		"files": len(rec.Files), "approved_by": rec.Approved,
		"carried_by": rec.Carried, "reason": rec.Reason,
	}) {
		if len(problems) > 0 {
			return errBlocked{fmt.Errorf("%d problem(s)", len(problems))}
		}
		return nil
	}

	if len(problems) == 0 {
		w.Human("%sverified%s  %d file(s)\n", bold, reset, len(rec.Files))
		w.Human("  %s left %s on %s, approved by %s, carried by %s%s\n",
			dim, orDash(rec.From), rec.Created, rec.Approved, rec.Carried, reset)
		w.Human("  %sreason: %s%s\n", dim, rec.Reason, reset)
		return nil
	}
	w.Human("%s%d problem(s)%s\n", bold, len(problems), reset)
	for _, p := range problems {
		w.Human("  %s\n", p)
	}
	return errBlocked{fmt.Errorf(
		"what arrived is not what left. A file that is present and not on " +
			"the manifest is the one to look at first: it joined the " +
			"transfer somewhere between the two networks")}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
