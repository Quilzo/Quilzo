package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/codescan"
	"github.com/rsh1k/scrivet/internal/config"
	"github.com/rsh1k/scrivet/internal/csp"
	"github.com/rsh1k/scrivet/internal/out"
	"github.com/rsh1k/scrivet/internal/site"
)

func cmdScan(root string, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	tplDir := fs.String("templates", "templates", "where templates live")
	ref := fs.String("ref", site.RefDraft, "which content to scan")
	min := fs.String("min", "low", "lowest severity to report")
	failOn := fs.String("fail-on", "high",
		"severity that makes this exit non-zero, for CI")
	rulesOnly := fs.Bool("rules", false, "list the rules and stop")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rulesOnly {
		return scanRules()
	}

	inputs, err := collectInputs(root, *tplDir, *ref)
	if err != nil {
		return err
	}
	found := codescan.AtLeast(codescan.Scan(inputs), codescan.Severity(*min))

	if w.JSON(map[string]any{
		"scanned": len(inputs), "findings": found,
	}) {
		return scanExit(found, codescan.Severity(*failOn))
	}

	w.Human("%d file(s) and field(s) scanned, %d finding(s)\n", len(inputs),
		len(found))
	if len(found) == 0 {
		w.Human("  %snothing matched. That is not the same as being safe: "+
			"these are patterns,%s\n", dim, reset)
		w.Human("  %snot proofs, and a scanner only finds what somebody "+
			"thought to look for%s\n", dim, reset)
		return nil
	}
	for _, f := range found {
		colour := yellow
		if f.Severity == codescan.Critical || f.Severity == codescan.High {
			colour = red
		}
		where := f.Where
		if f.Line > 0 {
			where = fmt.Sprintf("%s:%d", f.Where, f.Line)
		}
		w.Human("\n  %s%-8s%s %s\n", colour, f.Severity, reset, where)
		w.Human("      %s\n", f.Detail)
		if f.Excerpt != "" {
			w.Human("      %s%s%s\n", dim, f.Excerpt, reset)
		}
		w.Human("      %sfix: %s%s\n", dim, f.Fix, reset)
		tags := f.Rule
		if len(f.Controls) > 0 {
			tags += "  " + strings.Join(f.Controls, " ")
		}
		if f.OWASP != "" {
			tags += "  " + f.OWASP
		}
		w.Human("      %s%s%s\n", dim, tags, reset)
	}
	return scanExit(found, codescan.Severity(*failOn))
}

// exitFor turns findings into an exit code.
//
// A gate refusing rather than the command failing, so a pipeline can tell
// "this found something" from "this could not run" — which is the distinction
// that decides whether a red build gets investigated or retried.
func scanExit(found []codescan.Finding, failOn codescan.Severity) error {
	if len(codescan.AtLeast(found, failOn)) == 0 {
		return nil
	}
	return errBlocked{fmt.Errorf(
		"%d finding(s) at %s or above", len(codescan.AtLeast(found, failOn)),
		failOn)}
}

func scanRules() error {
	rs := codescan.Rules()
	if w.JSON(rs) {
		return nil
	}
	for _, r := range rs {
		w.Human("%s%-28s%s %s\n", bold, r.ID, reset, r.Severity)
		w.Human("  %s%s%s\n", dim, r.Detail, reset)
	}
	w.Human("\n  %s%d rules%s\n", dim, len(rs), reset)
	return nil
}

// collectInputs gathers everything worth scanning.
//
// Templates from disk, content from the store, and the redirect map if there
// is one. Content is scanned field by field rather than as a serialised blob,
// so a finding names the page it is in and not a byte offset into JSON.
func collectInputs(root, tplDir, ref string) ([]codescan.Input, error) {
	var inputs []codescan.Input

	if entries, err := os.ReadDir(tplDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			switch filepath.Ext(e.Name()) {
			case ".html", ".htm", ".tmpl", ".js", ".css":
			default:
				continue
			}
			path := filepath.Join(tplDir, e.Name())
			body, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			inputs = append(inputs, codescan.Input{
				Name: path, Kind: codescan.Template, Body: string(body)})
		}
	}

	s, err := open(root)
	if err != nil {
		return inputs, nil // no store: templates alone is a usable scan
	}
	commit := s.GetRef(ref)
	if commit == "" {
		return inputs, nil
	}
	pages, err := site.PagesAt(s, commit)
	if err != nil {
		return inputs, nil
	}
	for name, v := range pages {
		fields, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for key, val := range fields {
			str, ok := val.(string)
			if !ok || str == "" {
				continue
			}
			// The field name is prepended as an assignment, because in
			// structured content that is what it is. A field called api_key
			// holding a high-entropy value is the same finding as
			// `api_key = "..."` in a file, and scanning the value alone
			// misses every one of them — the rule looks for a name and a
			// value, and the name was in the other column.
			inputs = append(inputs, codescan.Input{
				Name: name + "." + key, Kind: codescan.Content,
				Body: key + " = " + str})
		}
	}
	return inputs, nil
}

// -- the CSP generator --------------------------------------------------------

func cmdCSP(root string, args []string) error {
	fs := flag.NewFlagSet("csp", flag.ContinueOnError)
	ref := fs.String("ref", site.RefLive, "which content to read")
	mode := fs.String("mode", "", "enforce | report-only | off (default from config)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	commit := s.GetRef(*ref)
	if commit == "" {
		return fmt.Errorf("nothing is published, so there is no content to " +
			"derive a policy from.\n  A policy generated from an empty site " +
			"would permit nothing, which is correct and useless")
	}
	pages, err := site.PagesAt(s, commit)
	if err != nil {
		return err
	}

	p := buildCSP(cfg, pages)
	// The flag overrides the configured mode for this one run, so somebody can
	// see what report-only would look like without committing to it.
	if m := strings.TrimSpace(*mode); m != "" {
		p.Mode = csp.Mode(m)
	}
	header := p.Build()
	name, _ := p.Header()

	if w.JSON(map[string]any{
		"mode": p.Mode, "header": name, "value": header,
		"sources": p.Sources,
	}) {
		return nil
	}

	w.Human("%s%s%s\n%s\n", bold, name, reset, header)
	w.Human("\n  %sderived from %d published page(s)%s\n", dim, len(pages), reset)
	if n := len(p.Sources.Img) + len(p.Sources.Media) + len(p.Sources.Frame); n > 0 {
		w.Human("  %s%d external host(s) named, rather than a wildcard%s\n",
			dim, n, reset)
	}
	w.Human("\n  %sthis is served automatically; site.csp.mode changes whether "+
		"it is enforced%s\n", dim, reset)
	w.Human("  %shosts referenced from inside rich text are invisible here — "+
		"name them%s\n", dim, reset)
	w.Human("  %sin site.csp.extra_img and site.csp.extra_frame%s\n", dim, reset)
	return nil
}

// buildCSP is the one place a policy is assembled, so the header the site
// serves and the header `scrivet csp` prints cannot drift apart.
func buildCSP(cfg *config.Config, pages map[string]any) csp.Policy {
	src := csp.Collect(pages)
	src.Img = append(src.Img, cfg.Strings("site.csp.extra_img")...)
	src.Frame = append(src.Frame, cfg.Strings("site.csp.extra_frame")...)
	return csp.Policy{
		Mode:    csp.Mode(cfg.Raw("site.csp.mode")),
		Sources: src,
	}
}

var _ = out.ExitBlocked
var _ = audit.Success
