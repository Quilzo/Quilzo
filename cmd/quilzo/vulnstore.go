// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/vuln"
)

// The vulnerability queue, kept in the store.
//
// `vuln queue` ranked a file against a file in whatever directory it was run
// from, which is a calculation and not a register: nothing else could read
// it, and the screen had nothing to show. `vuln load` puts the inventory and
// the advisories in the store, checked line by line on the way in, and
// everything else — the queue, the plan, the screen, the trend — reads them
// from there.
//
// Loading replaces. An inventory is a statement of what is installed now,
// and one merged with last month's is a list of things that may or may not
// still exist.

// MaxVulnFile bounds one loaded file.
const MaxVulnFile = 64 << 20

func storedAdvisories(root string) string {
	return filepath.Join(vulnDir(root), "advisories.jsonl")
}

func storedInventory(root string) string {
	return filepath.Join(vulnDir(root), "inventory.jsonl")
}

func vulnHistoryPath(root string) string {
	return filepath.Join(vulnDir(root), "history.jsonl")
}

// vulnView is everything the queue is made of, read once.
type vulnView struct {
	Advisories  []vuln.Advisory
	Inventory   []vuln.Component
	Assessments []vuln.Assessment
	// Matched is every exposure, ranked, including what is decided away.
	Matched []vuln.Exposure
	History []vuln.Tally
	// Reach is what reading source established, per advisory and asset.
	Reach []vuln.Reach
	// Tree is the SSVC decision table, nil when none is loaded, and Tags
	// what this organisation says about its assets.
	Tree vuln.Tree
	Tags vuln.Tags
	// Loaded is when each file was last replaced; zero when never.
	AdvisoriesAt, InventoryAt time.Time
}

// Live is the part of the queue nobody has decided away.
func (v vulnView) Live() []vuln.Exposure {
	var out []vuln.Exposure
	for _, e := range v.Matched {
		if !e.Silenced {
			out = append(out, e)
		}
	}
	return out
}

func modTime(path string) time.Time {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime().UTC()
}

// loadVulnView reads the stored queue. Nothing loaded is an empty view with
// zero times, which a caller has to say out loud: an empty inventory and a
// clean one are the same list.
func loadVulnView(root string, now time.Time) (vulnView, error) {
	var v vulnView
	var err error
	if v.Advisories, err = loadAdvisories(storedAdvisories(root)); err != nil {
		return v, err
	}
	if v.Inventory, err = loadInventory(storedInventory(root)); err != nil {
		return v, err
	}
	if v.Assessments, err = loadAssessments(root); err != nil {
		return v, err
	}
	if v.History, err = loadVulnHistory(root); err != nil {
		return v, err
	}
	v.AdvisoriesAt = modTime(storedAdvisories(root))
	v.InventoryAt = modTime(storedInventory(root))
	if v.Reach, err = loadReach(root); err != nil {
		return v, err
	}
	if v.Tree, err = loadSSVCTree(root); err != nil {
		return v, err
	}
	if v.Tags, err = loadAssetTags(root); err != nil {
		return v, err
	}
	v.Matched = vuln.ApplyReach(vuln.Match(v.Advisories, v.Inventory,
		v.Assessments, now), v.Reach, now)
	return v, nil
}

func loadVulnHistory(root string) ([]vuln.Tally, error) {
	var out []vuln.Tally
	err := loadJSONL(vulnHistoryPath(root), func(b []byte) error {
		var t vuln.Tally
		if err := json.Unmarshal(b, &t); err != nil {
			return err
		}
		out = append(out, t)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, err
}

// saveVulnDay records today's tally, replacing an earlier one the same day.
func saveVulnDay(root string, t vuln.Tally) error {
	hist, err := loadVulnHistory(root)
	if err != nil {
		return err
	}
	day := t.At.UTC().Format("2006-01-02")
	kept := hist[:0]
	for _, h := range hist {
		if h.At.UTC().Format("2006-01-02") != day {
			kept = append(kept, h)
		}
	}
	kept = append(kept, t)
	sort.Slice(kept, func(i, j int) bool { return kept[i].At.Before(kept[j].At) })
	if len(kept) > maxHistory {
		kept = kept[len(kept)-maxHistory:]
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, h := range kept {
		if err := enc.Encode(h); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(vulnDir(root), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(vulnHistoryPath(root), buf.Bytes(), 0o600)
}

// tallyVulns recomputes the queue and records the day. Called after
// anything that changes it, and failures are returned: a trend with a
// silent gap reads as a day nothing was wrong.
func tallyVulns(root string, now time.Time) error {
	v, err := loadVulnView(root, now)
	if err != nil {
		return err
	}
	if len(v.Inventory) == 0 || len(v.Advisories) == 0 {
		// Nothing to compare is not a day with no vulnerabilities.
		return nil
	}
	return saveVulnDay(root, vuln.Summarise(v.Matched, now))
}

// storeJSONL checks a file line by line and replaces the stored copy with
// what passed, re-encoded — so what is stored is what was validated, and not
// whatever else the file had in it.
func storeJSONL[T any](from, to string, check func(T) error) (int, error) {
	st, err := os.Stat(from)
	if err != nil {
		return 0, err
	}
	if st.Size() > MaxVulnFile {
		return 0, fmt.Errorf("%s is %d bytes; the most one load takes is %d",
			from, st.Size(), int64(MaxVulnFile))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	n := 0
	err = loadJSONL(from, func(b []byte) error {
		var item T
		if err := json.Unmarshal(b, &item); err != nil {
			return err
		}
		if err := check(item); err != nil {
			return err
		}
		n++
		return enc.Encode(item)
	})
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, fmt.Errorf("%s holds nothing. Loading it would replace "+
			"what is stored with an empty list, and an empty list reads as "+
			"a clean one", from)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return 0, err
	}
	return n, atomicfile.Write(to, buf.Bytes(), 0o600)
}

func vulnLoad(root string, args []string) error {
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	advPath := fs.String("advisories", "", "advisories, one per line")
	invPath := fs.String("inventory", "", "installed components, one per line")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *advPath == "" && *invPath == "" {
		return fmt.Errorf("usage: quilzo vuln load [--advisories FILE] " +
			"[--inventory FILE]")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	detail := map[string]string{}
	var advisories, components int
	var err error
	if *advPath != "" {
		advisories, err = storeJSONL(*advPath, storedAdvisories(root),
			vuln.Advisory.Validate)
		if err != nil {
			return err
		}
		detail["advisories"] = fmt.Sprint(advisories)
	}
	if *invPath != "" {
		components, err = storeJSONL(*invPath, storedInventory(root),
			vuln.Component.Validate)
		if err != nil {
			return err
		}
		detail["components"] = fmt.Sprint(components)
	}
	record(root, audit.Record{Action: "vuln.loaded", Resource: "/vuln",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified, Detail: detail})
	if err := tallyVulns(root, time.Now().UTC()); err != nil {
		return err
	}
	if w.JSON(map[string]any{"advisories": advisories,
		"components": components}) {
		return nil
	}
	if *advPath != "" {
		w.Human("%s%d advisory(ies)%s stored\n", bold, advisories, reset)
	}
	if *invPath != "" {
		w.Human("%s%d component(s)%s stored\n", bold, components, reset)
	}
	w.Human("  %sreplaces what was there; quilzo vuln plan says what to "+
		"change%s\n", dim, reset)
	return nil
}

// recordAssessment validates and stores one assessment. The one place an
// assessment is written, from the command line and from the screen.
//
// known says the assessment must name something in the stored queue. The
// screen always does; the command line may be assessing ahead of a load.
func recordAssessment(root string, a vuln.Assessment, known bool) error {
	if err := a.Validate(); err != nil {
		return err
	}
	advisories, err := loadAdvisories(storedAdvisories(root))
	if err != nil {
		return err
	}
	var adv *vuln.Advisory
	for i := range advisories {
		if strings.EqualFold(advisories[i].ID, a.Advisory) {
			adv = &advisories[i]
		}
	}
	if known {
		if adv == nil {
			return fmt.Errorf("%s is not an advisory in the store", a.Advisory)
		}
		mentioned := false
		for _, r := range adv.Affects {
			mentioned = mentioned || vuln.Key(r.Ecosystem, r.Package) == a.Component
		}
		if !mentioned {
			return fmt.Errorf("%s does not mention %s", adv.ID, a.Component)
		}
	}
	if adv != nil {
		a.Advisory = adv.ID
		if yes, who := adv.Attested(); yes && a.Accepted() &&
			a.Until.Sub(a.At) > vuln.MaxAcceptanceExploited {
			return fmt.Errorf(
				"%s is being exploited, per %s. It can be accepted for %d "+
					"days at most: long enough to schedule the change, not "+
					"long enough to forget it", adv.ID,
				strings.Join(who, " and "),
				int(vuln.MaxAcceptanceExploited.Hours()/24))
		}
	}
	if err := os.MkdirAll(vulnDir(root), 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(a)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(assessmentsPath(root),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := recordE(root, a.Record()); err != nil {
		return err
	}
	return tallyVulns(root, a.At)
}

func vulnAccept(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("accept", flag.ContinueOnError)
	because := fs.String("because", "", "why it is being left, in one line")
	owner := fs.String("owner", "", "who answers for it when the date comes")
	until := fs.String("until", "", "when it comes back, as 2026-12-01")
	where := fs.String("where", "",
		"one asset, issuer:value; empty means every installation")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo vuln accept CVE-ID " +
			"ECOSYSTEM:PACKAGE --owner WHO --until DATE --because \"...\"")
	}
	parsed, perr := time.Parse("2006-01-02", strings.TrimSpace(*until))
	if perr != nil {
		return fmt.Errorf("an acceptance needs the date it ends, as " +
			"--until 2026-12-01. One with no end is a decision to stop " +
			"looking")
	}
	caller := resolveCaller(root, flagToken)
	a := vuln.Assessment{Advisory: pos[0],
		Component: strings.ToLower(pos[1]), Status: vuln.Affected,
		Where: strings.TrimSpace(*where), At: time.Now().UTC(),
		By: caller.Name, Kind: caller.Kind,
		Owner:   strings.TrimSpace(*owner),
		Because: strings.TrimSpace(*because),
		Until:   parsed.UTC().Add(24*time.Hour - time.Second)}
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	if err := recordAssessment(root, a, false); err != nil {
		return err
	}
	if w.JSON(a) {
		return nil
	}
	w.Human("%s%s%s in %s is %saccepted%s until %s\n", bold, a.Advisory,
		reset, a.Component, yellow, reset, parsed.Format("2006-01-02"))
	w.Human("  %s%s answers for it; it comes back into the queue on that "+
		"day, higher than it left%s\n", dim, a.Owner, reset)
	return nil
}

func vulnPlan(root string, args []string) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	top := fs.Int("top", 15, "how many to show")
	if err := fs.Parse(args); err != nil {
		return err
	}
	at := time.Now().UTC()
	v, err := loadVulnView(root, at)
	if err != nil {
		return err
	}
	if len(v.Inventory) == 0 || len(v.Advisories) == 0 {
		return fmt.Errorf("nothing is loaded, so there is nothing to plan " +
			"and that is not a clean bill. quilzo vuln load --advisories " +
			"FILE --inventory FILE")
	}
	ups := vuln.Upgrades(v.Live(), v.Advisories, at)
	shown := ups
	if len(shown) > *top {
		shown = shown[:*top]
	}
	if w.JSON(map[string]any{"upgrades": shown, "total": len(ups),
		"tally": vuln.Summarise(v.Matched, at)}) {
		return nil
	}
	if len(ups) == 0 {
		w.Human("%sNothing open%s across %d component(s) and %d "+
			"advisory(ies)\n", bold, reset, len(v.Inventory), len(v.Advisories))
		return nil
	}
	for i, u := range shown {
		colour := bold
		if u.Exploited {
			colour = red
		}
		if u.To == "" {
			w.Human("%s%2d.%s %s%s%s %s: nothing to upgrade to\n", dim, i+1,
				reset, bold, u.Name, reset, strings.Join(u.Versions, ", "))
		} else {
			w.Human("%s%2d.%s %s%s%s %s -> %s%s%s clears %d on %d asset(s)\n",
				dim, i+1, reset, colour, u.Name, reset,
				strings.Join(u.Versions, ", "), bold, u.To, reset,
				len(u.Clears), u.Assets)
			w.Human("     %s%s%s\n", dim, strings.Join(u.Clears, ", "), reset)
		}
		for _, l := range u.Leaves {
			w.Human("     %sleaves %s: %s%s\n", yellow, l.ID, l.Why, reset)
		}
		if len(u.Into) > 0 {
			w.Human("     %s%s is itself affected by %s%s\n", yellow, u.To,
				strings.Join(u.Into, ", "), reset)
		}
	}
	if len(ups) > len(shown) {
		w.Human("\n  %s%d more%s\n", dim, len(ups)-len(shown), reset)
	}
	return nil
}

func vulnVEX(root string, args []string) error {
	fs := flag.NewFlagSet("vex", flag.ContinueOnError)
	author := fs.String("author", "", "who the statement is from")
	id := fs.String("id", "", "the document's identifier, a URL you control")
	if err := fs.Parse(args); err != nil {
		return err
	}
	assessments, err := loadAssessments(root)
	if err != nil {
		return err
	}
	d, err := vuln.Draft(assessments, *author, *id, time.Now().UTC())
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	// The document is the output, in both modes: it is already JSON.
	fmt.Fprintln(os.Stdout, string(b))
	return nil
}
