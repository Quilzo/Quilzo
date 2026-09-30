// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/sca"
	"github.com/quilzo/quilzo/internal/telemetry"
	"github.com/quilzo/quilzo/internal/vuln"
)

// Filling the queue from what the world publishes.
//
// `vuln load` takes this program's own two formats, which nobody publishes.
// `vuln import` takes the four files people actually have: a CycloneDX bill
// of materials for what is installed, OSV records for what is wrong with
// it, CISA's catalogue for what is being exploited, and FIRST's EPSS scores
// for what is likely to be.
//
// All four are files. This command opens no connection: the feeds are
// fetched by whatever the operator already trusts to fetch things, and what
// is read here is bounded, checked and converted. A vulnerability tool that
// reaches out to four hosts on a schedule is four more things to be wrong
// about, and the comparison does not need any of them.
//
// Importing merges, where loading replaces. A bill replaces the components
// of the one asset it describes. OSV records replace advisories of the same
// id and leave the rest. The date this organisation learned of an advisory
// is kept across imports — it is the date every deadline runs from, and an
// import that reset it would make each refresh a way to be on time.

const (
	// MaxOSVRecord bounds one advisory as published.
	MaxOSVRecord = 16 << 20
	// MaxOSVTotal bounds everything read from one archive, decompressed.
	MaxOSVTotal = 4 << 30
	// MaxOSVEntries bounds how many files one archive may hold.
	MaxOSVEntries = 1_000_000
	// MaxAdvisoryLine is the largest advisory kept, as stored. Under the
	// line limit every reader of the store applies, so nothing imported
	// can make the store unreadable.
	MaxAdvisoryLine = MaxTelemetryLine / 2
	// KEVSource is the name CISA's attestations are recorded under.
	KEVSource = "cisa-kev"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// importReport is what one import did, for the person and the log.
type importReport struct {
	Components int    `json:"components,omitempty"`
	Replaced   int    `json:"components_replaced,omitempty"`
	Unplaced   int    `json:"components_without_a_package_url,omitempty"`
	Read       int    `json:"advisories_read,omitempty"`
	Kept       int    `json:"advisories_kept,omitempty"`
	New        int    `json:"advisories_new,omitempty"`
	Irrelevant int    `json:"advisories_about_nothing_installed,omitempty"`
	Merged     int    `json:"advisories_merged,omitempty"`
	Withdrawn  int    `json:"advisories_withdrawn,omitempty"`
	TooLarge   int    `json:"advisories_too_large,omitempty"`
	Unreadable int    `json:"files_unreadable,omitempty"`
	Exploited  int    `json:"exploited,omitempty"`
	Scored     int    `json:"scored,omitempty"`
	ScoreDate  string `json:"score_date,omitempty"`
	Advisories int    `json:"advisories_stored"`
	Inventory  int    `json:"components_stored"`
}

func vulnImport(root string, args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	var osv multiFlag
	fs.Var(&osv, "osv", "OSV records: a file, a directory, or a .zip "+
		"as osv.dev publishes them; may be given more than once")
	bom := fs.String("bom", "", "a CycloneDX bill of materials")
	where := fs.String("where", "", "the asset the bill describes, "+
		"as issuer:value, for example repo:storefront")
	kev := fs.String("kev", "", "CISA's known exploited vulnerabilities, as JSON")
	epss := fs.String("epss", "", "EPSS scores, as the .csv or .csv.gz FIRST publishes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(osv) == 0 && *bom == "" && *kev == "" && *epss == "" {
		return fmt.Errorf("usage: quilzo vuln import [--bom FILE --where " +
			"ISSUER:VALUE] [--osv PATH]... [--kev FILE] [--epss FILE]")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	now := time.Now().UTC()
	var rep importReport

	inventory, err := loadInventory(storedInventory(root))
	if err != nil {
		return err
	}
	advisories, err := loadAdvisories(storedAdvisories(root))
	if err != nil {
		return err
	}
	invChanged, advChanged := false, false

	// The bill first, so the advisories that follow are filtered against
	// the inventory as it now is.
	if *bom != "" {
		asset, perr := parseAsset(*where)
		if perr != nil {
			return perr
		}
		parts, unplaced, berr := readBill(*bom, asset)
		if berr != nil {
			return berr
		}
		kept := inventory[:0:0]
		for _, c := range inventory {
			if c.Where == asset {
				rep.Replaced++
				continue
			}
			kept = append(kept, c)
		}
		inventory = append(kept, parts...)
		rep.Components, rep.Unplaced = len(parts), unplaced
		invChanged = true
	}

	installed := map[string]bool{}
	for _, c := range inventory {
		installed[c.Key()] = true
	}
	concerns := func(a vuln.Advisory) bool {
		for _, r := range a.Affects {
			if installed[vuln.Key(r.Ecosystem, r.Package)] {
				return true
			}
		}
		return false
	}

	if len(osv) > 0 {
		if len(inventory) == 0 {
			return fmt.Errorf("there is no inventory, so every advisory " +
				"would be about nothing installed and none would be kept. " +
				"Import a bill first: --bom FILE --where ISSUER:VALUE")
		}
		at := map[string]int{}
		for i, a := range advisories {
			at[a.ID] = i
		}
		withdrawn := map[string]bool{}
		touched := map[string]bool{}
		take := func(r sca.Record) {
			rep.Read++
			if !r.Live() {
				rep.Withdrawn++
				withdrawn[r.ID] = true
				withdrawn[underCVE(vuln.Advisory{ID: r.ID,
					Aliases: r.Aliases}).ID] = true
				return
			}
			a := r.Advisory(now)
			if !concerns(a) {
				rep.Irrelevant++
				return
			}
			if len(a.FixedIn) == 0 {
				a.FixedIn = nil
			}
			// One vulnerability, one row. The same CVE is published by
			// more than one database — PyPI's own and GitHub's both carry
			// it, under their own identifiers — and counted twice it is
			// two rows of work and twice its probability in the total.
			a = underCVE(a)
			i, known := at[a.ID]
			if known && touched[a.ID] {
				// A second database's record of something already taken
				// in this import: its ranges are added to the first's.
				merged := mergeAdvisory(advisories[i], a)
				if line, merr := json.Marshal(merged); merr != nil ||
					len(line) > MaxAdvisoryLine {
					rep.TooLarge++
					return
				}
				advisories[i] = merged
				rep.Merged++
				return
			}
			if known {
				// What this organisation already knew stays: when it
				// learned of it, and what the other feeds said about it.
				old := advisories[i]
				a.Known, a.EPSS, a.EPSSAt = old.Known, old.EPSS, old.EPSSAt
				a.Exploited = old.Exploited
			}
			if a.Validate() != nil {
				rep.Unreadable++
				return
			}
			if line, merr := json.Marshal(a); merr != nil ||
				len(line) > MaxAdvisoryLine {
				rep.TooLarge++
				return
			}
			touched[a.ID] = true
			if known {
				advisories[i] = a
			} else {
				at[a.ID] = len(advisories)
				advisories = append(advisories, a)
				rep.New++
			}
			rep.Kept++
		}
		for _, path := range osv {
			if err := readOSV(path, take, &rep); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
		if rep.Read == 0 {
			return fmt.Errorf("no OSV record was found in %s",
				strings.Join(osv, ", "))
		}
		// Retracted by the database: closed, not left.
		if len(withdrawn) > 0 {
			kept := advisories[:0:0]
			for _, a := range advisories {
				// Unless another database still stands behind it, in
				// this same import.
				gone := withdrawn[a.ID]
				for _, id := range a.Aliases {
					// Stored under its CVE, withdrawn under the
					// database's own name.
					gone = gone || withdrawn[id]
				}
				if !gone || touched[a.ID] {
					kept = append(kept, a)
				}
			}
			advisories = kept
		}
		advChanged = true
	}

	if *kev != "" {
		list, kerr := readKEV(*kev)
		if kerr != nil {
			return kerr
		}
		for i := range advisories {
			a := &advisories[i]
			var others []vuln.Attestation
			for _, at := range a.Exploited {
				if at.By != KEVSource {
					others = append(others, at)
				}
			}
			a.Exploited = others
			for _, id := range append([]string{a.ID}, a.Aliases...) {
				if at, listed := list[strings.ToUpper(id)]; listed {
					a.Exploited = append(a.Exploited, at)
					rep.Exploited++
					break
				}
			}
		}
		advChanged = true
	}

	if *epss != "" {
		scores, date, eerr := readEPSS(*epss)
		if eerr != nil {
			return eerr
		}
		for i := range advisories {
			a := &advisories[i]
			for _, id := range append([]string{a.ID}, a.Aliases...) {
				if p, scored := scores[strings.ToUpper(id)]; scored {
					a.EPSS, a.EPSSAt = p, date
					rep.Scored++
					break
				}
			}
		}
		rep.ScoreDate = date.Format("2006-01-02")
		advChanged = true
	}

	if invChanged {
		if err := writeJSONL(storedInventory(root), inventory); err != nil {
			return err
		}
	}
	if advChanged {
		sort.SliceStable(advisories, func(i, j int) bool {
			return advisories[i].ID < advisories[j].ID
		})
		if err := writeJSONL(storedAdvisories(root), advisories); err != nil {
			return err
		}
	}
	rep.Advisories, rep.Inventory = len(advisories), len(inventory)

	detail := map[string]string{
		"advisories": fmt.Sprint(rep.Advisories),
		"components": fmt.Sprint(rep.Inventory),
	}
	if *bom != "" {
		detail["asset"] = *where
	}
	record(root, audit.Record{Action: "vuln.imported", Resource: "/vuln",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified, Detail: detail})
	if err := tallyVulns(root, now); err != nil {
		return err
	}
	if w.JSON(rep) {
		return nil
	}
	if *bom != "" {
		w.Human("%s%d component(s)%s on %s, replacing %d\n", bold,
			rep.Components, reset, *where, rep.Replaced)
		if rep.Unplaced > 0 {
			w.Human("  %s%d had no package URL, so nothing can be matched "+
				"against them and they were left out%s\n", yellow,
				rep.Unplaced, reset)
		}
		if len(osv) == 0 {
			w.Human("  %sthe advisories kept are the ones that concerned "+
				"the inventory when they were imported; import them again "+
				"now it has changed%s\n", yellow, reset)
		}
	}
	if len(osv) > 0 {
		w.Human("%s%d advisory(ies) read%s: %d kept (%d new), %d about "+
			"nothing installed, %d withdrawn\n", bold, rep.Read, reset,
			rep.Kept, rep.New, rep.Irrelevant, rep.Withdrawn)
		if rep.Merged > 0 {
			w.Human("  %s%d were a second database's record of a "+
				"vulnerability already taken, and were merged into "+
				"it%s\n", dim, rep.Merged, reset)
		}
		if rep.TooLarge+rep.Unreadable > 0 {
			w.Human("  %s%d could not be kept: %d too large, %d not "+
				"usable. These are not in the queue%s\n", red,
				rep.TooLarge+rep.Unreadable, rep.TooLarge, rep.Unreadable,
				reset)
		}
	}
	if *kev != "" {
		w.Human("%s%d%s of the stored advisories are in CISA's catalogue\n",
			bold, rep.Exploited, reset)
	}
	if *epss != "" {
		w.Human("%s%d%s scored, as of %s\n", bold, rep.Scored, reset,
			rep.ScoreDate)
	}
	w.Human("  %s%d advisory(ies) and %d component(s) stored; quilzo vuln "+
		"plan says what to change%s\n", dim, rep.Advisories, rep.Inventory,
		reset)
	return nil
}

func writeJSONL[T any](path string, items []T) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, it := range items {
		if err := enc.Encode(it); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, buf.Bytes(), 0o600)
}

func parseAsset(s string) (telemetry.ID, error) {
	issuer, value, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || strings.TrimSpace(issuer) == "" || strings.TrimSpace(value) == "" {
		return telemetry.ID{}, fmt.Errorf("a bill describes one thing, and " +
			"--where says which, as issuer:value — repo:storefront, " +
			"image:api@sha256:…. Without it every bill is the same asset " +
			"and each import replaces the last")
	}
	return telemetry.ID{Issuer: strings.TrimSpace(issuer),
		Value: strings.TrimSpace(value)}, nil
}

// readBill turns a CycloneDX bill into components on one asset.
func readBill(path string, asset telemetry.ID) ([]vuln.Component, int, error) {
	raw, err := readBounded(path, MaxVulnFile)
	if err != nil {
		return nil, 0, err
	}
	b, err := sca.ReadBOM(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", path, err)
	}
	tree := b.Graph()
	var out []vuln.Component
	seen := map[string]bool{}
	unplaced := 0
	for _, p := range b.Flat() {
		eco, name, ok := sca.ParsePURL(p.PURL)
		if !ok || strings.TrimSpace(p.Version) == "" {
			unplaced++
			continue
		}
		c := vuln.Component{Ecosystem: eco, Name: name, Version: p.Version,
			Where: asset}
		// Direct only when the bill's own graph says so. A bill with no
		// graph does not make everything direct.
		if tree.Known() && p.BOMRef != "" && tree.Depth(p.BOMRef) == 1 {
			c.Direct = true
		}
		if k := c.Key() + "@" + c.Version; seen[k] {
			continue
		} else {
			seen[k] = true
		}
		if c.Validate() != nil {
			unplaced++
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, unplaced, fmt.Errorf("%s lists nothing with a package "+
			"URL and a version, so there is nothing to match advisories "+
			"against", path)
	}
	return out, unplaced, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return b, nil
}

// readOSV walks a file, a directory or a zip of OSV records.
func readOSV(path string, take func(sca.Record), rep *importReport) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	one := func(raw []byte) {
		records, rerr := sca.ReadOSV(raw)
		if rerr != nil {
			rep.Unreadable++
			return
		}
		for _, r := range records {
			take(r)
		}
	}
	switch {
	case st.IsDir():
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		if len(entries) > MaxOSVEntries {
			return fmt.Errorf("holds %d entries; the most read is %d",
				len(entries), MaxOSVEntries)
		}
		for _, e := range entries {
			// Regular files by name, not followed: a directory of
			// advisories has no reason to hold a link to anywhere else.
			if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			raw, rerr := readBounded(filepath.Join(path, e.Name()), MaxOSVRecord)
			if rerr != nil {
				rep.Unreadable++
				continue
			}
			one(raw)
		}
		return nil
	case strings.HasSuffix(strings.ToLower(path), ".zip"):
		z, err := zip.OpenReader(path)
		if err != nil {
			return err
		}
		defer z.Close()
		if len(z.File) > MaxOSVEntries {
			return fmt.Errorf("holds %d entries; the most read is %d",
				len(z.File), MaxOSVEntries)
		}
		var total int64
		for _, f := range z.File {
			if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
				continue
			}
			// The size the archive claims is not trusted: what is read is
			// counted as it is read, and the entry is never written
			// anywhere, so its name is only a name.
			rc, oerr := f.Open()
			if oerr != nil {
				rep.Unreadable++
				continue
			}
			raw, rerr := io.ReadAll(io.LimitReader(rc, MaxOSVRecord+1))
			rc.Close()
			total += int64(len(raw))
			if total > MaxOSVTotal {
				return fmt.Errorf("decompresses to more than %d bytes; "+
					"stopped", int64(MaxOSVTotal))
			}
			if rerr != nil || len(raw) > MaxOSVRecord {
				rep.Unreadable++
				continue
			}
			one(raw)
		}
		return nil
	default:
		raw, err := readBounded(path, MaxVulnFile)
		if err != nil {
			return err
		}
		records, err := sca.ReadOSV(raw)
		if err != nil {
			return err
		}
		for _, r := range records {
			take(r)
		}
		return nil
	}
}

// readKEV reads CISA's catalogue into attestations by CVE.
func readKEV(path string) (map[string]vuln.Attestation, error) {
	raw, err := readBounded(path, MaxVulnFile)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Vulnerabilities []struct {
			ID         string `json:"cveID"`
			Added      string `json:"dateAdded"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s is not CISA's catalogue: %w", path, err)
	}
	if len(doc.Vulnerabilities) == 0 {
		// An empty catalogue would strip every attestation already held,
		// and the real one has never been empty.
		return nil, fmt.Errorf("%s lists no vulnerabilities. Importing it "+
			"would record that nothing is being exploited", path)
	}
	out := map[string]vuln.Attestation{}
	for _, v := range doc.Vulnerabilities {
		at, perr := time.Parse("2006-01-02", strings.TrimSpace(v.Added))
		if perr != nil || strings.TrimSpace(v.ID) == "" {
			continue
		}
		a := vuln.Attestation{By: KEVSource, At: at.UTC(),
			Ref: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}
		if strings.EqualFold(strings.TrimSpace(v.Ransomware), "Known") {
			a.Note = "used in ransomware campaigns"
		}
		out[strings.ToUpper(strings.TrimSpace(v.ID))] = a
	}
	return out, nil
}

// readEPSS reads FIRST's daily scores: a comment line carrying the date,
// a header, then cve,epss,percentile.
func readEPSS(path string) (map[string]float64, time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer f.Close()
	var in io.Reader = bufio.NewReader(f)
	if magic, _ := in.(*bufio.Reader).Peek(2); len(magic) == 2 &&
		magic[0] == 0x1f && magic[1] == 0x8b {
		gz, gerr := gzip.NewReader(in)
		if gerr != nil {
			return nil, time.Time{}, gerr
		}
		defer gz.Close()
		in = gz
	}
	// Bounded after decompression, which is where a small file becomes a
	// large one.
	limited := &io.LimitedReader{R: in, N: MaxVulnFile + 1}
	sc := bufio.NewScanner(limited)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	out := map[string]float64{}
	var date time.Time
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
		case strings.HasPrefix(line, "#"):
			for _, part := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
				k, v, _ := strings.Cut(part, ":")
				if strings.TrimSpace(k) != "score_date" || len(v) < 10 {
					continue
				}
				if d, perr := time.Parse("2006-01-02", strings.TrimSpace(v)[:10]); perr == nil {
					date = d.UTC()
				}
			}
		default:
			cols := strings.Split(line, ",")
			if len(cols) < 2 || strings.EqualFold(cols[0], "cve") {
				continue
			}
			p, perr := strconv.ParseFloat(strings.TrimSpace(cols[1]), 64)
			if perr != nil || p < 0 || p > 1 {
				return nil, date, fmt.Errorf("%s: %q is not a probability "+
					"between 0 and 1", path, cols[1])
			}
			out[strings.ToUpper(strings.TrimSpace(cols[0]))] = p
		}
	}
	if err := sc.Err(); err != nil {
		return nil, date, err
	}
	if limited.N <= 0 {
		return nil, date, fmt.Errorf("%s decompresses to more than %d bytes",
			path, int64(MaxVulnFile))
	}
	if len(out) == 0 {
		return nil, date, fmt.Errorf("%s holds no scores", path)
	}
	if date.IsZero() {
		// The date is what says whether a score is fresh. Guessing today
		// would make a year-old file read as this morning's.
		return nil, date, fmt.Errorf("%s does not say which day its scores "+
			"are for. FIRST's file starts with a line carrying score_date; "+
			"without it a stale file cannot be told from a current one",
			path)
	}
	return out, date, nil
}

// underCVE names an advisory by its CVE when it has one.
//
// The identifier the other two feeds use, and the one a person searches
// for. The database's own identifier is kept as an alias.
func underCVE(a vuln.Advisory) vuln.Advisory {
	best := ""
	for _, id := range append([]string{a.ID}, a.Aliases...) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if strings.HasPrefix(id, "CVE-") && (best == "" || id < best) {
			best = id
		}
	}
	if best == "" || best == a.ID {
		return a
	}
	aliases := []string{a.ID}
	for _, id := range a.Aliases {
		if !strings.EqualFold(strings.TrimSpace(id), best) {
			aliases = append(aliases, id)
		}
	}
	a.ID, a.Aliases = best, aliases
	return a
}

// mergeAdvisory adds a second database's account of a vulnerability to the
// first's: every range either names, the higher severity, the earlier
// publication, and both sets of names.
func mergeAdvisory(into, from vuln.Advisory) vuln.Advisory {
	seen := map[vuln.Range]bool{}
	for _, r := range into.Affects {
		seen[r] = true
	}
	for _, r := range from.Affects {
		if !seen[r] {
			seen[r] = true
			into.Affects = append(into.Affects, r)
		}
	}
	names := map[string]bool{strings.ToUpper(into.ID): true}
	for _, id := range into.Aliases {
		names[strings.ToUpper(id)] = true
	}
	for _, id := range from.Aliases {
		if !names[strings.ToUpper(id)] {
			names[strings.ToUpper(id)] = true
			into.Aliases = append(into.Aliases, id)
		}
	}
	if from.CVSS > into.CVSS {
		into.CVSS, into.Severity = from.CVSS, from.Severity
	}
	if !from.Published.IsZero() && (into.Published.IsZero() ||
		from.Published.Before(into.Published)) {
		into.Published = from.Published
	}
	for k, v := range from.FixedIn {
		if _, have := into.FixedIn[k]; !have {
			if into.FixedIn == nil {
				into.FixedIn = map[string]string{}
			}
			into.FixedIn[k] = v
		}
	}
	return into
}
