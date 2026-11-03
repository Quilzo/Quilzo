// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/quilzo/quilzo/internal/anchor"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/site"
)

func anchorPath(root string) string { return filepath.Join(root, "anchors.json") }

type anchorFile struct {
	Proofs []anchor.Proof `json:"proofs"`
}

// loadAnchors reads anchors.json with every proof saying what it is about.
//
// A proof written before proofs said so has no kind. It reads as before, a
// publication, unless its digest is a log head `auditlog anchor` saved:
// both kinds went into this one file, and the Integrity screen listed every
// log head as evidence of when something was published.
func loadAnchors(root string) (*anchorFile, error) {
	file := &anchorFile{}
	if err := loadJSON(anchorPath(root), file); err != nil {
		return nil, err
	}
	var heads map[string]bool
	for i, p := range file.Proofs {
		if p.Kind != "" {
			continue
		}
		if heads == nil {
			heads = map[string]bool{}
			hf := &headFile{}
			if err := loadJSON(headsPath(root), hf); err == nil {
				for _, h := range hf.Heads {
					heads[h.Root] = true
				}
			}
		}
		file.Proofs[i].Kind = anchor.Publication
		if heads[p.Digest] {
			file.Proofs[i].Kind = anchor.LogHead
		}
	}
	return file, nil
}

// anchorCalendars is how a digest reaches the public calendars: through the
// checked fetcher (httpSubmitter). A variable so a test can stand in for
// them.
var anchorCalendars = func() anchor.Submitter { return httpSubmitter{fetch.For("anchor")} }

// httpSubmitter routes calendar traffic through the SSRF-hardened fetcher.
//
// Calendar URLs are configuration, and a pending attestation inside a proof
// names a URL this program later fetches — so one of these addresses arrives
// from a file somebody else produced. That is exactly the case the fetcher's
// connect-time check exists for.
type httpSubmitter struct{ c *fetch.Client }

func (h httpSubmitter) Post(ctx context.Context, url string, body []byte) ([]byte, error) {
	res, err := h.c.Post(ctx, url, body, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}

func (h httpSubmitter) Get(ctx context.Context, url string) ([]byte, error) {
	res, err := h.c.Get(ctx, url)
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}

func cmdAnchor(root string, args []string) error {
	if len(args) == 0 {
		args = []string{bareRuns["anchor"]}
	}
	switch args[0] {
	case "status":
		return anchorStatus(root)
	case "submit":
		return anchorSubmit(root, args[1:])
	case "upgrade":
		return anchorUpgrade(root)
	case "export":
		return anchorExport(root, args[1:])
	default:
		return fmt.Errorf("unknown anchor command %q; try status, submit, upgrade or export",
			args[0])
	}
}

// liveFingerprint is what gets anchored: one hash over the whole publication.
//
// Not a page, not a field. The EDPB's blockchain guidelines rule out putting
// personal data on a ledger in any form, including hashed, because erasure has
// to stay possible. A root over an entire site satisfies that — delete the
// content and the anchor proves a site existed on a date and nothing about who
// was in it.
func liveFingerprint(root string) (string, error) {
	s, err := open(root)
	if err != nil {
		return "", err
	}
	// The live commit id, not the display fingerprint. Fingerprint() is
	// shortened for humans — eight bytes — and submitting that would anchor a
	// truncated hash, which is both refused by the calendar and a weaker claim
	// than it appears. The commit id is a full SHA-256 that already commits to
	// the entire tree, which is exactly the value worth anchoring.
	live := s.GetRef(site.RefLive)
	if live == "" {
		return "", fmt.Errorf("nothing is published, so there is nothing to stamp or anchor")
	}
	if len(live) != 64 {
		return "", fmt.Errorf("the live commit id is %d characters, not a "+
			"SHA-256", len(live))
	}
	return live, nil
}

func anchorSubmit(root string, args []string) error {
	fs := flag.NewFlagSet("submit", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	fp, err := liveFingerprint(root)
	if err != nil {
		return err
	}
	digest, err := hex.DecodeString(fp)
	if err != nil {
		return fmt.Errorf("the fingerprint is not hex: %w", err)
	}

	file, err := loadAnchors(root)
	if err != nil {
		return err
	}
	for _, p := range file.Proofs {
		if p.Digest == fp {
			w.Human("%sthis publication is already submitted%s\n", dim, reset)
			return anchorStatus(root)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	w.Human("submitting %s%s%s\n", bold, short(fp), reset)
	proofs, errs := anchor.Submit(ctx, anchorCalendars(), digest, nil, time.Now())
	for i := range proofs {
		proofs[i].Kind = anchor.Publication
	}

	for _, e := range errs {
		w.Human("  %s%v%s\n", yellow, e, reset)
	}
	if len(proofs) == 0 {
		return errBlocked{fmt.Errorf(
			"no calendar accepted the digest, so nothing was recorded anywhere")}
	}

	file.Proofs = append(file.Proofs, proofs...)
	if err := saveJSON(anchorPath(root), file); err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "anchor.submit", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		Detail: map[string]string{
			"fingerprint": fp,
			"calendars":   fmt.Sprintf("%d", len(proofs)),
		},
	})

	if w.JSON(map[string]any{"digest": fp, "proofs": proofs}) {
		return nil
	}
	for _, p := range proofs {
		w.Human("  %s%s%s  %s\n", green, "accepted", reset, p.Calendar)
	}
	w.Human("\n  %sthese are pending, which is not anchored. A calendar batches\n"+
		"  many hashes into one Bitcoin commitment, which takes hours.%s\n",
		yellow, reset)
	w.Human("  %srun `quilzo anchor upgrade` later%s\n", dim, reset)
	return nil
}

func anchorUpgrade(root string) error {
	file, err := loadAnchors(root)
	if err != nil {
		return err
	}
	if len(file.Proofs) == 0 {
		return fmt.Errorf("nothing has been submitted")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sub := anchorCalendars()

	var upgraded, waiting int
	for i := range file.Proofs {
		if file.Proofs[i].Anchored() {
			continue
		}
		out, err := anchor.Upgrade(ctx, sub, file.Proofs[i], time.Now())
		if errors.Is(err, anchor.ErrNotYet) {
			waiting++
			continue
		}
		if err != nil {
			w.Human("  %s%s: %v%s\n", yellow, file.Proofs[i].Calendar, err, reset)
			continue
		}
		if out.Anchored() {
			upgraded++
			w.Human("  %sanchored%s  %s  block %d\n",
				green, reset, out.Calendar, out.Height)
		}
		file.Proofs[i] = out
	}
	if err := saveJSON(anchorPath(root), file); err != nil {
		return err
	}
	// Upgrading asks the calendars about each pending proof and writes what
	// they answer over it; submitting was on the record and this was not.
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "anchor.upgrade", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		Detail: map[string]string{
			"upgraded": fmt.Sprintf("%d", upgraded),
			"waiting":  fmt.Sprintf("%d", waiting),
		},
	})
	if upgraded == 0 {
		w.Human("  %s%d proof(s) still waiting for a block; commitments take "+
			"hours%s\n", dim, waiting, reset)
	}
	return anchorStatus(root)
}

func anchorStatus(root string) error {
	file, err := loadAnchors(root)
	if err != nil {
		return err
	}
	if w.JSON(file) {
		return nil
	}
	if len(file.Proofs) == 0 {
		w.Human("nothing has been anchored\n")
		w.Human("  %squilzo anchor submit — commit this publication's "+
			"fingerprint%s\n", dim, reset)
		w.Human("  %sone hash over the whole site. Nothing about a page or a\n"+
			"  person goes to a public ledger, because a ledger cannot forget.%s\n",
			dim, reset)
		return nil
	}

	for _, p := range file.Proofs {
		state := yellow + string(p.State) + reset
		if p.Anchored() {
			state = green + "anchored" + reset
		}
		w.Human("  %-10s %-46s %s  %s\n", state, p.Calendar, short(p.Digest),
			anchorOf(p.Kind))
		if p.Anchored() {
			w.Human("             %sBitcoin block %d%s\n", dim, p.Height, reset)
		} else {
			w.Human("             %swaiting %s%s\n", dim,
				anchor.Age(p, time.Now()).Round(time.Minute), reset)
		}
	}
	// It said "ots verify <proof>", and no proof was ever a file the client
	// could read.
	w.Human("\n  %sverify independently: quilzo anchor export --dir DIR writes each\n"+
		"  proof as an .ots file, then ots verify -d DIGEST FILE%s\n", dim, reset)
	w.Human("  %sthat walks the proof and checks the block it names against the\n"+
		"  chain, which this program has no headers for%s\n", dim, reset)
	return nil
}

// anchorOf names what a proof's digest is, for a person.
func anchorOf(kind string) string {
	if kind == anchor.LogHead {
		return "the audit log's head"
	}
	return "a publication"
}

// anchorExport writes each proof as a file the OpenTimestamps client reads.
//
// The status and every anchored proof's description told people to run `ots
// verify anchor.ots`, and nothing wrote it: proofs are kept as the
// calendar's bytes inside anchors.json, which `ots` cannot read. Written
// rather than verified here, as timestamps are exported for openssl: the
// block check needs the chain, and the client has it.
func anchorExport(root string, args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	dir := fs.String("dir", ".", "where to write the .ots files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	file, err := loadAnchors(root)
	if err != nil {
		return err
	}
	if len(file.Proofs) == 0 {
		return fmt.Errorf("nothing has been anchored, so there is nothing to export")
	}
	type written struct {
		File     string `json:"file"`
		Digest   string `json:"digest"`
		Kind     string `json:"kind"`
		Calendar string `json:"calendar"`
		State    string `json:"state"`
	}
	var out []written
	used := map[string]bool{}
	for _, p := range file.Proofs {
		body, err := anchor.File(p)
		if err != nil {
			w.Human("  %s%s %s: %v%s\n", yellow, short(p.Digest), p.Calendar, err, reset)
			continue
		}
		host := p.Calendar
		if u, perr := url.Parse(p.Calendar); perr == nil && u.Host != "" {
			host = u.Host
		}
		base := fmt.Sprintf("%s-%s-%s", p.Kind, short(p.Digest),
			reUnsafeName.ReplaceAllString(host, "-"))
		// Numbered past the first: one calendar can hold two proofs of one
		// digest, a log head anchored twice, and the second was written
		// over the first.
		name := filepath.Join(*dir, base+".ots")
		for n := 2; used[name]; n++ {
			name = filepath.Join(*dir, fmt.Sprintf("%s-%d.ots", base, n))
		}
		used[name] = true
		if err := os.WriteFile(name, body, 0o644); err != nil {
			return err
		}
		out = append(out, written{File: name, Digest: p.Digest, Kind: p.Kind,
			Calendar: p.Calendar, State: string(p.State)})
	}
	if len(out) == 0 {
		return fmt.Errorf("no proof could be written; each is named above")
	}
	if w.JSON(map[string]any{"files": out}) {
		return nil
	}
	w.Human("wrote %d proof file(s) to %s\n\n", len(out), *dir)
	w.Human("  %sverify each yourself with the OpenTimestamps client — this tool\n"+
		"  does not ask you to take its word:%s\n", dim, reset)
	for _, f := range out {
		w.Human("    ots verify -d %s %s\n", f.Digest, f.File)
	}
	return nil
}

// reUnsafeName is what a calendar's host may not carry into a file name.
var reUnsafeName = regexp.MustCompile(`[^A-Za-z0-9.-]+`)
