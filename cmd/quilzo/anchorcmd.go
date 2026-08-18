package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
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
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		return anchorStatus(root)
	case "submit":
		return anchorSubmit(root, args[1:])
	case "upgrade":
		return anchorUpgrade(root)
	default:
		return fmt.Errorf("unknown anchor command %q; try status, submit or upgrade",
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
		return "", fmt.Errorf("nothing is published, so there is nothing to anchor")
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

	file := &anchorFile{}
	if err := loadJSON(anchorPath(root), file); err != nil {
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
	proofs, errs := anchor.Submit(ctx, httpSubmitter{fetch.New()}, digest, nil,
		time.Now())

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
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
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
	file := &anchorFile{}
	if err := loadJSON(anchorPath(root), file); err != nil {
		return err
	}
	if len(file.Proofs) == 0 {
		return fmt.Errorf("nothing has been submitted")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sub := httpSubmitter{fetch.New()}

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
	if upgraded == 0 {
		w.Human("  %s%d proof(s) still waiting for a block; commitments take "+
			"hours%s\n", dim, waiting, reset)
	}
	return anchorStatus(root)
}

func anchorStatus(root string) error {
	file := &anchorFile{}
	if err := loadJSON(anchorPath(root), file); err != nil {
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
		w.Human("  %-10s %-46s %s\n", state, p.Calendar, short(p.Digest))
		if p.Anchored() {
			w.Human("             %sBitcoin block %d%s\n", dim, p.Height, reset)
		} else {
			w.Human("             %swaiting %s%s\n", dim,
				anchor.Age(p, time.Now()).Round(time.Minute), reset)
		}
	}
	w.Human("\n  %sverify independently:  ots verify <proof>%s\n", dim, reset)
	w.Human("  %sthis walks the proof and recomputes the commitment; whether a\n"+
		"  block contains it needs block headers, which this does not have%s\n",
		dim, reset)
	return nil
}
