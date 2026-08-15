package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/rsh1k/scrivet/internal/anchor"
	"github.com/rsh1k/scrivet/internal/fetch"
	"github.com/rsh1k/scrivet/internal/logd"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/out"
)

// Where the audit log lives.
//
// By default inside the store, which is the single-account bootstrap. A
// separated deployment puts it somewhere the CMS account cannot write, and
// that directory is recorded in the store so every command finds it without
// each one growing a flag — a flag that has to be passed identically to
// `auditlog`, `siem` and `logd status` forever is a flag that will eventually
// be passed to two of the three.
//
// The pointer file is deliberately plain and inside the store. It is not a
// security boundary: it says where to look, and lying in it points the reader
// at a file that fails verification rather than at a forged one that passes.
// What protects the log is the ownership of the directory it names and the
// hash chain inside it.
// logDirOverride is set by `logd --log-dir`, which knows where it is writing
// and must not consult the store to find out — the store belongs to the other
// account and may point somewhere stale.
var logDirOverride string

func auditDir(root string) string {
	if logDirOverride != "" {
		return logDirOverride
	}
	b, err := os.ReadFile(filepath.Join(root, "auditlog.dir"))
	if err != nil {
		return root
	}
	if dir := strings.TrimSpace(string(b)); dir != "" {
		return dir
	}
	return root
}

// cmdAuditDir shows or sets where the audit log lives.
//
// Run by whoever owns the store, which in a separated deployment is not the
// account that writes the log. That asymmetry is the reason this is a command
// rather than something logd does at startup.
func cmdAuditDir(root string, args []string) error {
	if len(args) == 0 {
		dir := auditDir(root)
		if dir == root {
			w.Human("  the log is in the store: %s", auditPath(root))
			w.Human("  %sthat means this account writes its own audit record%s",
				dim, reset)
			w.Human("  %sscrivet auditlog dir /srv/audit — after creating it "+
				"for the log account%s", dim, reset)
			return nil
		}
		w.Human("  the log is at %s", filepath.Join(dir, "audit.jsonl"))
		return nil
	}
	dir := args[0]
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if fi, err := os.Stat(abs); err != nil {
		return fmt.Errorf("%s: %w\n  create it first, owned by the account "+
			"that will run `scrivet logd`", abs, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", abs)
	}
	// Repointing every reader at a different log is the single most sensitive
	// thing in this command, and it recorded nothing. Written to the OLD log
	// before the pointer moves, so the change is in the record that was being
	// kept at the time rather than only in the one it moves to.
	record(root, resolveCaller(root, "").auditRecord("auditlog.dir", "/",
		audit.Success, map[string]string{"from": auditDir(root), "to": abs}))
	if err := setAuditDir(root, abs); err != nil {
		return err
	}
	w.Human("  the log is now read from %s", filepath.Join(abs, "audit.jsonl"))
	w.Human("  %sstart the writer: scrivet --root %s logd --log-dir %s%s",
		dim, root, abs, reset)
	return nil
}

func setAuditDir(root, dir string) error {
	if dir == "" || dir == root {
		return os.Remove(filepath.Join(root, "auditlog.dir"))
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "auditlog.dir"),
		[]byte(abs+"\n"), 0o644)
}

// keyMode picks the file mode from the deployment rather than from a constant.
//
// A log inside the store belongs to one account and stays 0600. A log the
// operator has moved elsewhere is the separated deployment, where the writer
// owns the files and the readers are in its group.
func keyMode(root string) os.FileMode {
	if auditDir(root) == root {
		return audit.ModePrivate
	}
	return audit.ModeShared
}

func auditPath(root string) string {
	return filepath.Join(auditDir(root), "audit.jsonl")
}

func auditKeyPath(root string) string {
	return filepath.Join(auditDir(root), "audit.key")
}

// openAudit returns a log, creating a pseudonymisation key on first use.
//
// The key lives beside the log rather than inside it, at 0600. That is the
// weakest part of this design and worth naming: anyone who can read both the
// log and the key can re-identify everyone in it. A deployment that means it
// puts the key in a KMS and mounts the log read-only. The local default is the
// bootstrap, not the destination.
func openAudit(root string) (*audit.Log, error) {
	key, err := os.ReadFile(auditKeyPath(root))
	if os.IsNotExist(err) {
		key, err = audit.NewKey()
		if err != nil {
			return nil, err
		}
		// 0640, not 0600. In a separated deployment the writer owns this and
		// the CMS account has to read it to render `auditlog` and `siem`
		// output — the CMS is not trusted to *write* the log, which is a
		// different claim from not being trusted to read it. A shared group
		// is the Unix answer and 0600 made the deployment impossible.
		if err := os.WriteFile(auditKeyPath(root), key, keyMode(root)); err != nil {
			return nil, err
		}
	} else if err != nil {
		if os.IsPermission(err) {
			return nil, fmt.Errorf(
				"cannot read %s: %w\n"+
					"  the audit key belongs to the account that writes the "+
					"log. This account needs to be in its group, and the key "+
					"needs to be group-readable:\n"+
					"    chgrp <shared-group> %s && chmod 640 %s",
				auditKeyPath(root), err, auditKeyPath(root), auditKeyPath(root))
		}
		return nil, err
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown-host"
	}
	return audit.New(audit.Options{
		Path: auditPath(root), Key: key, Source: "scrivet-cli@" + host,
		Mode: keyMode(root),
	})
}

// record writes an audit event, and never stops the operation it describes.
//
// A failure to log is reported on stderr rather than returned. That is a real
// trade: NIST allows for alerting on audit failure, and the alternative — a
// publish refused because a log file is full — trades an availability problem
// for an accountability one. Reporting loudly and continuing is the choice, and
// `scrivet auditlog verify` is what catches a gap afterwards.
func record(root string, r audit.Record) {
	// A separate writer, if one is running. Its presence is the configuration:
	// the socket existing means somebody set this up, and going around it would
	// make the separation optional at exactly the moment it matters.
	if sock := logSocketPath(root); fileExists(sock) {
		_, err := logd.Submit(sock, logd.Submission{
			Action: r.Action, Resource: r.Resource, Outcome: string(r.Outcome),
			Principal: r.Principal, Kind: string(r.Kind), Model: r.Model,
			Verified: r.Verified, Detail: r.Detail,
		})
		if err != nil {
			// Deliberately no fallback to writing the file directly. Falling
			// back would mean anybody who can stop the writer regains the
			// ability to edit the log, which is the whole thing this prevents —
			// and where the separation is properly configured the fallback
			// would fail anyway, because this account cannot open the file.
			fmt.Fprintf(os.Stderr,
				"%saudit record NOT written: %v%s\n"+
					"  %sthe log writer is configured and unreachable. This "+
					"action is not in the record.%s\n",
				red, err, reset, red, reset)
		}
		return
	}

	l, err := openAudit(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%saudit log unavailable: %v%s\n", red, err, reset)
		return
	}
	if _, err := l.Append(r); err != nil {
		fmt.Fprintf(os.Stderr, "%saudit record refused: %v%s\n", red, err, reset)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func cmdAuditLog(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"show"}
	}
	switch args[0] {
	case "dir":
		return cmdAuditDir(root, args[1:])
	case "verify":
		return auditVerify(root)
	case "show":
		return auditShow(root, args[1:])
	case "export":
		return auditExport(root)
	case "head":
		return auditHead(root, args[1:])
	case "prove":
		return auditProve(root, args[1:])
	case "consistency":
		return auditConsistency(root, args[1:])
	case "anchor":
		return auditAnchor(root)
	default:
		return fmt.Errorf("unknown auditlog command %q; try show, verify, "+
			"export, head, prove, consistency or anchor", args[0])
	}
}

// unreadable reports whether every problem is the file refusing to open,
// rather than its contents failing to verify.
func unreadable(problems []audit.Problem) bool {
	if len(problems) == 0 {
		return false
	}
	for _, p := range problems {
		if !strings.Contains(p.Reason, "permission denied") &&
			!strings.Contains(p.Reason, "no such file") {
			return false
		}
	}
	return true
}

func auditVerify(root string) error {
	n, good, problems, err := audit.VerifyFile(auditPath(root))
	if err != nil {
		return err
	}

	if w.Mode == out.JSON {
		rows := make([]map[string]any, 0, len(problems))
		for _, p := range problems {
			rows = append(rows, map[string]any{"seq": p.Seq, "reason": p.Reason})
		}
		w.JSON(map[string]any{"entries": n, "intact": good, "problems": rows})
		if !good {
			return errBlocked{fmt.Errorf("%d problem(s)", len(problems))}
		}
		return nil
	}

	w.Human("%d entr%s\n", n, plural(n))
	if good {
		w.Human("  %schain intact%s\n", green, reset)
		w.Human("  %severy entry re-hashes and links to the one before it, so nothing\n"+
			"  was altered, inserted or removed — including by an administrator%s\n",
			dim, reset)
		return nil
	}
	w.Human("  %s%d problem(s)%s\n", red, len(problems), reset)
	for _, p := range problems {
		w.Human("    entry %d: %s\n", p.Seq, p.Reason)
	}
	// A log that cannot be read is not a log that has been tampered with, and
	// saying so is worse than saying nothing.
	//
	// A permission error reported as "the audit log has been tampered with" is
	// the alert that cries wolf — and it fires in exactly the deployment this
	// program recommends, where the writer owns the file and a reader has not
	// been put in its group yet. An operator who sees a tamper alert resolved
	// by a chmod learns to resolve the next one the same way.
	if unreadable(problems) {
		return fmt.Errorf(
			"the audit log could not be read, so nothing was verified.\n" +
				"  This is not evidence of tampering — it is a permission " +
				"problem. The log belongs to the account that writes it; this " +
				"account needs to be in its group")
	}
	return errBlocked{fmt.Errorf("the audit log has been tampered with")}
}

func auditShow(root string, args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	limit := fs.Int("limit", 25, "how many recent entries")
	if err := fs.Parse(args); err != nil {
		return err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	if len(events) > *limit {
		events = events[len(events)-*limit:]
	}

	if w.JSON(map[string]any{"entries": events}) {
		return nil
	}
	if len(events) == 0 {
		w.Human("no audit entries\n")
		return nil
	}
	for _, e := range events {
		colour := green
		switch e.Outcome {
		case audit.Denied:
			colour = yellow
		case audit.Failure:
			colour = red
		}
		who := e.Principal
		if e.Kind == audit.KindAI && e.Model != "" {
			who = e.Model
		}
		w.Human("  %s  %s%-8s%s %-16s %-22s %s(%s)%s\n",
			e.At[:19], colour, e.Outcome, reset, e.Action, e.Resource, dim, who, reset)
	}
	return nil
}

func auditExport(root string) error {
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	return audit.Export(events, os.Stdout)
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// -- transparency ------------------------------------------------------------

func headsPath(root string) string { return filepath.Join(root, "log-heads.json") }

type headFile struct {
	Heads []audit.Head `json:"heads"`
}

// auditHead publishes a commitment to the log as it stands.
//
// Publishing is the whole mechanism. A head kept on the same machine as the log
// protects nothing — whoever can rewrite one can rewrite the other. A head that
// has left the building fixes history before it, and an administrator can still
// alter yesterday's entries but cannot make the altered version consistent with
// a head somebody else is holding.
func auditHead(root string, args []string) error {
	fs := flag.NewFlagSet("head", flag.ContinueOnError)
	save := fs.Bool("save", false, "record this head locally as well")
	if err := fs.Parse(args); err != nil {
		return err
	}

	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	head, err := audit.TreeHead(events, time.Now())
	if err != nil {
		return err
	}

	if *save {
		f := &headFile{}
		if err := loadJSON(headsPath(root), f); err != nil {
			return err
		}
		f.Heads = append(f.Heads, head)
		if err := saveJSON(headsPath(root), f); err != nil {
			return err
		}
	}

	if w.JSON(head) {
		return nil
	}
	w.Human("%s%d entries%s\n", bold, head.Size, reset)
	w.Human("  root %s\n", head.Root)
	w.Human("\n  %sthis commits to every entry. Get it out of this machine —\n"+
		"  export it to a SIEM, hand it to an auditor, or anchor it:%s\n",
		dim, reset)
	w.Human("    %sscrivet auditlog anchor%s\n", dim, reset)
	w.Human("\n  %sa head kept only here protects nothing: whoever can rewrite\n"+
		"  the log can rewrite the head beside it%s\n", yellow, reset)
	return nil
}

// auditProve produces an inclusion proof for one entry.
func auditProve(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: scrivet auditlog prove <sequence>")
	}
	var seq int64
	if _, err := fmt.Sscanf(args[0], "%d", &seq); err != nil {
		return fmt.Errorf("%q is not a sequence number", args[0])
	}

	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	proof, head, err := audit.Inclusion(events, seq)
	if err != nil {
		return err
	}

	var entry audit.Event
	index := -1
	for i, e := range events {
		if e.Seq == seq {
			entry, index = e, i
			break
		}
	}

	if w.JSON(map[string]any{
		"entry": entry, "index": index, "proof": proof, "head": head,
	}) {
		return nil
	}
	w.Human("%sentry %d is in a log of %d%s\n", bold, seq, head.Size, reset)
	w.Human("  root  %s\n", head.Root)
	w.Human("  proof %d hashes\n", len(proof))
	w.Human("\n  %sthat is the whole proof. Somebody holding this entry, these\n"+
		"  %d hashes and a root they trust can confirm it is in the log without\n"+
		"  ever seeing the log — which also means without seeing every other\n"+
		"  entry in it%s\n", dim, len(proof), reset)
	return nil
}

// auditConsistency proves the log only grew since a published head.
func auditConsistency(root string, args []string) error {
	fs := flag.NewFlagSet("consistency", flag.ContinueOnError)
	against := fs.Int("since", 0, "the size of a previously published head")
	if err := fs.Parse(args); err != nil {
		return err
	}

	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}

	// Against the most recently saved head if none was named, because that is
	// the check somebody wants and remembering a number is not.
	oldSize := *against
	var published audit.Head
	f := &headFile{}
	if err := loadJSON(headsPath(root), f); err != nil {
		return err
	}
	if oldSize == 0 {
		if len(f.Heads) == 0 {
			return fmt.Errorf(
				"no head has been published, so there is nothing to check " +
					"against.\n  `scrivet auditlog head --save` records one; a " +
					"head only proves anything once it exists somewhere the log " +
					"cannot be quietly rewritten alongside")
		}
		published = f.Heads[len(f.Heads)-1]
		oldSize = published.Size
	} else {
		for _, h := range f.Heads {
			if h.Size == oldSize {
				published = h
			}
		}
		if published.Root == "" {
			return fmt.Errorf("no published head covers %d entries", oldSize)
		}
	}

	proof, now, err := audit.Consistency(events, oldSize)
	if err != nil {
		return errBlocked{err}
	}
	if err := audit.VerifyConsistency(published, now, proof); err != nil {
		return errBlocked{fmt.Errorf(
			"this log is NOT an append-only extension of the head published at "+
				"%d entries.\n  %v\n  Entries before that point have been "+
				"changed, reordered or removed", oldSize, err)}
	}

	if w.JSON(map[string]any{
		"consistent": true, "from": published, "to": now, "proof": proof,
	}) {
		return nil
	}
	w.Human("%sconsistent%s  %d → %d entries\n", green, reset, oldSize, now.Size)
	w.Human("  %severy entry behind the published head is still there, unchanged,\n"+
		"  in the same order%s\n", dim, reset)
	return nil
}

// auditAnchor commits the log head to Bitcoin.
//
// This is what turns "detectable" into "provable". Once a head is in a block,
// rewriting anything behind it produces a log that cannot pass consistency
// against a value nobody involved can alter.
func auditAnchor(root string) error {
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	head, err := audit.TreeHead(events, time.Now())
	if err != nil {
		return err
	}
	if head.Size == 0 {
		return fmt.Errorf("the log is empty")
	}

	digest, err := hex.DecodeString(head.Root)
	if err != nil {
		return fmt.Errorf("the root is not hex: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	proofs, errs := anchor.Submit(ctx, httpSubmitter{fetch.New()}, digest, nil,
		time.Now())
	for _, e := range errs {
		w.Human("  %s%v%s\n", yellow, e, reset)
	}
	if len(proofs) == 0 {
		return errBlocked{fmt.Errorf("no calendar accepted the log head")}
	}

	// The head is saved alongside, because a proof about a root nobody kept is
	// a proof about a number nobody can reconstruct.
	f := &headFile{}
	if err := loadJSON(headsPath(root), f); err != nil {
		return err
	}
	f.Heads = append(f.Heads, head)
	if err := saveJSON(headsPath(root), f); err != nil {
		return err
	}

	af := &anchorFile{}
	if err := loadJSON(anchorPath(root), af); err != nil {
		return err
	}
	af.Proofs = append(af.Proofs, proofs...)
	if err := saveJSON(anchorPath(root), af); err != nil {
		return err
	}

	w.Human("submitted the log head at %d entries\n", head.Size)
	for _, p := range proofs {
		w.Human("  %saccepted%s %s\n", green, reset, p.Calendar)
	}
	w.Human("\n  %sonce this is in a block, entries before it cannot be rewritten\n"+
		"  without producing a log that fails consistency against a value\n"+
		"  nobody involved can alter — including whoever runs this machine%s\n",
		dim, reset)
	return nil
}
