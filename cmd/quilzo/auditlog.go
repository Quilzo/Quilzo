// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/anchor"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/logd"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/siem"
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
		// Where the log is under --json, and whether that is in the store.
		// This wrote only for a person, so a script asking where to read the
		// log was answered with nothing and exit 0.
		if w.JSON(map[string]any{"log": auditPath(root), "in_store": dir == root}) {
			return nil
		}
		if dir == root {
			w.Human("  the log is in the store: %s\n", auditPath(root))
			w.Human("  %sthat means this account writes its own audit record%s\n",
				dim, reset)
			w.Human("  %squilzo auditlog dir /srv/audit — after creating it "+
				"for the log account%s\n", dim, reset)
			return nil
		}
		w.Human("  the log is at %s\n", filepath.Join(dir, "audit.jsonl"))
		return nil
	}
	dir := args[0]
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if fi, err := os.Stat(abs); err != nil {
		return fmt.Errorf("%s: %w\n  create it first, owned by the account "+
			"that will run `quilzo logd`", abs, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", abs)
	}
	// Where the public half of the head keys is now, before anything moves.
	oldKeys := headKeysPath(root)
	// Repointing every reader at a different log is the single most sensitive
	// thing in this command, so it waits for a second administrator, who
	// moves it on approving (applyDual).
	apply, err := proposeSecond(root, resolveCaller(root, ""), dual.AuditLog, "move the audit log to "+abs,
		dual.AuditLogChange{Dir: abs}, "")
	if err != nil || !apply {
		return err
	}
	// Written to the OLD log before the pointer moves, so the change is in
	// the record that was being kept at the time rather than only in the one
	// it moves to.
	record(root, resolveCaller(root, "").auditRecord("auditlog.dir", "/",
		audit.Success, map[string]string{"from": auditDir(root), "to": abs}))
	if err := setAuditDir(root, abs); err != nil {
		return err
	}
	w.Human("  the log is now read from %s\n", filepath.Join(abs, "audit.jsonl"))
	w.Human("  %sstart the writer, unless something runs it already: quilzo --root %s logd --log-dir %s%s\n",
		dim, root, abs, reset)
	sayKeysLeftBehind(oldKeys, abs)
	return nil
}

// sayKeysLeftBehind says, once the log has moved to dir, that what was
// signed before the move checks against the public keys it left behind at
// oldKeys, when there are some and dir does not hold the same.
//
// The writer in the new directory makes a key of its own, and every check
// reads the head.pub.json beside the log: a head, a receipt or a feature
// package signed before the move stopped checking against it, and nothing
// said which file still does, at the moment somebody had just moved it.
func sayKeysLeftBehind(oldKeys, dir string) {
	if keysLeftBehind(oldKeys, dir) == "" {
		return
	}
	w.Human("  %sheads, receipts and statements signed before the move check against %s, not the keys%s\n",
		yellow, oldKeys, reset)
	w.Human("  %sthe writer makes in %s: keep that file, and check them with --keys %s%s\n",
		yellow, dir, oldKeys, reset)
}

// keysLeftBehind is what sayKeysLeftBehind says, as one sentence, or
// nothing when there is nothing to say: for the People screen, where
// approving a move of the log moves it as `quilzo pending approve` does.
func keysLeftBehind(oldKeys, dir string) string {
	old, err := os.ReadFile(oldKeys)
	if err != nil {
		return ""
	}
	if now, err := os.ReadFile(filepath.Join(dir, "head.pub.json")); err == nil && bytes.Equal(now, old) {
		return ""
	}
	return fmt.Sprintf("Heads, receipts and statements signed before the move check against %s, not the "+
		"keys the writer makes in %s: keep that file, and check them with --keys %s.", oldKeys, dir, oldKeys)
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

// auditEntries is every whole entry of the audit log, for whatever works
// from the entries: exports, heads, receipts, the stream, agentwatch.
//
// A line a crash left unfinished is not an entry, nor part of the chain or
// the tree, and it stopped every one of them, for good, at the first
// record after it. It is passed over here (audit.Entries) and reported by
// what reports on the log: auditlog verify and show, the audit log screen,
// posture.
func auditEntries(root string) ([]audit.Event, error) {
	return audit.Entries(audit.Read(auditPath(root)))
}

// exportedEntries is auditEntries for an export, which says on stderr which
// lines of the log it leaves out. The system an export goes to cannot tell
// that anything else was in the log, so passed over without a word, a line
// somebody added to it would leave no trace there.
func exportedEntries(root string) ([]audit.Event, error) {
	events, err := audit.Read(auditPath(root))
	var bad *audit.Unreadable
	if errors.As(err, &bad) {
		fmt.Fprintf(w.Err, "%s%v: not in this export, which holds every entry and only entries;\n"+
			"  quilzo auditlog verify says what is there%s\n", yellow, bad, reset)
	}
	return audit.Entries(events, err)
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
		Path: auditPath(root), Key: key, Source: "quilzo-cli@" + host,
		Mode: keyMode(root),
	})
}

// record writes an audit event, and never stops the operation it describes.
//
// A failure to log is reported on stderr rather than returned. That is a real
// trade: NIST allows for alerting on audit failure, and the alternative — a
// publish refused because a log file is full — trades an availability problem
// for an accountability one. Reporting loudly and continuing is the choice
// for what a person does, and the message on stderr is all that shows it:
// a record never written leaves no gap `quilzo auditlog verify` could find,
// since the next one takes its number. What an agent does is the other way
// round (SP 800-53 AU-5): it is asked about first (auditReady) and refused
// while its record could not be written, because an agent acting unrecorded
// is the gap nobody can explain afterwards.
func record(root string, r audit.Record) {
	if err := recordE(root, r); err != nil {
		fmt.Fprintf(os.Stderr, "%s%v%s\n", red, err, reset)
	}
}

// recordE is record, for a caller whose action is the record.
//
// A finding decision is nothing but its audit entry, so reporting one as made
// when the entry was refused is reporting something that did not happen.
// record prints the failure and carries on, which is right for a page save
// that is already in the store; for a decision the caller has to be told.
func recordE(root string, r audit.Record) error {
	err := writeRecord(root, r)
	noteAuditWrite(root, err)
	return err
}

// auditFaults holds, by store, the last failure to write its log in this
// process, until a write that succeeds clears it. A probe can tell that
// the writer listens and the file opens, not that the next record fits:
// a full disk, a writer refusing, a chain it cannot extend show only in a
// write, and are remembered from it.
var auditFaults sync.Map

func auditKey(root string) string {
	if abs, err := filepath.Abs(root); err == nil {
		return abs
	}
	return root
}

func noteAuditWrite(root string, err error) {
	if err != nil {
		auditFaults.Store(auditKey(root), err)
		return
	}
	auditFaults.Delete(auditKey(root))
}

// auditHeadroom is the space the log's filesystem must have left for an
// agent's action to go ahead: room for thousands of records, so the one
// about to be written is not the one that fills it.
const auditHeadroom = 8 << 20

// auditReady says whether an action whose record must exist may go ahead:
// the log can take a record now, as far as can be known without writing
// one. Agents' actions ask it first and are refused while it says no
// (SP 800-53 AU-5); what people do still goes ahead and is reported.
func auditReady(root string) error {
	refuse := func(why string) error {
		return fmt.Errorf("the audit log cannot take a record (%s), so nothing an agent does is performed "+
			"until it can: quilzo auditlog verify", why)
	}
	if v, ok := auditFaults.Load(auditKey(root)); ok {
		return refuse("the last record was not written: " + v.(error).Error())
	}
	if sock := logSocketPath(root); fileExists(sock) {
		if err := logd.Reachable(sock); err != nil {
			return refuse(err.Error())
		}
		return nil
	}
	if _, err := openAudit(root); err != nil {
		return refuse(err.Error())
	}
	f, err := os.OpenFile(auditPath(root), os.O_WRONLY|os.O_APPEND|os.O_CREATE, keyMode(root))
	if err != nil {
		return refuse(err.Error())
	}
	if err := f.Close(); err != nil {
		return refuse(err.Error())
	}
	if free, ok := audit.FreeBytes(auditDir(root)); ok && free < auditHeadroom {
		return refuse(fmt.Sprintf("%d bytes are left where it is kept", free))
	}
	return nil
}

// auditWritten, when set, is shown each record as it is written. The tests
// set it to check that no record names a person anywhere the log does not
// pseudonymise (auditnames_test.go); nothing else does.
var auditWritten func(root string, r audit.Record)

func writeRecord(root string, r audit.Record) error {
	if auditWritten != nil {
		auditWritten(root, r)
	}
	// A separate writer, if one is running. Its presence is the configuration:
	// the socket existing means somebody set this up, and going around it would
	// make the separation optional at exactly the moment it matters.
	if sock := logSocketPath(root); fileExists(sock) {
		_, err := logd.Submit(sock, logd.Submission{
			Action: r.Action, Resource: r.Resource, Outcome: string(r.Outcome),
			Principal: r.Principal, Kind: string(r.Kind), Model: r.Model,
			Verified: r.Verified, Detail: r.Detail, People: r.People,
		})
		if err != nil {
			// Deliberately no fallback to writing the file directly. Falling
			// back would mean anybody who can stop the writer regains the
			// ability to edit the log, which is the whole thing this prevents —
			// and where the separation is properly configured the fallback
			// would fail anyway, because this account cannot open the file.
			return fmt.Errorf("audit record NOT written: %v. The log writer "+
				"is configured and unreachable; this action is not in the "+
				"record", err)
		}
		return nil
	}

	l, err := openAudit(root)
	if err != nil {
		return fmt.Errorf("audit log unavailable: %v", err)
	}
	if _, err := l.Append(r); err != nil {
		return fmt.Errorf("audit record refused: %v", err)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func cmdAuditLog(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"show"}
	}
	// A log is a store's, and a --root with neither a store nor a log has
	// none: `auditlog verify` of a mistyped path said "0 entries, chain
	// intact" of a log it had just begun there. A log copied out on its own
	// is still read where it is. `dir` is about a directory of logs and
	// `verify-head` about a head and its keys, wherever they are, and help is
	// answered wherever it is asked.
	if args[0] != "dir" && args[0] != "verify-head" && !helpAsked(args[1:]) && !fileExists(auditPath(root)) {
		if err := needStore(root); err != nil {
			return err
		}
	}
	switch args[0] {
	case "dir":
		return cmdAuditDir(root, args[1:])
	case "verify":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return auditVerify(root)
	case "show":
		return auditShow(root, args[1:])
	case "export":
		return auditExport(root, args[1:])
	case "head":
		return auditHead(root, args[1:])
	case "verify-head":
		return auditVerifyHead(root, args[1:])
	case "prove":
		return auditProve(root, args[1:])
	case "consistency":
		return auditConsistency(root, args[1:])
	case "anchor":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return auditAnchor(root)
	default:
		return fmt.Errorf("unknown auditlog command %q; try show, verify, "+
			"export, head, verify-head, prove, consistency or anchor", args[0])
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
	events, err := audit.Read(auditPath(root))
	n := len(events)
	report, err := audit.Check(events, err)
	read := err == nil
	if err != nil {
		report = audit.Report{Problems: []audit.Problem{{Seq: 0, Reason: err.Error()}}}
	}
	// Against every head saved beside the log too. The chain cannot see
	// entries removed from its end: what is left verifies, and the next
	// write takes the first number removed. This said nothing was removed,
	// "including by an administrator", with a saved head covering entries
	// the log no longer held.
	heads, err := savedHeads(root)
	head := audit.LargestHead(heads)
	if err != nil {
		report.Problems = append(report.Problems, audit.Problem{Reason: "the heads saved beside the log " +
			"cannot be read, so it was not checked against them: " + err.Error()})
		report.Intact = false
	} else if read {
		if p := audit.AgainstHeads(events, heads); p != nil {
			report.Problems = append(report.Problems, *p)
			report.Intact = false
		}
	}
	good, problems := report.Intact, report.Problems

	if w.Mode == out.JSON {
		rows := make([]map[string]any, 0, len(problems))
		for _, p := range problems {
			rows = append(rows, map[string]any{"seq": p.Seq, "reason": p.Reason})
		}
		w.JSON(map[string]any{"entries": n, "intact": good, "problems": rows,
			"unfinished": report.Unfinished, "head": head})
		if !good {
			return errBlocked{fmt.Errorf("%d problem(s)", len(problems))}
		}
		return nil
	}

	w.Human("%d entr%s\n", n, entrySuffix(n))
	if good {
		// What the chain proves, and no more: it says nothing of entries
		// removed from the end, and its hashes are not keyed, so whoever
		// can rewrite the file can re-chain what is left.
		w.Human("  %schain intact%s\n", green, reset)
		w.Human("  %severy entry re-hashes and links to the one before it, so nothing\n"+
			"  between entries was altered, inserted or removed%s\n", dim, reset)
		if head == nil {
			w.Human("  %sno head is saved, so entries removed from the end would not show here:\n"+
				"  quilzo auditlog head --save, and keep a copy off this machine%s\n", yellow, reset)
			return nil
		}
		// The time through onOneLine, as the problem lines below are: it is
		// what the heads file holds, and that file can be rewritten with the
		// log. The audit log screen marks it the same way (shown).
		if len(heads) > 1 {
			w.Human("  %sand it still extends each of the %d heads saved beside it, the largest\n"+
				"  at %d entries (%s), so none of those was removed or rewritten since%s\n",
				dim, len(heads), head.Size, onOneLine(head.At), reset)
		} else {
			w.Human("  %sand it still extends the head saved at %d entries (%s), so none of\n"+
				"  those was removed or rewritten since%s\n", dim, head.Size, onOneLine(head.At), reset)
		}
		w.Human("  %sa head saved here can be rewritten with the log; a copy kept off this\n"+
			"  machine is the one that counts: quilzo auditlog consistency --head FILE%s\n", dim, reset)
		return nil
	}
	w.Human("  %s%d problem(s)%s\n", red, len(problems), reset)
	for _, p := range problems {
		// The reason can quote what the file held, for an entry that is not
		// readable at all; see auditShow.
		w.Human("    entry %d: %s\n", p.Seq, onOneLine(p.Reason))
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
	// Nor is a crash. A write cut short leaves a line that is not an entry,
	// and the writer carries on past it; called tampering, it was the same
	// alarm as a chmod, and it rang at "entry 0" of a log it said was one
	// entry long. Still a finding, so a script sees it: the record that
	// write was making is lost.
	if report.Crashed() {
		return errBlocked{fmt.Errorf("a write to the audit log was left unfinished, as a crash or a full " +
			"disk leaves one, and the record it was making is lost.\n  Every entry around it " +
			"re-hashes and links to the one before it, so this is not evidence of tampering")}
	}
	return errBlocked{fmt.Errorf("the audit log has been tampered with")}
}

// auditShow lists the most recent entries, or shows one in full.
//
// The help has always offered `auditlog show SEQ` for one entry, and nothing
// read the argument: `show 3` printed the last twenty-five entries as though
// one of them were entry 3, and exited 0. Arguments are now read wherever
// they are, and what is not a sequence number is refused rather than ignored.
func auditShow(root string, args []string) error {
	const usage = "usage: quilzo auditlog show [SEQ] [--limit N]"
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	limit := fs.Int("limit", 25, "how many recent entries")
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	// A negative limit sliced past the end of the log and panicked.
	if len(pos) > 1 || *limit < 0 {
		return errors.New(usage)
	}
	var seq int64
	if len(pos) == 1 {
		n, err := strconv.ParseInt(pos[0], 10, 64)
		if err != nil || n < 1 {
			return fmt.Errorf("%q is not a sequence number; %s", pos[0], usage)
		}
		seq = n
	}
	events, err := audit.Read(auditPath(root))
	// Verified here, and not only by `auditlog verify`.
	//
	// This printed whatever was in the file. Somebody who edits an entry and
	// then runs `quilzo auditlog show` sees the doctored record with nothing
	// to suggest it is doctored, and `show` is what anybody reads — `verify`
	// is what you run when you already suspect something, which is the one
	// time you do not need telling.
	//
	// The whole chain, not the page. A break before the window would go
	// unnoticed by a check that only looked at what is on screen, and the
	// question "has this log been edited" is about the log. A line that is
	// not an entry is among what it found, and the entries after it are
	// shown: they were not, for good, after one crash.
	report, err := audit.Check(events, err)
	if err != nil {
		return err
	}
	// And against the heads saved beside it, as verify and the audit log
	// screen check it. Along its chain alone, a log cut back was shown as
	// intact while verify said it had shrunk.
	if heads, err := savedHeads(root); err != nil {
		report.Problems = append(report.Problems, audit.Problem{Reason: "the heads saved beside the log " +
			"cannot be read, so it was not checked against them: " + err.Error()})
		report.Intact = false
	} else if p := audit.AgainstHeads(events, heads); p != nil {
		report.Problems = append(report.Problems, *p)
		report.Intact = false
	}
	intact, problems := report.Intact, report.Problems
	if seq != 0 {
		return auditShowEntry(events, seq, intact, report.Crashed(), problems)
	}

	if len(events) > *limit {
		events = events[len(events)-*limit:]
	}

	if w.JSON(map[string]any{
		"entries": events, "intact": intact, "problems": problems,
	}) {
		return nil
	}
	warnBroken(intact, report.Crashed(), problems)
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
		// To the second, which is the first nineteen characters of the time
		// the log writes, and no more than the entry has. Reading never
		// checks the shape of "at", and an entry whose time had been cut to
		// a date stopped this listing with a stack trace just after the
		// warning that the chain was broken, which is the one listing that
		// has to reach its end.
		at := e.At
		if len(at) > 19 {
			at = at[:19]
		}
		// Every field through onOneLine, because every field is what the file
		// holds and some of it was written by the people the log is about. A
		// decoy is presented by an outsider and the path they asked for is
		// recorded as they sent it, so a path carrying escape sequences
		// reached the terminal raw from here, erased its own line and the one
		// above it, and printed a green "all quiet". A doctored entry is no
		// different: one that could move the cursor could clear the warning
		// printed above it. JSON and `auditlog export` keep the exact bytes;
		// this is only what a person is shown. Padding still lines up,
		// because each control character becomes one visible character.
		w.Human("  %-19s  %s%-8s%s %-16s %-22s %s(%s)%s\n",
			onOneLine(at), colour, onOneLine(string(e.Outcome)), reset,
			onOneLine(e.Action), onOneLine(e.Resource), dim, onOneLine(who), reset)
	}
	return nil
}

// warnBroken says, before any entry is shown, that the chain does not hold,
// or, when crashed, that all it found is a write a crash left unfinished
// (audit.Report.Crashed), which is not tampering.
func warnBroken(intact, crashed bool, problems []audit.Problem) {
	if intact {
		return
	}
	if crashed {
		w.Human("%sa write was left unfinished — its record is lost, and every entry "+
			"around it links up%s\n", yellow, reset)
	} else {
		w.Human("%sthe chain is broken — these entries cannot be trusted%s\n",
			yellow, reset)
	}
	for _, p := range problems {
		w.Human("  %sentry %d: %s%s\n", dim, p.Seq, onOneLine(p.Reason), reset)
	}
	w.Human("  %squilzo auditlog verify — the whole story%s\n\n", dim, reset)
}

// auditShowEntry is `auditlog show SEQ`: one entry, every field of it,
// after the same statement about the whole chain that the listing makes.
func auditShowEntry(events []audit.Event, seq int64, intact, crashed bool, problems []audit.Problem) error {
	var entry *audit.Event
	for i := range events {
		if events[i].Seq == seq {
			entry = &events[i]
			break
		}
	}
	if entry == nil {
		return fmt.Errorf("there is no entry %d in a log of %d", seq, len(events))
	}
	// "entry", as `auditlog prove` names the one it is about.
	if w.JSON(map[string]any{"entry": entry, "intact": intact, "problems": problems}) {
		return nil
	}
	warnBroken(intact, crashed, problems)
	w.Human("%sentry %d%s\n", bold, entry.Seq, reset)
	// Every value through onOneLine, as in the listing, and the detail's
	// keys too: all of it is what the file holds.
	field := func(name, value string) {
		if value != "" {
			w.Human("  %-10s %s\n", name, onOneLine(value))
		}
	}
	field("at", entry.At)
	field("action", entry.Action)
	field("resource", entry.Resource)
	field("outcome", string(entry.Outcome))
	field("principal", entry.Principal)
	field("kind", string(entry.Kind))
	field("verified", strconv.FormatBool(entry.Verified))
	field("model", entry.Model)
	field("source", entry.Source)
	field("prev", entry.Prev)
	field("hash", entry.Hash)
	if len(entry.Detail) > 0 {
		keys := make([]string, 0, len(entry.Detail))
		for k := range entry.Detail {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		w.Human("  detail\n")
		for _, k := range keys {
			w.Human("    %-16s %s\n", onOneLine(k), onOneLine(entry.Detail[k]))
		}
	}
	return nil
}

// auditExport is the whole log as it is stored, on standard output or, with
// -o, in a file, unverified, so a log whose chain is broken can still be
// taken away and examined, which `quilzo siem` refuses to do.
//
// The help has always offered `auditlog export -o FILE`, and the dispatcher
// passed this nothing: the whole log went to the terminal, no file was made,
// and the exit status was 0, so a script that shipped the archive it had just
// written shipped nothing. The file is written whole or not at all, and
// readable by this account only, as the log it copies is.
//
// Through the one export of the log, as the log stores it
// (siem.Options.AsStored), and recorded as every export of the log is
// (siem.ExportRecorded). It was an exporter of its own that recorded
// nothing, and it is the one bulk export the auditor's job reaches, so the
// record an auditor would look for of the log leaving was missing for
// exactly the people meant to read it.
func auditExport(root string, args []string) error {
	fs := flag.NewFlagSet("auditlog export", flag.ContinueOnError)
	to := fs.String("o", "", "write the log to this file instead of printing it")
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("auditlog export takes no %q; usage: quilzo auditlog export [-o FILE]", pos[0])
	}
	events, err := exportedEntries(root)
	if err != nil {
		return err
	}
	res, err := siem.ExportRecorded(siem.JSONL, events, siem.Options{AsStored: true}, time.Now(),
		recordAuditLogExport(root))
	if err != nil {
		return err
	}
	if *to == "" {
		_, err := os.Stdout.WriteString(res.Body)
		return err
	}
	if err := atomicfile.Write(*to, []byte(res.Body), 0o600); err != nil {
		return err
	}
	if w.JSON(map[string]any{"entries": res.Count, "events": res.Count, "first_seq": res.Chain.FirstSeq,
		"last_seq": res.Chain.LastSeq, "file": *to}) {
		return nil
	}
	w.Human("%d entr%s written to %s\n", res.Count, entrySuffix(res.Count), *to)
	return nil
}

// entrySuffix completes "entr-y" or "entr-ies".
//
// It was called plural(n), which reads as a general helper and is not one: it
// returns "y" and "ies" and nothing else. The next person to reach for it
// printed "1 submissiony". Named for the word it completes, so the mistake is
// not available.
func entrySuffix(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// count renders "1 submission" and "4 submissions".
//
// The plain case, for words that take an s. A word that does not is a word
// this should not be used for.
func count(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// -- transparency ------------------------------------------------------------

func headsPath(root string) string { return filepath.Join(root, "log-heads.json") }

type headFile struct {
	Heads []audit.Head `json:"heads"`
}

// savedHeads is every head saved beside the log, by `auditlog head --save`
// or `anchor`: what verify, posture, consistency and the audit log screen
// check the log against, as well as along its chain (audit.AgainstHeads).
//
// Every one, not the largest alone: a log cut back and grown again extends
// the next head saved, and only one saved before the cut shows it. A head
// kept here can be rewritten with the log by whoever can rewrite the log,
// and says so where it is reported; it still catches everybody else.
func savedHeads(root string) ([]audit.Head, error) {
	f := &headFile{}
	if err := loadJSON(headsPath(root), f); err != nil {
		return nil, err
	}
	return f.Heads, nil
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
	if err := parseFlags(fs, args, nil, 0); err != nil {
		return err
	}

	events, err := auditEntries(root)
	if err != nil {
		return err
	}
	head, err := audit.TreeHead(events, time.Now())
	if err != nil {
		return err
	}

	// Signed, with both algorithms, before it goes anywhere.
	//
	// An unsigned head is three fields anybody with a text editor can produce,
	// so exporting one to a SIEM or handing it to an auditor proved only that
	// somebody had typed a plausible root. See internal/audit/sign.go for why
	// there are two signatures rather than one.
	signer, err := headSigner(root)
	if err != nil {
		return err
	}
	signed, err := signer.Sign(head)
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

	if w.JSON(signed) {
		return nil
	}
	w.Human("%s%d entries%s\n", bold, head.Size, reset)
	w.Human("  root %s\n", head.Root)
	if signer.PostQuantum() {
		w.Human("  signed by %s with Ed25519 and ML-DSA-65\n", signed.KeyID)
	} else {
		// Said here rather than only in a report, because this is the moment
		// somebody is looking at a head and deciding what it is worth.
		w.Human("  signed by %s with Ed25519 alone\n", signed.KeyID)
		w.Human("\n  %s%s%s\n", yellow, signer.Why(), reset)
		w.Human("  %sa verifier has to be told it accepts a head with one "+
			"signature%s\n", dim, reset)
	}
	w.Human("\n  %sthis commits to every entry. Get it out of this machine —\n"+
		"  export it to a SIEM, hand it to an auditor, or anchor it:%s\n",
		dim, reset)
	w.Human("    %squilzo auditlog anchor%s\n", dim, reset)
	w.Human("\n  %sthe public keys to check it are at %s%s\n",
		dim, headKeysPath(root), reset)
	w.Human("\n  %sa head kept only here protects nothing: whoever can rewrite\n"+
		"  the log can rewrite the head beside it%s\n", yellow, reset)
	return nil
}

// auditProve produces an inclusion proof for one entry.
func auditProve(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo auditlog prove <sequence>")
	}
	var seq int64
	if _, err := fmt.Sscanf(args[0], "%d", &seq); err != nil {
		return fmt.Errorf("%q is not a sequence number", args[0])
	}

	events, err := auditEntries(root)
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
	headPath := fs.String("head", "", "a signed head kept off this machine (auditlog head --json), "+
		"checked against instead of the heads saved beside the log")
	keysPath := fs.String("keys", "", "the public keys that check that head (default head.pub.json beside the log)")
	// A head file may be named on its own as well. It was dropped without a
	// word, and the heads saved beside the log checked instead: the one
	// kept off the machine, which is the one that counts, could not be
	// checked at all.
	files, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	switch {
	case len(files) == 1 && *headPath == "":
		*headPath = files[0]
	case len(files) > 0:
		return fmt.Errorf("usage: quilzo auditlog consistency [--since N] [--head FILE [--keys FILE]]")
	}

	events, err := auditEntries(root)
	if err != nil {
		return err
	}

	// The head named, once its signatures check out. Otherwise the heads
	// saved beside the log if no size was named, because that is the check
	// somebody wants and remembering a number is not: every one, as verify
	// checks them, with the proof from the largest. The largest and not the
	// newest: a head saved after entries were removed from the end covers
	// fewer than one saved before them, and checked against that, the log
	// was called consistent.
	var published audit.Head
	if *headPath != "" {
		keys := *keysPath
		if keys == "" {
			keys = headKeysPath(root)
		}
		sh, err := loadSignedHead(*headPath, keys)
		if err != nil {
			return err
		}
		if *against != 0 && *against != sh.Size {
			return fmt.Errorf("the head in %s covers %d entries, not %d", *headPath, sh.Size, *against)
		}
		published = sh.Head
	} else if *against == 0 {
		heads, err := savedHeads(root)
		if err != nil {
			return err
		}
		h := audit.LargestHead(heads)
		if h == nil {
			return fmt.Errorf(
				"no head has been published, so there is nothing to check " +
					"against.\n  `quilzo auditlog head --save` records one; a " +
					"head only proves anything once it exists somewhere the log " +
					"cannot be quietly rewritten alongside")
		}
		// And every other head saved: the largest was taken from the log as
		// it is if it was saved after a cut, and one saved before is what
		// shows the cut.
		if p := audit.AgainstHeads(events, heads); p != nil {
			return errBlocked{errors.New(p.Reason)}
		}
		published = *h
	} else {
		f := &headFile{}
		if err := loadJSON(headsPath(root), f); err != nil {
			return err
		}
		var named []audit.Head
		for _, h := range f.Heads {
			if h.Size == *against {
				published = h
				named = append(named, h)
			}
		}
		if published.Root == "" {
			return fmt.Errorf("no published head covers %d entries", *against)
		}
		// Every head of that size, not the newest alone: two of one size
		// with different roots are one taken before a cut and one after it,
		// and the one after was the one checked.
		if p := audit.AgainstHeads(events, named); p != nil {
			return errBlocked{errors.New(p.Reason)}
		}
	}
	oldSize := published.Size

	proof, now, err := audit.Extends(events, published)
	if err != nil {
		return errBlocked{err}
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
	events, err := auditEntries(root)
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
	proofs, errs := anchor.Submit(ctx, anchorCalendars(), digest, nil, time.Now())
	for _, e := range errs {
		w.Human("  %s%v%s\n", yellow, e, reset)
	}
	if len(proofs) == 0 {
		return errBlocked{fmt.Errorf("no calendar accepted the log head")}
	}
	// Kept as a log head: these go into the file publications' proofs are
	// in, and without the kind the Integrity screen showed them as those.
	for i := range proofs {
		proofs[i].Kind = anchor.LogHead
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

	af, err := loadAnchors(root)
	if err != nil {
		return err
	}
	af.Proofs = append(af.Proofs, proofs...)
	if err := saveJSON(anchorPath(root), af); err != nil {
		return err
	}
	// Sending the log's head out is an act, as `anchor submit` sending the
	// publication's is, and that one was on the record while this was not.
	// The entry goes after the head it names, so the head is unchanged.
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "auditlog.anchor", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		Detail: map[string]string{
			"root":      head.Root,
			"size":      fmt.Sprintf("%d", head.Size),
			"calendars": fmt.Sprintf("%d", len(proofs)),
		},
	})

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

// adminRecord is an audit record for what the admin reports, from the
// detail it reports it with.
//
// A person signed in names themselves as "by", and is a verified human. A
// refusal at the door has nobody signed in — a wrong enrolment link, a
// failed single sign-on, an account locked by somebody else's guesses —
// and was written with no principal at all, which the log refuses (AU-3),
// so the attempts it most needed to keep were the ones it lost. Those are
// recorded as an anonymous caller, not verified, and a refusal is recorded
// as one: they were all written as successes.
func adminRecord(action, resource string, detail map[string]string) audit.Record {
	r := audit.Record{Action: action, Resource: resource, Outcome: audit.Success,
		Principal: detail["by"], Kind: audit.KindHuman, Verified: true, Detail: detail}
	if r.Principal == "" {
		r.Principal, r.Kind, r.Verified = "anonymous", audit.KindUnknown, false
	}
	switch {
	case strings.HasSuffix(action, "refused") || strings.HasSuffix(action, ".denied"):
		r.Outcome = audit.Denied
	case detail["outcome"] == "failed" || strings.HasSuffix(action, "-failed") || strings.HasSuffix(action, ".failed"):
		r.Outcome = audit.Failure
	}
	return r
}
