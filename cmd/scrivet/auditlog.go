package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/out"
)

func auditPath(root string) string { return filepath.Join(root, "audit.jsonl") }
func auditKeyPath(root string) string {
	return filepath.Join(root, "audit.key")
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
		if err := os.WriteFile(auditKeyPath(root), key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown-host"
	}
	return audit.New(audit.Options{
		Path: auditPath(root), Key: key, Source: "scrivet-cli@" + host,
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
	l, err := openAudit(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%saudit log unavailable: %v%s\n", red, err, reset)
		return
	}
	if _, err := l.Append(r); err != nil {
		fmt.Fprintf(os.Stderr, "%saudit record refused: %v%s\n", red, err, reset)
	}
}

func cmdAuditLog(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"show"}
	}
	switch args[0] {
	case "verify":
		return auditVerify(root)
	case "show":
		return auditShow(root, args[1:])
	case "export":
		return auditExport(root)
	default:
		return fmt.Errorf("unknown auditlog command %q; try show, verify or export", args[0])
	}
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
