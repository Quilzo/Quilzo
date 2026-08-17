package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/out"
)

// Forms from a terminal: the operations a pipeline and an obligation need.
//
// Reading submissions is not one of them. They are what members of the public
// typed, they belong behind authentication on a screen where deleting one is a
// button, and a command that prints them to a terminal is a command that puts
// them in a shell history and a CI log. What is here is retention, which wants
// to run from a timer, and erasure, which has a deadline attached.
func cmdForms(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return formsList(root)
	case "expire":
		return formsExpire(root)
	case "erase":
		return formsErase(root, args[1:])
	default:
		return fmt.Errorf("unknown form command %q; try list, expire or erase",
			args[0])
	}
}

func formsList(root string) error {
	set, err := loadForms(root)
	if err != nil {
		return err
	}
	st, err := openSubmissions(root)
	if err != nil {
		return err
	}
	type row struct {
		Name     string `json:"name"`
		Held     int    `json:"held"`
		KeptDays int    `json:"kept_days"`
		Closed   bool   `json:"closed"`
	}
	var rows []row
	for _, name := range set.Names() {
		f, _ := set.Get(name)
		subs, _ := st.List(name)
		rows = append(rows, row{name, len(subs),
			int(f.Retention().Hours() / 24), f.Closed})
	}
	if w.JSON(rows) {
		return nil
	}
	if len(rows) == 0 {
		w.Human("no forms\n")
		return nil
	}
	for _, r := range rows {
		state := green + "open" + reset
		if r.Closed {
			state = yellow + "closed" + reset
		}
		w.Human("%s%-18s%s %3d held  %s%d days%s  %s\n",
			bold, r.Name, reset, r.Held, dim, r.KeptDays, reset, state)
	}
	w.Human("\n  %ssubmissions are read in the interface, not here — they are "+
		"what%s\n", dim, reset)
	w.Human("  %smembers of the public typed, and a terminal is a shell "+
		"history%s\n", dim, reset)
	return nil
}

// formsExpire runs retention. Meant for a timer.
func formsExpire(root string) error {
	set, err := loadForms(root)
	if err != nil {
		return err
	}
	st, err := openSubmissions(root)
	if err != nil {
		return err
	}
	n, err := st.Expire(set, time.Now())
	if err != nil {
		return err
	}
	if n > 0 {
		record(root, resolveCaller(root, "").auditRecord("form.expire", "/",
			audit.Success, map[string]string{"removed": fmt.Sprint(n)}))
	}
	if w.JSON(map[string]any{"removed": n}) {
		return nil
	}
	w.Human("%d submission(s) past their retention period are gone\n", n)
	return nil
}

// formsErase honours a request to be forgotten.
//
// Searches every form for the value and removes what matches. --dry-run first,
// because this is irreversible and the person asking gave you a string rather
// than a list of identifiers.
func formsErase(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("erase", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "report what would go and remove nothing")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf(
			"usage: scrivet form erase <value> [--dry-run]\n" +
				"  the value is what the person gave you — usually an address")
	}

	set, err := loadForms(root)
	if err != nil {
		return err
	}
	st, err := openSubmissions(root)
	if err != nil {
		return err
	}
	found, err := st.Search(set, pos[0])
	if err != nil {
		return err
	}

	if w.Mode == out.JSON {
		w.JSON(map[string]any{"matched": len(found), "removed": !*dry})
		return nil
	}
	if len(found) == 0 {
		w.Human("nothing matches %q\n", pos[0])
		return nil
	}
	for _, s := range found {
		w.Human("  %s%s%s  %s\n", dim, s.Form, reset, short(s.ID))
	}
	if *dry {
		w.Human("\n%d submission(s) would be erased\n", len(found))
		return nil
	}
	for _, s := range found {
		if err := st.Delete(s.Form, s.ID); err != nil {
			return err
		}
	}
	// The count and the forms, never the value that was searched for — that
	// value is the personal data somebody asked to have removed, and writing
	// it into an append-only log is the one place it would survive the
	// erasure.
	record(root, resolveCaller(root, "").auditRecord("form.erase", "/",
		audit.Success, map[string]string{"removed": fmt.Sprint(len(found))}))
	w.Human("\n%d submission(s) erased\n", len(found))
	return nil
}
