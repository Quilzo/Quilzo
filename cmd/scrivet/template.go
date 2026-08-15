package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rsh1k/scrivet/internal/starter"
)

func cmdTemplate(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return templateList()
	case "show":
		return templateShow(args[1:])
	case "use":
		return templateUse(root, args[1:])
	default:
		return fmt.Errorf("unknown template command %q; try list, show or use",
			args[0])
	}
}

func templateList() error {
	all := starter.All()
	if w.JSON(all) {
		return nil
	}
	for _, t := range all {
		w.Human("%s%-11s%s %s\n", bold, t.Name, reset, wrapIndent(t.Summary, 62, 12))
		w.Human("  %s%d fields · scrivet template show %s%s\n\n",
			dim, len(t.Fields), t.Name, reset)
	}
	w.Human("%sscrivet template use NAME  writes the template, its stylesheet%s\n",
		dim, reset)
	w.Human("%s                           and sample content you can edit%s\n",
		dim, reset)
	return nil
}

func templateShow(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: scrivet template show <name>")
	}
	t, ok := starter.Get(args[0])
	if !ok {
		return fmt.Errorf("no starter template %q; try: %s",
			args[0], strings.Join(starter.Names(), ", "))
	}
	if w.JSON(t) {
		return nil
	}
	w.Human("%s%s%s\n", bold, t.Name, reset)
	w.Human("%s\n\n", wrapIndent(t.Summary, 74, 0))

	w.Human("%sfields%s\n", bold, reset)
	fields := append([]string{}, t.Fields...)
	sort.Strings(fields)
	for _, f := range fields {
		kind := "text"
		switch v := t.Sample[f].(type) {
		case []any:
			kind = fmt.Sprintf("list of %d", len(v))
		case map[string]any:
			kind = "object"
		case nil:
			kind = "optional"
		}
		w.Human("  %-18s %s%s%s\n", f, dim, kind, reset)
	}
	return nil
}

func templateUse(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("use", flag.ContinueOnError)
	dir := fs.String("dir", "templates", "where to write page.html and site.css")
	page := fs.String("page", "index", "page name for the sample content")
	force := fs.Bool("force", false, "overwrite files that already exist")
	noContent := fs.Bool("no-content", false, "write the template but not the sample")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: scrivet template use <name> [--dir templates]")
	}
	t, ok := starter.Get(pos[0])
	if !ok {
		return fmt.Errorf("no starter template %q; try: %s",
			pos[0], strings.Join(starter.Names(), ", "))
	}
	html, err := t.HTML()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	// Refuse to clobber by default. A template directory is somebody's work,
	// and "use" reading as "replace what I spent a week on" is the kind of
	// surprise a tool gets one chance at.
	targets := map[string]string{
		filepath.Join(*dir, "page.html"): html,
		filepath.Join(*dir, "site.css"):  starter.CSS(),
	}
	if !*force {
		for path := range targets {
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("%s already exists; pass --force to replace it",
					path)
			}
		}
	}
	for path, body := range targets {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return err
		}
	}

	w.Human("wrote %s%s%s from the %s starter\n",
		bold, filepath.Join(*dir, "page.html"), reset, t.Name)
	w.Human("wrote %s%s%s\n", bold, filepath.Join(*dir, "site.css"), reset)

	if *noContent {
		return nil
	}
	// Sample content, so the first render shows a finished page rather than a
	// skeleton with every field empty. It is also the fixture the test suite
	// renders, which is why it is guaranteed to fill the template.
	sample := filepath.Join(*dir, t.Name+".json")
	body, err := json.MarshalIndent(t.Sample, "", "  ")
	if err != nil {
		return err
	}
	if _, err := os.Stat(sample); err == nil && !*force {
		w.Human("  %s%s already exists, left alone%s\n", dim, sample, reset)
	} else if err := os.WriteFile(sample, body, 0o600); err != nil {
		return err
	} else {
		w.Human("wrote %s%s%s\n", bold, sample, reset)
	}

	w.Human("\n  %snext:%s\n", dim, reset)
	w.Human("    scrivet add %s=%s\n", *page, sample)
	w.Human("    scrivet render %s %s -o preview.html\n",
		*page, filepath.Join(*dir, "page.html"))
	w.Human("\n  %sthe stylesheet is served at /site.css by scrivet site%s\n",
		dim, reset)
	return nil
}

// wrapIndent wraps text to a width, indenting continuation lines.
func wrapIndent(s string, width, indent int) string {
	words := strings.Fields(s)
	var b strings.Builder
	col := 0
	for i, word := range words {
		if col+len(word) > width && i > 0 {
			b.WriteString("\n" + strings.Repeat(" ", indent))
			col = indent
		} else if i > 0 {
			b.WriteString(" ")
			col++
		}
		b.WriteString(word)
		col += len(word)
	}
	return b.String()
}
