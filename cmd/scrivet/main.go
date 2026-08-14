// Command scrivet is the whole CMS. There is no admin panel yet, and that
// ordering is deliberate: a CMS whose primitives only exist behind a web UI
// cannot be scripted, reviewed in a pull request, or driven by an assistant
// without pretending to be a browser. Building the UI on a complete CLI keeps
// every action available to a person, a script and an agent on equal terms.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rsh1k/scrivet/internal/site"
	"github.com/rsh1k/scrivet/internal/store"
	"github.com/rsh1k/scrivet/internal/tmpl"
)

const defaultRoot = ".scrivet"

const (
	dim    = "\033[2m"
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
	reset  = "\033[0m"
)

var version = "dev"

func usage() {
	fmt.Fprint(os.Stderr, `scrivet — a CMS where content is immutable and publishing is a pointer.

  scrivet init                              create a content store
  scrivet add NAME=FILE.json [...]          stage pages into a draft
  scrivet diff                              what differs between live and draft
  scrivet publish [COMMIT]                  move live to the draft
  scrivet rollback [--steps N]              move live back along its history
  scrivet log [--ref draft|live]            commit history
  scrivet render PAGE TEMPLATE [-o FILE]    render a page
  scrivet audit [DIR]                       list templates that disable escaping
  scrivet verify                            re-hash every object

  --root DIR    store location (default .scrivet)
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	root := defaultRoot
	args := os.Args[1:]
	// A tiny hand-rolled global flag pass, so `--root` works before the
	// subcommand as well as after it.
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--root" && i+1 < len(args) {
			root = args[i+1]
			i++
			continue
		}
		if v, ok := strings.CutPrefix(args[i], "--root="); ok {
			root = v
			continue
		}
		rest = append(rest, args[i])
	}
	if len(rest) == 0 {
		usage()
		os.Exit(2)
	}

	cmd, cmdArgs := rest[0], rest[1:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(root)
	case "add":
		err = cmdAdd(root, cmdArgs)
	case "diff":
		err = cmdDiff(root)
	case "publish":
		err = cmdPublish(root, cmdArgs)
	case "rollback":
		err = cmdRollback(root, cmdArgs)
	case "log":
		err = cmdLog(root, cmdArgs)
	case "render":
		err = cmdRender(root, cmdArgs)
	case "audit":
		err = cmdAudit(cmdArgs)
	case "verify":
		err = cmdVerify(root)
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func open(root string) (*store.Store, error) { return store.Open(root) }

// reorder moves flags ahead of positional arguments.
//
// Go's flag package stops parsing at the first non-flag argument, so
// `add index=home.json -m "msg"` treats -m as a filename. That is the natural
// order to type and the CLI has to accept it, so flags are lifted out first.
// `valued` names the flags that consume the following argument; a boolean flag
// must not swallow the token after it.
func reorder(args []string, valued map[string]bool) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if n, _, hasEq := strings.Cut(name, "="); hasEq {
			_ = n
			continue // --flag=value carries its own value
		}
		if valued[name] && i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return append(flags, positional...)
}

func cmdInit(root string) error {
	_, existed := os.Stat(root)
	s, err := open(root)
	if err != nil {
		return err
	}
	if existed != nil {
		fmt.Printf("created %s\n", s.Root())
		fmt.Printf("  %scontent is immutable and addressed by hash; publishing "+
			"moves a pointer%s\n", dim, reset)
	} else {
		fmt.Printf("reusing %s\n", s.Root())
	}
	return nil
}

func cmdAdd(root string, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	msg := fs.String("m", "edit", "commit message")
	author := fs.String("author", "cli", "author")
	remove := fs.String("remove", "", "comma-separated page names to drop")
	if err := fs.Parse(reorder(args, map[string]bool{
		"m": true, "author": true, "remove": true})); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	parent := s.GetRef(site.RefDraft)
	if parent == "" {
		parent = s.GetRef(site.RefLive)
	}
	pages := map[string]any{}
	if parent != "" {
		if pages, err = site.PagesAt(s, parent); err != nil {
			return err
		}
	}

	for _, spec := range fs.Args() {
		name, path, ok := strings.Cut(spec, "=")
		if !ok {
			return fmt.Errorf("expected NAME=FILE.json, got %q", spec)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("cannot read %s: %w", path, err)
		}
		var v any
		if err := json.Unmarshal(body, &v); err != nil {
			return fmt.Errorf("%s is not valid JSON: %w", path, err)
		}
		pages[name] = v
	}
	for _, name := range strings.Split(*remove, ",") {
		if name = strings.TrimSpace(name); name != "" {
			delete(pages, name)
		}
	}

	cid, err := site.SaveDraft(s, pages, *msg, *author)
	if err != nil {
		return err
	}
	fmt.Printf("draft %s  %d page(s)\n", short(cid), len(pages))
	return nil
}

func cmdDiff(root string) error {
	s, err := open(root)
	if err != nil {
		return err
	}
	live, draft := s.GetRef(site.RefLive), s.GetRef(site.RefDraft)
	if draft == "" {
		fmt.Println("no draft")
		return nil
	}
	if live == draft {
		fmt.Println("draft matches live")
		return nil
	}
	changes, err := site.Diff(s, live, draft)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		fmt.Println("no content differences")
		return nil
	}
	colour := map[string]string{"added": green, "removed": red, "modified": yellow}
	for _, c := range changes {
		fmt.Printf("  %s%-9s%s %s\n", colour[c.Kind], c.Kind, reset, c.Path)
	}
	fmt.Printf("\n  %d change(s) between live and draft\n", len(changes))
	return nil
}

func cmdPublish(root string, args []string) error {
	s, err := open(root)
	if err != nil {
		return err
	}
	target := ""
	if len(args) > 0 {
		target = args[0]
	}
	pub, err := site.Publish(s, target)
	if err != nil {
		return err
	}
	if len(pub.Changes) == 0 && pub.Previous == pub.Published {
		fmt.Println("already live")
		return nil
	}
	fmt.Printf("live is now %s  (%d change(s))\n", short(pub.Published), len(pub.Changes))
	if pub.Previous != "" {
		fmt.Printf("  %sprevious %s is still stored; `scrivet rollback` moves the "+
			"pointer back%s\n", dim, short(pub.Previous), reset)
	}
	// Said plainly because it is the one thing a pointer cannot fix.
	fmt.Printf("  %srolling back restores the content, not the fact that it was "+
		"published%s\n", dim, reset)
	return nil
}

func cmdRollback(root string, args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	steps := fs.Int("steps", 1, "how many commits to go back")
	if err := fs.Parse(reorder(args, map[string]bool{"steps": true})); err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	pub, err := site.Rollback(s, *steps)
	if err != nil {
		return err
	}
	fmt.Printf("live is now %s  (%d change(s) reverted)\n",
		short(pub.Published), len(pub.Changes))
	fmt.Printf("  %srolled back from %s, which is still stored and can be "+
		"published again%s\n", dim, short(pub.Previous), reset)
	return nil
}

func cmdLog(root string, args []string) error {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	ref := fs.String("ref", site.RefDraft, "which ref to walk")
	limit := fs.Int("limit", 20, "how many commits")
	if err := fs.Parse(reorder(args, map[string]bool{
		"ref": true, "limit": true})); err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	head := s.GetRef(*ref)
	if head == "" {
		return fmt.Errorf("no ref %q", *ref)
	}
	live := s.GetRef(site.RefLive)
	hist, err := s.History(head, *limit)
	if err != nil {
		return err
	}
	for _, h := range hist {
		mark := ""
		if h.ID == live {
			mark = green + " ← live" + reset
		}
		fmt.Printf("  %s  %-10s %s%s\n", short(h.ID), h.Commit.Author, h.Commit.Message, mark)
	}
	return nil
}

func cmdRender(root string, args []string) error {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	ref := fs.String("ref", site.RefLive, "which ref to read")
	out := fs.String("o", "", "write here instead of stdout")
	if err := fs.Parse(reorder(args, map[string]bool{
		"ref": true, "o": true})); err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return fmt.Errorf("usage: scrivet render PAGE TEMPLATE")
	}
	pageName, templatePath := fs.Arg(0), fs.Arg(1)

	s, err := open(root)
	if err != nil {
		return err
	}
	pages, err := site.PagesAt(s, *ref)
	if err != nil {
		return err
	}
	page, ok := pages[pageName]
	if !ok {
		names := make([]string, 0, len(pages))
		for n := range pages {
			names = append(names, n)
		}
		sort.Strings(names)
		return fmt.Errorf("no page %q; have %s", pageName, strings.Join(names, ", "))
	}

	src, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}
	names := make([]any, 0, len(pages))
	for n := range pages {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return names[i].(string) < names[j].(string) })

	html, err := tmpl.Render(string(src), map[string]any{
		"page": page,
		"site": map[string]any{"pages": names},
	})
	if err != nil {
		return fmt.Errorf("template: %w", err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(html), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", *out)
		return nil
	}
	fmt.Print(html)
	return nil
}

func cmdAudit(args []string) error {
	dir := "templates"
	if len(args) > 0 {
		dir = args[0]
	}
	total := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".html" {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		sites := tmpl.RawSites(string(body))
		if len(sites) > 0 {
			fmt.Printf("  %s\n", path)
			for _, s := range sites {
				fmt.Printf("      %sraw%s %s\n", yellow, reset, s)
			}
			total += len(sites)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if total > 0 {
		fmt.Printf("\n  %d place(s) where escaping is switched off. Each one is a "+
			"decision to trust that content.\n", total)
	} else {
		fmt.Println("  no template opts out of escaping")
	}
	return nil
}

func cmdVerify(root string) error {
	s, err := open(root)
	if err != nil {
		return err
	}
	n, err := s.Verify()
	if err != nil {
		return fmt.Errorf("%s%v%s", red, err, reset)
	}
	fmt.Printf("  %d object(s) intact\n", n)
	fmt.Printf("  %severy object re-hashed to the id it is filed under%s\n", dim, reset)
	return nil
}

func short(oid string) string {
	if len(oid) > 12 {
		return oid[:12]
	}
	return oid
}
