package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/collection"
	"github.com/rsh1k/scrivet/internal/demo"
	"github.com/rsh1k/scrivet/internal/form"
	"github.com/rsh1k/scrivet/internal/listing"
	"github.com/rsh1k/scrivet/internal/media"
	"github.com/rsh1k/scrivet/internal/schema"
	"github.com/rsh1k/scrivet/internal/site"
)

// Installing a whole application, so somebody can see one.
//
// A starter template shows what a page looks like. It cannot show what this
// tool is for, because that only appears with several features working at once
// — a query over records, a page embedding it, a navigation that will not point
// at nothing, content with a date after which it stops being served, and a form
// the public process can write to and cannot read.
//
// So this installs Gram: the demonstration in internal/demo, which was built
// through the admin interface before it was written down.
//
// # It refuses to run over anything
//
// Not a flag, not a confirmation prompt — a refusal. This writes content types,
// listings, menus, vocabularies, forms, a media library and a draft, and
// running it into somebody's site would overwrite the parts of their setup that
// share a name with the parts of this one. The store it wants is an empty one.

func cmdDemo(root string, args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	tplDir := fs.String("templates", "templates",
		"where to write page.html and site.css")
	publish := fs.Bool("publish", true,
		"publish the draft, so the site serves immediately")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	if s.GetRef(site.RefDraft) != "" || s.GetRef(site.RefLive) != "" {
		return fmt.Errorf(
			"this store already has content, and the demonstration would " +
				"write over the content types, listings, menus and forms that " +
				"share a name with its own.\n  Run it in an empty directory:\n" +
				"    mkdir gram && cd gram && scrivet init && scrivet demo")
	}

	d := demo.Gram()

	// Media first, because everything else refers to it and a file's address is
	// the hash of its bytes — not known until it is stored.
	lib, err := openMedia(root)
	if err != nil {
		return fmt.Errorf("opening the media library: %w", err)
	}
	addresses := map[string]string{}
	for _, a := range d.Media {
		f, aerr := media.Accept(a.Name+".png", a.Bytes, time.Now())
		if aerr != nil {
			return fmt.Errorf("%s: %w", a.Name, aerr)
		}
		f.Alt = a.Alt
		if perr := lib.Put(f, a.Bytes); perr != nil {
			return fmt.Errorf("storing %s: %w", a.Name, perr)
		}
		addresses[a.Name] = f.ID
	}
	if rerr := d.Resolve(addresses); rerr != nil {
		return rerr
	}

	// Types, and the pages bound to them. Saved before the content so the
	// content is validated against them on the way in rather than afterwards.
	types, err := schema.Load(root)
	if err != nil {
		return err
	}
	for _, t := range d.Types {
		if aerr := types.Registry.Add(t); aerr != nil {
			return fmt.Errorf("content type %s: %w", t.Name, aerr)
		}
	}
	for page, name := range d.Bind {
		if berr := types.Bind(page, name); berr != nil {
			return fmt.Errorf("binding %s: %w", page, berr)
		}
	}
	if serr := types.Save(); serr != nil {
		return serr
	}

	// The content itself, checked against its own types before it is stored.
	if failures := types.Gate(d.Pages); len(failures) > 0 {
		lines := make([]string, 0, len(failures))
		for _, f := range failures {
			lines = append(lines, f.String())
		}
		sort.Strings(lines)
		return fmt.Errorf("the demonstration does not satisfy its own types, "+
			"which is a bug in it and not in your store:\n  %v", lines)
	}
	// An empty base, stated rather than defaulted. This command has already
	// refused to run unless both refs are unset, so there is provably nothing
	// to collide with — which is the one case where an empty base is a decision
	// and not an omission.
	if _, serr := site.SaveDraftFrom(s, d.Pages, "the Gram demonstration",
		"demo", ""); serr != nil {
		return serr
	}

	// Records, written into the draft's tree.
	for name, recs := range d.Records {
		c, cerr := s.GetCommit(s.GetRef(site.RefDraft))
		if cerr != nil {
			return cerr
		}
		next, _, perr := collection.PutMany(s, c.Tree, name, recs, time.Now())
		if perr != nil {
			return fmt.Errorf("collection %s: %w", name, perr)
		}
		if cerr := commitTreeNoLock(s, next, "records for "+name,
			"demo"); cerr != nil {
			return cerr
		}
	}

	// Everything that lives beside the store rather than in it.
	set := &listing.Set{}
	for _, l := range d.Listings {
		if aerr := set.Add(l); aerr != nil {
			return fmt.Errorf("listing %s: %w", l.Name, aerr)
		}
	}
	if werr := saveJSON(listingPath(root), set); werr != nil {
		return werr
	}
	if werr := saveJSON(menuPath(root), d.Menus); werr != nil {
		return werr
	}
	if werr := saveJSON(vocabPath(root), d.Vocabularies); werr != nil {
		return werr
	}
	forms := &form.Set{}
	for _, f := range d.Forms {
		if aerr := forms.Add(f); aerr != nil {
			return fmt.Errorf("form %s: %w", f.Name, aerr)
		}
	}
	if werr := saveJSON(formsPath(root), forms); werr != nil {
		return werr
	}

	// The name, in configuration rather than a flag, so the accessibility gate
	// and the exports render the same page the server does.
	if cfg, cerr := loadConfig(root); cerr == nil {
		if serr := cfg.Set("site.name", d.Name, "the demonstration site",
			"demo"); serr == nil {
			_ = saveConfig(root, cfg)
		}
	}

	// The template and the stylesheet, beside the store where `scrivet site`
	// looks for them.
	if merr := os.MkdirAll(*tplDir, 0o700); merr != nil {
		return merr
	}
	for path, body := range map[string]string{
		filepath.Join(*tplDir, "page.html"): d.Template,
		filepath.Join(*tplDir, "site.css"):  d.CSS,
	} {
		if werr := os.WriteFile(path, []byte(body), 0o600); werr != nil {
			return werr
		}
	}

	if *publish {
		if _, perr := site.Publish(s, ""); perr != nil {
			return fmt.Errorf("publishing: %w", perr)
		}
	}

	// In the log, because this writes more of a store in one command than
	// anything else here does. Somebody reading the history later should not
	// have to infer a whole application from a scatter of commits.
	record(root, resolveCaller(root, "").auditRecord("demo.install", "/",
		audit.Success, map[string]string{
			"pages":     fmt.Sprint(len(d.Pages)),
			"records":   fmt.Sprint(len(d.Records["posts"])),
			"media":     fmt.Sprint(len(d.Media)),
			"published": fmt.Sprint(*publish),
		}))

	w.Human("%sGram is installed.%s %s\n\n", bold, reset, d.Summary)
	w.Human("  %d page(s), %d record(s), %d image(s), %d listing(s), %d form(s)\n",
		len(d.Pages), len(d.Records["posts"]), len(d.Media), len(d.Listings),
		len(d.Forms))
	w.Human("\n  %sto look at it%s\n", bold, reset)
	w.Human("    scrivet site  --addr 127.0.0.1:8081   %sthe site%s\n", dim, reset)
	w.Human("    scrivet serve --addr 127.0.0.1:8080   %sthe admin%s\n", dim, reset)
	w.Human("\n  %sthings worth trying%s\n", bold, reset)
	w.Human("    /explore?topic=travel   %sa listing with a parameter%s\n", dim, reset)
	w.Human("    /stories/sol-rooftop    %s404s until September: its window "+
		"has not opened%s\n", dim, reset)
	w.Human("    /messages               %sthe one thing the public server "+
		"may write%s\n", dim, reset)
	return nil
}
