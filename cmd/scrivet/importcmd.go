package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/fetch"
	"github.com/rsh1k/scrivet/internal/importer"
	"github.com/rsh1k/scrivet/internal/media"
	"github.com/rsh1k/scrivet/internal/out"
	"github.com/rsh1k/scrivet/internal/seo"
	"github.com/rsh1k/scrivet/internal/site"
)

func cmdImport(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	from := fs.String("from", "", "wordpress, markdown or json (detected if omitted)")
	dryRun := fs.Bool("dry-run", false, "report what would happen and write nothing")
	prefix := fs.String("prefix", "", "prepend this to every imported page name")
	author := fs.String("author", "import", "who to record as the author")
	redirectsOut := fs.String("redirects-out", "redirects.json",
		"where to write the generated redirect map")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: scrivet import <export-file> [--from wordpress]")
	}

	body, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	src := importer.Source(*from)
	if src == "" {
		detected, ok := importer.Detect(body)
		if !ok {
			return fmt.Errorf("cannot tell what %s is; pass --from wordpress, "+
				"markdown or json", pos[0])
		}
		src = detected
		w.Human("%sdetected %s%s\n", dim, src, reset)
	}

	rep, err := importer.Import(src, strings.NewReader(string(body)), time.Now())
	if err != nil {
		return err
	}

	if w.Mode == out.JSON {
		w.JSON(rep)
		if *dryRun {
			return nil
		}
	} else {
		w.Human("\n%s%d page(s)%s from %s\n", bold, len(rep.Pages), reset, src)
		for _, p := range rep.Pages {
			w.Human("  %s\n", *prefix+p.Name)
			for _, d := range p.Dropped {
				w.Human("    %s- %s%s\n", dim, d, reset)
			}
		}
		// What was not imported, always. An importer that quietly drops half an
		// export is worse than one that refuses, because the loss is found
		// months later by a reader.
		if len(rep.Skipped) > 0 {
			w.Human("\n  %snot imported:%s\n", yellow, reset)
			for _, s := range rep.Skipped {
				w.Human("    %s%s%s\n", dim, s, reset)
			}
		}
		for _, n := range rep.Notes {
			w.Human("\n  %s%s%s\n", yellow, wrapIndent(n, 70, 4), reset)
		}
	}

	if *dryRun {
		w.Human("\n  %snothing written (--dry-run)%s\n", dim, reset)
		return nil
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	base := s.GetRef(site.RefDraft)
	pages := map[string]any{}
	if base != "" {
		if existing, err := site.PagesAt(s, base); err == nil {
			pages = existing
		}
	}

	// Refuse to overwrite. An import that silently replaces a page somebody
	// wrote is the worst possible way to find out the names collided.
	var clashes []string
	for _, p := range rep.Pages {
		name := *prefix + p.Name
		if _, exists := pages[name]; exists {
			clashes = append(clashes, name)
		}
	}
	if len(clashes) > 0 {
		return errBlocked{fmt.Errorf(
			"%d page(s) already exist and would be replaced: %s\n"+
				"  use --prefix to import them alongside",
			len(clashes), strings.Join(clashes, ", "))}
	}

	for _, p := range rep.Pages {
		pages[*prefix+p.Name] = p.Fields
	}

	// The same gate every other write goes through. Imported content is content
	// from a system somebody else administered, which makes it the least
	// trustworthy input this program accepts.
	types, err := gateWrite(root, pages)
	if err != nil {
		return err
	}
	cid, err := site.SaveDraftFrom(s, pages,
		fmt.Sprintf("import %d page(s) from %s", len(rep.Pages), src), *author, base)
	if err != nil {
		var imported []string
		for _, pg := range rep.Pages {
			imported = append(imported, *prefix+pg.Name)
		}
		return conflictError(err, imported)
	}
	if err := types.Save(); err != nil {
		return err
	}

	// The caller's real identity and its real verification state. The first
	// version recorded this as a verified service principal, which the audit
	// package refused outright — a service is only a service because a
	// credential proved it. The record was silently dropped, leaving the least
	// trustworthy operation in the system as the one with no log entry.
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "import", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"source": string(src), "pages": fmt.Sprintf("%d", len(rep.Pages)),
			"skipped":   fmt.Sprintf("%d", len(rep.Skipped)),
			"redirects": fmt.Sprintf("%d", len(rep.Redirects)),
			"commit":    short(cid), "author": *author,
		},
	})

	// Written, not just described. The report says to serve this file, and a
	// message naming a file the tool did not produce is the kind of instruction
	// people follow once and then stop trusting.
	if len(rep.Redirects) > 0 && *redirectsOut != "" {
		out := struct {
			Redirects []seo.Redirect `json:"redirects"`
		}{rep.Redirects}
		if err := saveJSON(*redirectsOut, out); err != nil {
			return fmt.Errorf("the pages were imported but the redirect map "+
				"could not be written (%w). Links to the old URLs will break "+
				"until it exists", err)
		}
		w.Human("\n  wrote %s%s%s with %d redirect(s)\n",
			bold, *redirectsOut, reset, len(rep.Redirects))
		w.Human("  %sserve them: scrivet site --redirects %s%s\n",
			dim, *redirectsOut, reset)
	}

	w.Human("\n  draft %s\n", short(cid))
	w.Human("  %snothing is public until someone publishes%s\n", dim, reset)
	return nil
}

func cmdMedia(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"formats"}
	}
	switch args[0] {
	case "add":
		return mediaAdd(root, args[1:])
	case "get":
		return mediaGet(root, args[1:])
	case "formats":
		return mediaFormats()
	default:
		return fmt.Errorf("unknown media command %q; try add, get or formats",
			args[0])
	}
}

func mediaFormats() error {
	if w.JSON(map[string]any{"accepted": media.Accepted()}) {
		return nil
	}
	w.Human("%saccepted%s\n  %s\n\n", bold, reset,
		strings.Join(media.Accepted(), ", "))
	w.Human("%srefused, with reasons%s\n", bold, reset)
	for _, ext := range []string{"svg", "html", "js", "php", "zip", "docx", "exe"} {
		w.Human("  %s%-6s%s %s\n", dim, ext, reset,
			wrapIndent(media.WhyRefused(ext), 62, 9))
	}
	w.Human("\n  %severy accepted format is decoded, not sniffed: magic bytes "+
		"are%s\n", dim, reset)
	w.Human("  %sbypassable with a polyglot, so the file has to actually parse%s\n",
		dim, reset)
	return nil
}

func mediaAdd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	alt := fs.String("alt", "", "description, required for images (WCAG 1.1.1)")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: scrivet media add <file> [--alt \"...\"]")
	}

	body, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	f, err := media.Accept(pos[0], body, time.Now())
	if err != nil {
		return errBlocked{err}
	}
	// Alt text is required at the point an image enters, not checked later. A
	// library full of undescribed images is a library somebody has to go back
	// through, and nobody ever does.
	if f.Kind == media.Image && strings.TrimSpace(*alt) == "" {
		return errBlocked{fmt.Errorf(
			"this image needs a description: --alt \"what it shows\"\n" +
				"  Say what the image conveys, not that it is an image. If it is " +
				"purely decorative, pass --alt \"\" explicitly once that is supported")}
	}
	f.Alt = strings.TrimSpace(*alt)

	if w.JSON(f) {
		return nil
	}
	// An accepted upload is a file this site will serve to the public.
	record(root, resolveCaller(root, "").auditRecord("media.add", "/",
		audit.Success, map[string]string{"file": f.Name, "id": short(f.ID),
			"format": string(f.Format)}))
	w.Human("accepted %s%s%s\n", bold, f.Name, reset)
	w.Human("  %s%s · %s · %d bytes", dim, f.Format, f.Kind, f.Size)
	if f.Width > 0 {
		w.Human(" · %dx%d", f.Width, f.Height)
	}
	w.Human("%s\n", reset)
	w.Human("  %sid %s%s\n", dim, f.ID[:32], reset)
	if !f.Inline() {
		w.Human("  %sserved as a download, not rendered in the page's origin%s\n",
			dim, reset)
	}
	return nil
}

func mediaGet(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	alt := fs.String("alt", "", "description, required for images")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: scrivet media get <https://...> [--alt \"...\"]")
	}

	c := fetch.New()
	res, err := c.Get(context.Background(), pos[0])
	if err != nil {
		return errBlocked{err}
	}
	f, err := media.Accept(res.FinalURL, res.Body, time.Now())
	if err != nil {
		return errBlocked{fmt.Errorf("%s was fetched but refused: %w", pos[0], err)}
	}
	if f.Kind == media.Image && strings.TrimSpace(*alt) == "" {
		return errBlocked{fmt.Errorf("this image needs a description: --alt \"...\"")}
	}
	f.Alt = strings.TrimSpace(*alt)
	f.Source = res.FinalURL

	if w.JSON(f) {
		return nil
	}
	record(root, resolveCaller(root, "").auditRecord("media.get", "/",
		audit.Success, map[string]string{"file": f.Name, "id": short(f.ID),
			"format": string(f.Format), "source": f.Source}))
	w.Human("fetched and accepted %s%s%s\n", bold, f.Name, reset)
	w.Human("  %sfrom %s%s\n", dim, res.FinalURL, reset)
	w.Human("  %s%s · %d bytes · id %s%s\n", dim, f.Format, f.Size, f.ID[:32], reset)
	return nil
}
