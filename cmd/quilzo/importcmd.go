package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/importer"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/seo"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
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
		return fmt.Errorf("usage: quilzo import <export-file> [--from wordpress]")
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

	// A collections file is its own thing: it carries records, not pages, and
	// it goes into the collection it names rather than through the page
	// pipeline. Handled before the page path so a catalogue is never written
	// as two pages called "collection" and "records".
	if rep.Collection != "" {
		return importRecords(root, s, rep, *author)
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
		w.Human("  %sserve them: quilzo site --redirects %s%s\n",
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
	case "list":
		return mediaList(root)
	case "remove":
		return mediaRemove(root, args[1:])
	case "formats":
		return mediaFormats()
	default:
		return fmt.Errorf("unknown media command %q; try add, get, list, "+
			"remove or formats", args[0])
	}
}

// mediaRemove takes a file out of the library.
//
// The admin has had this button since the library existed and the command line
// had nothing: files could be added from three interfaces and removed from one,
// so an operator working in a terminal had no way to undo an upload. The
// library's own Remove is what the button calls; this calls the same function.
//
// A file the live site uses is refused unless somebody says otherwise. The
// library's comment argues that a 404 is better than an image that silently
// changed, and that is right about the storage layer — but a command that
// quietly breaks a published page is not the same thing as a visible failure,
// and the check is cheap because `quilzo rights` already walks the content for
// image references.
func mediaRemove(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	force := fs.Bool("force", false,
		"remove it even though a published page uses it")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo media remove <id> [--force]")
	}
	id := pos[0]

	lib, err := openMedia(root)
	if err != nil {
		return fmt.Errorf("the media library could not be opened: %w", err)
	}
	f, err := lib.Stat(id)
	if err != nil {
		return err
	}

	if !*force {
		if used, uerr := mediaInUse(root, id); uerr == nil && used {
			return errBlocked{fmt.Errorf(
				"%s is used by the live site. Removing it would leave a "+
					"published page pointing at a 404.\n"+
					"  Publish a page that does not use it, or pass --force",
				short(id))}
		}
	}

	if err := lib.Remove(id); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("media.remove", "/",
		audit.Success, map[string]string{"id": short(id), "file": f.Name}))
	if w.JSON(map[string]any{"removed": id, "name": f.Name}) {
		return nil
	}
	w.Human("removed %s%s%s\n", bold, f.Name, reset)
	w.Human("  %sanything still pointing at it now gets a 404, which is "+
		"visible%s\n", dim, reset)
	return nil
}

// mediaInUse reports whether the live content references an asset.
//
// Built on the same walk `quilzo rights` uses, so "in use" means here exactly
// what it means there.
func mediaInUse(root, id string) (bool, error) {
	s, err := open(root)
	if err != nil {
		return false, err
	}
	lib, err := openMedia(root)
	if err != nil {
		return false, err
	}
	uses, err := assetUses(s, lib, site.RefLive)
	if err != nil {
		return false, err
	}
	_, used := uses[id]
	return used, nil
}

// mediaList prints what the library holds.
//
// There was no way to ask. Files went in and the id came back once, on the
// terminal that put them there; a week later the only route to the path a page
// needs was reading the store by hand. The assistant interface could already
// list them, which made the gap plainer rather than smaller.
//
// The path comes first on each line, because that is the part being copied.
func mediaList(root string) error {
	lib, err := openMedia(root)
	if err != nil {
		return fmt.Errorf("the media library could not be opened: %w", err)
	}
	files, err := lib.List()
	if err != nil {
		return err
	}
	if w.JSON(files) {
		return nil
	}
	if len(files) == 0 {
		w.Human("nothing has been uploaded\n")
		w.Human("  %squilzo media add photo.png --alt \"...\"%s\n", dim, reset)
		return nil
	}
	for _, f := range files {
		w.Human("/media/%s%s%s\n", bold, f.ID, reset)
		w.Human("  %s%s · %s · %d bytes", dim, f.Name, f.Format, f.Size)
		if f.Width > 0 {
			w.Human(" · %dx%d", f.Width, f.Height)
		}
		w.Human("%s\n", reset)
		if f.Alt != "" {
			w.Human("  %s%s%s\n", dim, f.Alt, reset)
		}
		if f.Kind == media.Image && f.Alt == "" {
			// Not a refusal: it is already stored. But a picture with no
			// description fails the accessibility gate at publish, and finding
			// that out here is cheaper than finding it out then.
			w.Human("  %sno description; a page using this will not publish%s\n",
				dim, reset)
		}
	}
	return nil
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
		return fmt.Errorf("usage: quilzo media add <file> [--alt \"...\"]")
	}

	body, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	f, err := media.Accept(pos[0], body, time.Now())
	if err != nil {
		return errBlocked{err}
	}

	// Optimised after acceptance, never before. Accept decodes the file to
	// prove it is what it claims to be, and optimising first would mean
	// re-encoding bytes nothing had validated — handing the optimiser the
	// polyglot the format check exists to catch.
	if f.Kind == media.Image {
		cfg, cerr := loadConfig(root)
		if cerr != nil {
			return cerr
		}
		opt, oerr := media.Optimise(f.Format, body, media.Options{
			MaxWidth:    cfg.Int("media.max_width"),
			MaxHeight:   cfg.Int("media.max_height"),
			JPEGQuality: cfg.Int("media.jpeg_quality"),
			WebP:        cfg.Bool("media.webp"),
		})
		if oerr != nil {
			// Reported, not fatal. The file has already been proved to be a
			// valid image; failing the upload because the optimiser could not
			// improve it would refuse something acceptable.
			fmt.Fprintf(os.Stderr, "  %snot optimised: %v%s\n", dim, oerr, reset)
		} else if len(opt.Did) > 0 {
			body = opt.Body
			for _, did := range opt.Did {
				fmt.Fprintf(os.Stderr, "  %s%s%s\n", dim, did, reset)
			}
			if opt.StrippedMetadata {
				fmt.Fprintf(os.Stderr, "  %sthe original carried metadata — a "+
					"photograph from a phone usually holds GPS coordinates%s\n",
					yellow, reset)
			}
			// Re-accepted so the stored id is the hash of what is actually
			// stored. Skipping this would file the optimised bytes under the
			// original's hash, and every integrity check downstream would be
			// verifying a claim about a file that no longer exists.
			f, err = media.Accept(pos[0], body, time.Now())
			if err != nil {
				return fmt.Errorf("the optimised image no longer validates, "+
					"so it has not been stored: %w", err)
			}
		}
		if len(body) > media.SingleFileWarn {
			fmt.Fprintf(os.Stderr, "  %sthis one file is %d KB; a page carrying "+
				"a few of these will be slow on a phone%s\n",
				yellow, len(body)/1024, reset)
		}
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

	// Stored, which it was not.
	//
	// This command validated the bytes, wrote an audit record saying the upload
	// had succeeded, printed "accepted", and then dropped the file. Nothing was
	// ever in the library, so nothing was ever served — and the audit log said
	// otherwise, which is worse than the missing feature.
	//
	// internal/medialib exists precisely for this and its own package comment
	// says so: "stores accepted uploads, which nothing did". It was written and
	// the command was never wired to it. Found by adding three images for a
	// demonstration and finding an empty picker.
	lib, err := openMedia(root)
	if err != nil {
		return fmt.Errorf("the media library could not be opened: %w", err)
	}
	if err := lib.Put(f, body); err != nil {
		return fmt.Errorf("%s was accepted and could not be stored: %w", f.Name, err)
	}

	if w.JSON(f) {
		return nil
	}
	// An accepted upload is a file this site will serve to the public.
	record(root, resolveCaller(root, "").auditRecord("media.add", "/",
		audit.Success, map[string]string{"file": f.Name, "id": short(f.ID),
			"format": string(f.Format)}))
	w.Human("stored %s%s%s\n", bold, f.Name, reset)
	w.Human("  %s%s · %s · %d bytes", dim, f.Format, f.Kind, f.Size)
	if f.Width > 0 {
		w.Human(" · %dx%d", f.Width, f.Height)
	}
	w.Human("%s\n", reset)
	// The whole id, and the path a page actually asks for.
	//
	// This printed f.ID[:32] — half of it. The id is the only thing anybody
	// wants from this command, and a truncated one put into a page 404s, so
	// what it printed was a value that looked usable and was not. Found by
	// building a demo page from the output and getting four grey boxes.
	w.Human("  %sid %s%s\n", dim, f.ID, reset)
	w.Human("  %sin a page: /media/%s%s\n", dim, f.ID, reset)
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
		return fmt.Errorf("usage: quilzo media get <https://...> [--alt \"...\"]")
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

	// The same hole as `media add` had: fetched, validated, announced, dropped.
	lib, err := openMedia(root)
	if err != nil {
		return fmt.Errorf("the media library could not be opened: %w", err)
	}
	if err := lib.Put(f, res.Body); err != nil {
		return fmt.Errorf("%s was fetched and could not be stored: %w", pos[0], err)
	}

	if w.JSON(f) {
		return nil
	}
	record(root, resolveCaller(root, "").auditRecord("media.get", "/",
		audit.Success, map[string]string{"file": f.Name, "id": short(f.ID),
			"format": string(f.Format), "source": f.Source}))
	w.Human("fetched and stored %s%s%s\n", bold, f.Name, reset)
	w.Human("  %sfrom %s%s\n", dim, res.FinalURL, reset)
	w.Human("  %s%s · %d bytes%s\n", dim, f.Format, f.Size, reset)
	w.Human("  %sid %s%s\n", dim, f.ID, reset)
	w.Human("  %sin a page: /media/%s%s\n", dim, f.ID, reset)
	return nil
}

// importRecords writes an imported collection back into the store.
//
// The records keep the ids the export gave them. Fresh ids would make every
// record a different record from the one anything else links to, and the
// broken relations are found by a reader rather than by this command.
func importRecords(root string, s *store.Store, rep *importer.Report,
	author string) error {

	tree, err := draftTree(s)
	if err != nil {
		return err
	}

	// Refuse to overwrite, exactly as the page path does. An import that
	// silently replaced a record somebody edited is the worst way to discover
	// the ids collided.
	var clashes []string
	for _, r := range rep.Records {
		if _, err := collection.Get(s, tree, rep.Collection, r.ID); err == nil {
			clashes = append(clashes, r.ID)
		}
	}
	if len(clashes) > 0 {
		shown := clashes
		if len(shown) > 5 {
			shown = shown[:5]
		}
		return errBlocked{fmt.Errorf(
			"%d record(s) already exist in %s and would be replaced: %s",
			len(clashes), rep.Collection, strings.Join(shown, ", "))}
	}

	recs := make([]collection.Record, 0, len(rep.Records))
	for _, r := range rep.Records {
		recs = append(recs, collection.Record{
			ID: r.ID, Fields: r.Fields, Created: r.Created, Updated: r.Updated,
		})
	}
	// RestoreMany, not PutMany: the dates the export carried are real
	// information and no destination can reconstruct them. A catalogue that
	// arrives with every item created at import time sorts wrongly from its
	// first day.
	next, written, err := collection.RestoreMany(s, tree, rep.Collection, recs,
		time.Now())
	if err != nil {
		return err
	}
	message := fmt.Sprintf("import %d record(s) into %s",
		len(written), rep.Collection)
	if err := commitTree(root, s, next, message, author); err != nil {
		return err
	}
	cid := s.GetRef(site.RefDraft)

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "import", Resource: "/" + rep.Collection, Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"source": string(rep.Source), "collection": rep.Collection,
			"records": fmt.Sprintf("%d", len(written)),
			"skipped": fmt.Sprintf("%d", len(rep.Skipped)),
			"commit":  short(cid), "author": author,
		},
	})

	if w.JSON(map[string]any{
		"collection": rep.Collection, "records": len(written),
		"skipped": rep.Skipped, "commit": cid,
	}) {
		return nil
	}
	w.Human("\n%s%d record(s)%s into %s%s%s\n",
		bold, len(written), reset, bold, rep.Collection, reset)
	w.Human("\n  draft %s\n", short(cid))
	return nil
}
