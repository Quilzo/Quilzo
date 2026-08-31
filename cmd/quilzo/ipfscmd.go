package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/ipfs"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/site"
)

// Computing what the permanent web will call your site.
//
// The same operation the admin screen performs, on the surface where somebody
// can pipe it into something else. `--json` gives a machine the root identifier
// and every file's, which is what a deployment pipeline wants: build, compute,
// upload, compare.

func cmdIPFS(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"id"}
	}
	switch args[0] {
	case "id":
		return ipfsID(root, args[1:])
	case "write":
		return ipfsWrite(root, args[1:])
	case "verify":
		return ipfsVerify(root, args[1:])
	default:
		return fmt.Errorf("unknown ipfs command %q; try id, write or verify",
			args[0])
	}
}

// ipfsID prints the identifier the published site would have.
func ipfsID(root string, args []string) error {
	fs := flag.NewFlagSet("id", flag.ContinueOnError)
	tplDir := fs.String("templates", "templates", "where page.html lives")
	if err := fs.Parse(args); err != nil {
		return err
	}
	files, err := renderBundle(root, *tplDir)
	if err != nil {
		return err
	}
	node, err := ipfs.Tree(files)
	if err != nil {
		return err
	}

	if w.Mode == out.JSON {
		per := map[string]string{}
		for path, body := range files {
			per[path] = ipfs.File(body).Block.CID
		}
		w.JSON(map[string]any{
			"root": node.Block.CID, "files": per, "blocks": len(node.All()),
		})
		return nil
	}

	w.Human("%s%s%s\n", bold, node.Block.CID, reset)
	w.Human("  %s%d file(s), %d block(s)%s\n", dim, len(files), len(node.All()), reset)
	w.Human("  %scomputed here, from your bytes, with nothing asked of anybody%s\n",
		dim, reset)
	w.Human("\n  %sipfs://%s%s\n", dim, node.Block.CID, reset)
	w.Human("  %sset that as your ENS contenthash and readers reach it at%s\n",
		dim, reset)
	w.Human("  %syourname.eth.limo%s\n", dim, reset)
	return nil
}

// ipfsWrite renders the site to a directory, ready for `ipfs add -r`.
func ipfsWrite(root string, args []string) error {
	fs := flag.NewFlagSet("write", flag.ContinueOnError)
	tplDir := fs.String("templates", "templates", "where page.html lives")
	dir := fs.String("o", "site", "write the rendered site here")
	basePath := fs.String("base-path", "",
		"serve the bundle from this subdirectory, e.g. /demo2")
	if err := fs.Parse(args); err != nil {
		return err
	}
	files, err := renderBundle(root, *tplDir)
	if err != nil {
		return err
	}
	// Under a subdirectory, if that is where it will live.
	//
	// Every link a page carries is rooted, so a bundle copied into /demo2 has
	// working pages and a broken site: the navigation, the pictures and the
	// stylesheet all resolve one level too high. There was no option for it,
	// and the alternative was a hand-written sed over the output.
	files = render.Rebase(files, *basePath)
	node, err := ipfs.Tree(files)
	if err != nil {
		return err
	}

	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		// Cleaned and joined, then checked to still be inside the output
		// directory. Page names are validated on write, so this cannot
		// currently escape — and "cannot currently" is exactly the phrase that
		// stops being true after somebody relaxes a rule somewhere else.
		full := filepath.Join(*dir, filepath.FromSlash(path))
		if rel, rerr := filepath.Rel(*dir, full); rerr != nil ||
			filepath.IsAbs(rel) || len(rel) > 1 && rel[:2] == ".." {
			return fmt.Errorf("%q would be written outside %s", path, *dir)
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, files[path], 0o644); err != nil {
			return err
		}
	}

	record(root, resolveCaller(root, "").auditRecord("ipfs.write", "/",
		audit.Success, map[string]string{
			"cid": node.Block.CID, "files": fmt.Sprintf("%d", len(files))}))

	if w.JSON(map[string]any{"root": node.Block.CID, "dir": *dir,
		"files": len(files)}) {
		return nil
	}
	w.Human("wrote %d file(s) to %s%s%s\n", len(files), bold, *dir, reset)
	w.Human("\n  %sipfs add -r --cid-version=1 %s%s\n", dim, *dir, reset)
	w.Human("  %smust print:%s %s%s%s\n", dim, reset, bold, node.Block.CID, reset)
	w.Human("\n  %sif it prints anything else, something changed the bytes "+
		"between here%s\n", dim, reset)
	w.Human("  %sand there, and that is worth finding out before you pin it%s\n",
		dim, reset)
	return nil
}

// ipfsVerify checks an identifier a service handed back.
func ipfsVerify(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	tplDir := fs.String("templates", "templates", "where page.html lives")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo ipfs verify <cid>")
	}
	claimed := pos[0]

	if err := ipfs.Valid(claimed); err != nil {
		return errBlocked{err}
	}
	files, err := renderBundle(root, *tplDir)
	if err != nil {
		return err
	}
	node, err := ipfs.Tree(files)
	if err != nil {
		return err
	}

	match := claimed == node.Block.CID
	if w.Mode == out.JSON {
		w.JSON(map[string]any{
			"claimed": claimed, "computed": node.Block.CID, "match": match})
		if !match {
			return errBlocked{fmt.Errorf("the identifier does not match this content")}
		}
		return nil
	}
	if match {
		w.Human("%smatches%s\n", green, reset)
		w.Human("  %sthe service stored what you gave it%s\n", dim, reset)
		return nil
	}
	w.Human("%sdoes not match%s\n", red, reset)
	w.Human("  claimed  %s\n", claimed)
	w.Human("  computed %s\n", node.Block.CID)
	w.Human("\n  %sthe claimed identifier is well formed and is not this "+
		"content. Either%s\n", dim, reset)
	w.Human("  %sthe upload was altered, the service re-chunked it, or you are%s\n",
		dim, reset)
	w.Human("  %scomparing against a different build%s\n", dim, reset)
	return errBlocked{fmt.Errorf("the identifier does not match this content")}
}

// renderBundle produces the published site as path-to-bytes.
//
// What is live, never the draft. A draft on permanent storage is an unfinished
// page nobody can withdraw, and that is the one mistake this medium does not
// allow anybody to take back.
func renderBundle(root, tplDir string) (map[string][]byte, error) {
	s, err := open(root)
	if err != nil {
		return nil, err
	}
	if s.GetRef(site.RefLive) == "" {
		return nil, fmt.Errorf(
			"nothing is published. This takes what is live, not what is in " +
				"the draft")
	}
	design, err := loadDesign(tplDir)
	if err != nil {
		return nil, err
	}

	// The same site the server serves, built by the same function, and asked
	// for its own pages.
	//
	// This used to call render.Bundle directly, which renders pages and nothing
	// else — so every static copy went out without the sitemap, robots.txt, the
	// crawl licence, the manifest, the service worker, the structured data on
	// each page or the provenance marking. Six routes and a legal disclosure,
	// missing from the copy people archive, because the bundle was a second
	// idea of what a site is. See internal/public/bundle.go.
	//
	// No base URL passed: siteFor reads site.base_url, because an absolute URL
	// in a sitemap has to be where the site actually lives and a bundle is
	// written long before anybody types a flag.
	st, serr := siteFor(root, design, siteOpts{})
	if serr != nil {
		return nil, serr
	}
	files, berr := st.Bundle()
	if berr != nil {
		return nil, berr
	}

	for _, face := range design.Fonts.Faces() {
		files["fonts/"+face.File] = face.Bytes
	}
	// The asset library, under the same paths the public server uses, so a
	// page's image reference resolves identically in a copy.
	if lib, lerr := openMedia(root); lerr == nil {
		if all, aerr := lib.List(); aerr == nil {
			exts := map[string]string{}
			for _, f := range all {
				_, body, gerr := lib.Get(f.ID)
				if gerr != nil {
					continue
				}
				files["media/"+f.ID] = body
				exts[f.ID] = f.Extension()
			}
			// Named by format, because a static host reads the type from the
			// name. Under a bare hash every asset is served as
			// application/octet-stream, and a host that sends nosniff — GitHub
			// Pages does — refuses to render the picture and refuses to play
			// the film. The server has the format table and does not need this.
			files = render.Named(files, exts)
		}
	}
	return files, nil
}
