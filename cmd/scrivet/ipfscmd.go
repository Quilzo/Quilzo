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
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/tmpl"
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
		return fmt.Errorf("usage: scrivet ipfs verify <cid>")
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
	raw, err := os.ReadFile(filepath.Join(tplDir, "page.html"))
	if err != nil {
		return nil, fmt.Errorf("no template at %s: %w",
			filepath.Join(tplDir, "page.html"), err)
	}
	pages, err := site.PagesAt(s, site.RefLive)
	if err != nil {
		return nil, err
	}

	// The same context the site serves. A bundle pinned to IPFS is the copy
	// somebody keeps, and it used to come out with no navigation on any page.
	src := sourcesFor(root, s, s.GetRef(site.RefLive), siteName(root), pages)

	files := map[string][]byte{}
	for name, body := range pages {
		ctx, cerr := src.For(name, body, nil)
		if cerr != nil {
			return nil, fmt.Errorf("%s: %w", name, cerr)
		}
		html, rerr := tmpl.Render(string(raw), ctx)
		if rerr != nil {
			return nil, fmt.Errorf("%s: %w", name, rerr)
		}
		path := name + "/index.html"
		if name == "index" {
			path = "index.html"
		}
		files[path] = []byte(html)
	}
	if css, cerr := os.ReadFile(filepath.Join(tplDir, "site.css")); cerr == nil {
		files["site.css"] = css
	}
	// The asset library, under the same paths the public server uses, so a
	// page's image reference resolves identically on IPFS.
	if lib, lerr := openMedia(root); lerr == nil {
		if all, aerr := lib.List(); aerr == nil {
			for _, f := range all {
				_, body, gerr := lib.Get(f.ID)
				if gerr != nil {
					continue
				}
				files["media/"+f.ID] = body
			}
		}
	}
	return files, nil
}
