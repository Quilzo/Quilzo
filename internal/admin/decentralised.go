package admin

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/ipfs"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// Publishing somewhere nobody can take it down.
//
// # What this does and, more importantly, what it refuses to do
//
// It renders the published site, computes the IPFS identifier for it locally,
// and hands you a bundle to upload. It does not hold your credentials, does not
// hold a wallet, does not sign a transaction and does not talk to a pinning
// service on your behalf.
//
// That is a deliberate design, not an unfinished one. The moment this program
// stores a pinning token it becomes a thing worth attacking for a reason
// unrelated to content, and the moment it holds a key it becomes a custodian.
// Neither is necessary: the useful, hard part is knowing what the identifier
// *should* be, and that is computed from your bytes with no third party in it.
//
// # Why computing it locally is the whole point
//
// Upload a site to a pinning service and it returns an identifier. Use that
// identifier and the service is the authority on what your content is — it can
// return one for something else, by bug or by compromise, and nothing
// downstream would notice because the only copy of the answer came from the
// party being checked.
//
// Here the answer is computed first. Whatever the service says is compared
// against it, and a mismatch is a refusal with both values shown. This is the
// same argument the store rests on: the name of a thing is a fact about its
// bytes.
//
// # What "cannot be taken down" honestly means
//
// It means we are not hosting it, so we cannot remove it, and neither can a
// court order served on us. It does not mean unreachable-by-anybody: readers
// arrive through gateways, gateways run on DNS, and in 2026 the main ENS
// gateway was hijacked through its registrar, seized by a previous registrar,
// and blocked by at least one large ISP. The content survived all three. The
// path to it did not.
//
// The documentation says this plainly rather than selling the stronger claim.

// Decentralised gives the admin what it needs to render the whole site.
type Decentralised struct {
	// Pages is the published page set. Nil means the screen explains that
	// nothing is published rather than offering to publish nothing.
	Pages func() (map[string]any, error)
	// Stylesheet is served at /site.css by the public server, so it belongs in
	// the bundle. Empty is fine.
	Stylesheet func() string
	// Media returns the asset library as path-to-bytes, under media/.
	Media func() (map[string][]byte, error)
}

// MaxBundlePages bounds a render.
//
// Rendering every page and hashing the result is proportional to the site, and
// a request that does that without a limit is a way to make this process spend
// a minute on one click. Sites larger than this belong on the command line,
// where nobody is waiting on an HTTP response.
const MaxBundlePages = 2000

func (s *Server) handleDecentralised(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}

	data := map[string]any{
		"Nav": "decentralised", "Title": "Permanent web", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"Claimed":  r.URL.Query().Get("claimed"),
		"CanBuild": s.Policy.Evaluate(p.Name, auth.ActPublish, "/").Allowed,
	}

	bundle, err := s.bundle()
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, "decentralised.html", data)
		return
	}

	root, err := ipfs.Tree(bundle)
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, "decentralised.html", data)
		return
	}

	// Per-file identifiers, so somebody can check one page rather than the
	// whole site. A file's identifier is the hash of its bytes and nothing
	// else, so this is also the cheapest possible integrity check.
	type row struct {
		Path, CID string
		Size      int
	}
	var rows []row
	var total int
	for path, body := range bundle {
		rows = append(rows, row{path, ipfs.File(body).Block.CID, len(body)})
		total += len(body)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Path < rows[j].Path })

	data["Root"] = root.Block.CID
	data["Blocks"] = len(root.All())
	data["Files"] = rows
	data["Total"] = total

	// If they pasted what a service told them, answer the only question that
	// matters about it.
	if claimed := strings.TrimSpace(r.URL.Query().Get("claimed")); claimed != "" {
		switch {
		case ipfs.Valid(claimed) != nil:
			data["Verdict"], data["VerdictKind"] =
				ipfs.Valid(claimed).Error(), "bad"
		case claimed == root.Block.CID:
			data["Verdict"], data["VerdictKind"] =
				"That is the identifier this content has. The service stored "+
					"what you gave it.", "ok"
		default:
			data["Verdict"], data["VerdictKind"] =
				"That is a valid identifier and it is not this content. "+
					"Either the upload was altered, the service re-chunked it, "+
					"or you are looking at a different build.", "bad"
		}
	}

	s.render(w, r, "decentralised.html", data)
}

// handleBundle sends the rendered site as a tar.gz.
//
// A tar rather than an archive nobody can open without this program, and
// gzip because both are in the standard library. The customer expands it and
// runs one command:
//
//	ipfs add -r --cid-version=1 site/
//
// which must print the identifier this screen showed. If it prints a different
// one, something between here and there changed the bytes.
func (s *Server) handleBundleDownload(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActPublish, "/") {
		return
	}
	bundle, err := s.bundle()
	if err != nil {
		s.decRedirect(w, r, "", err.Error())
		return
	}
	root, err := ipfs.Tree(bundle)
	if err != nil {
		s.decRedirect(w, r, "", err.Error())
		return
	}

	paths := make([]string, 0, len(bundle))
	for path := range bundle {
		paths = append(paths, path)
	}
	// Sorted, so the archive is byte-identical for identical content. An
	// archive whose bytes depend on map order cannot be compared between two
	// runs, which is half the point of having one.
	sort.Strings(paths)

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="site-%s.tar.gz"`, root.Block.CID[:16]))
	// The identifier in a header as well as on the screen, so a scripted
	// download can check it without scraping HTML.
	w.Header().Set("X-Content-Id", root.Block.CID)

	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	for _, path := range paths {
		body := bundle[path]
		// Timestamps and ownership are deliberately zero. A reproducible
		// archive cannot carry the moment it was made, and none of it affects
		// the IPFS identifier anyway — which is computed from the file bytes,
		// not from tar metadata.
		if err := tw.WriteHeader(&tar.Header{
			Name: "site/" + path, Mode: 0o644, Size: int64(len(body)),
			Format: tar.FormatUSTAR,
		}); err != nil {
			return
		}
		if _, err := tw.Write(body); err != nil {
			return
		}
	}
	s.auditPub(p, "ipfs.bundle", "/", map[string]string{
		"cid": root.Block.CID, "files": fmt.Sprint(len(paths))})
}

// handleVerifyCID checks what a service claimed.
func (s *Server) handleVerifyCID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/decentralised?claimed="+
		url.QueryEscape(strings.TrimSpace(r.FormValue("cid"))),
		http.StatusSeeOther)
}

// bundle renders the published site to a path-to-bytes map.
//
// The published site, not the draft. Putting a draft on permanent storage would
// make an unfinished page permanent, which is the one mistake this medium does
// not let anybody take back.
func (s *Server) bundle() (map[string][]byte, error) {
	if s.Decentralised == nil || s.Decentralised.Pages == nil {
		return nil, fmt.Errorf(
			"this build has no access to the published site, so it cannot " +
				"compute an identifier for one")
	}
	if s.Store.GetRef(site.RefLive) == "" {
		return nil, fmt.Errorf(
			"nothing is published. Permanent storage takes what is live, not " +
				"what is in the draft — a draft made permanent is an " +
				"unfinished page nobody can withdraw")
	}
	if s.Template == "" {
		return nil, fmt.Errorf(
			"there is no page template, so the site cannot be rendered")
	}

	pages, err := s.Decentralised.Pages()
	if err != nil {
		return nil, err
	}
	if len(pages) > MaxBundlePages {
		return nil, fmt.Errorf(
			"%d pages is more than this screen renders in one request; use "+
				"`quilzo ipfs` from a terminal, where nothing is waiting on a "+
				"response", len(pages))
	}

	// The same context the public server uses. A bundle is somebody's durable
	// copy of their site — pinned, handed over, served from a gateway — and it
	// used to come out with no navigation on any page.
	src := s.sources(s.Store.GetRef(site.RefLive), pages)

	out := map[string][]byte{}
	for name, body := range pages {
		ctx, cerr := src.For(name, body, nil)
		if cerr != nil {
			return nil, fmt.Errorf("%s: %w", name, cerr)
		}
		html, err := tmpl.Render(s.Template, ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		// index becomes index.html at the root; everything else becomes a
		// directory with an index.html in it, so a gateway serves clean paths.
		path := name + "/index.html"
		if name == "index" {
			path = "index.html"
		}
		out[path] = []byte(html)
	}
	if s.Decentralised.Stylesheet != nil {
		if css := s.Decentralised.Stylesheet(); css != "" {
			out["site.css"] = []byte(css)
		}
	}
	if s.Decentralised.Media != nil {
		assets, err := s.Decentralised.Media()
		if err != nil {
			return nil, err
		}
		for path, body := range assets {
			out[path] = body
		}
	}
	return out, nil
}

func (s *Server) decRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/decentralised"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}
