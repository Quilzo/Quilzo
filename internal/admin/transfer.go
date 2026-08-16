package admin

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lithoform/lithoform/internal/auth"
	"github.com/lithoform/lithoform/internal/export"
	"github.com/lithoform/lithoform/internal/importer"
	"github.com/lithoform/lithoform/internal/site"
	"github.com/lithoform/lithoform/internal/starter"
)

// Getting a site in and out, and starting from something.
//
// Import and export are the two operations that decide whether a CMS is a
// place you can leave. Having them only on the command line makes the answer
// "yes, if you have a shell on the server", which is a different answer.
//
// The import here reports and does not write. What an importer skipped is more
// important than what it took — an importer that quietly drops half an export
// is worse than one that refuses, because the loss is found months later by a
// reader — so the report is a screen somebody reads before deciding.

// Transfer moves whole sites.
type Transfer struct {
	// Pages is the current draft, for an export.
	Pages func() (map[string]any, error)
	// Save writes an accepted import into the draft.
	//
	// base is the commit the pages were read from, so the write is
	// compare-and-swap rather than last-one-wins. Two people importing at the
	// same moment would otherwise lose one of the two imports with no error.
	Save func(pages map[string]any, message, author, base string) error
	// SiteName and BaseURL describe this site, for formats that carry them.
	SiteName, BaseURL string
}

// MaxImport bounds an uploaded export.
//
// Well under internal/importer's own limit, because that one bounds what the
// parser will accept and this one bounds what a browser will send: a WordPress
// export of a large site is tens of megabytes, and a request that streams
// forever is the same denial of service whatever is at the other end.
const MaxImport = 64 << 20

func (s *Server) handleTransfer(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}
	s.render(w, r, "transfer.html", map[string]any{
		"Nav": "transfer", "Title": "Transfer", "Principal": p,
		"Formats": export.Formats(), "Starters": starter.All(),
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"CanWrite": s.Policy.Evaluate(p.Name, auth.ActEditDraft, "/").Allowed,
	})
}

// handleExport writes the site out.
//
// A download rather than a rendered page: the point of an export is a file
// somebody keeps, and a copy that went through a browser's rendering is a copy
// whose bytes nobody can compare.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}
	if s.Transfer == nil || s.Transfer.Pages == nil {
		s.transferRedirect(w, r, "", "export is not wired up in this build")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pages, err := s.Transfer.Pages()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	format := export.Format(r.FormValue("format"))
	files, err := export.Export(format, export.Site{
		Pages: pages, Name: s.Transfer.SiteName, BaseURL: s.Transfer.BaseURL,
	}, time.Now())
	if err != nil {
		s.transferRedirect(w, r, "", err.Error())
		return
	}
	s.auditPub(p, "export", "/", map[string]string{
		"format": string(format), "files": fmt.Sprint(len(files))})

	// One file is served as itself. Several are concatenated with a header per
	// file rather than zipped, because zip means an archive writer and this
	// binary has no dependencies — and a concatenated text export is something
	// a person can read, which an archive is not.
	var buf bytes.Buffer
	if len(files) == 1 {
		buf.Write(files[0].Body)
	} else {
		for _, f := range files {
			fmt.Fprintf(&buf, "===== %s =====\n", f.Path)
			buf.Write(f.Body)
			buf.WriteString("\n\n")
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf(
		`attachment; filename="export-%s.txt"`, format))
	_, _ = w.Write(buf.Bytes())
}

// handleImport reads an export and reports what it found.
//
// By default nothing is written: the report says what would come in, what was
// skipped and why, and which redirects the old URLs need. Writing is a second
// upload with the box ticked.
//
// Two passes over the same file rather than holding the parsed result between
// requests, which was the other option and is worse in both available shapes.
// Keeping it on the server makes the preview stateful, so a second person's
// import can be accepted by the first. Putting it in a hidden field ships an
// entire site through the browser twice and invites somebody to edit it in
// between. Re-reading the file costs a second parse of something that was
// already uploaded once, and the parse is not the expensive part of a
// migration.
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxImport)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		s.transferRedirect(w, r, "", fmt.Sprintf(
			"that file could not be read: %v. The limit is %d MB.",
			err, MaxImport>>20))
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		s.transferRedirect(w, r, "", "no file was attached")
		return
	}
	defer file.Close()
	body, err := io.ReadAll(file)
	if err != nil {
		s.transferRedirect(w, r, "", err.Error())
		return
	}

	src := importer.Source(strings.TrimSpace(r.FormValue("source")))
	if src == "" {
		detected, ok := importer.Detect(body)
		if !ok {
			s.transferRedirect(w, r, "", "this does not look like any export "+
				"this can read. Choose the format explicitly if you know what "+
				"it is.")
			return
		}
		src = detected
	}
	rep, err := importer.Import(src, bytes.NewReader(body), time.Now())
	if err != nil {
		s.transferRedirect(w, r, "", err.Error())
		return
	}
	action, written := "import.preview", false
	if r.FormValue("write") != "" {
		if s.Transfer == nil || s.Transfer.Save == nil || s.Transfer.Pages == nil {
			s.transferRedirect(w, r, "", "import is not wired up in this build")
			return
		}
		// Captured before the pages are read, so a draft that moves while this
		// import is being parsed makes the write fail rather than silently
		// discard whatever moved it.
		base := s.Store.GetRef(site.RefDraft)
		pages, err := s.Transfer.Pages()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if pages == nil {
			pages = map[string]any{}
		}
		// Merged over what is there rather than replacing it. An import that
		// replaces the draft deletes everything the site had that the export
		// did not mention, which is most of a site when somebody is importing
		// one section of an old one.
		for _, pg := range rep.Pages {
			pages[pg.Name] = pg.Fields
		}
		if err := s.Transfer.Save(pages, fmt.Sprintf("import %d page(s) from %s",
			len(rep.Pages), src), p.Name, base); err != nil {
			s.transferRedirect(w, r, "", err.Error())
			return
		}
		action, written = "import", true
	}
	s.auditPub(p, action, "/", map[string]string{
		"source": string(src), "file": header.Filename,
		"pages": fmt.Sprint(len(rep.Pages)), "skipped": fmt.Sprint(len(rep.Skipped))})

	s.render(w, r, "import.html", map[string]any{
		"Nav": "transfer", "Title": "Import", "Principal": p,
		"Report": rep, "Source": src, "Filename": header.Filename,
		"Written":  written,
		"CanWrite": s.Policy.Evaluate(p.Name, auth.ActEditDraft, "/").Allowed,
	})
}

// handleStarter applies a starting point.
func (s *Server) handleStarter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	if s.Transfer == nil || s.Transfer.Save == nil || s.Transfer.Pages == nil {
		s.transferRedirect(w, r, "", "starters are not wired up in this build")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	t, found := starter.Get(name)
	if !found {
		s.transferRedirect(w, r, "", "there is no starter called "+name)
		return
	}
	base := s.Store.GetRef(site.RefDraft)
	pages, err := s.Transfer.Pages()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pages == nil {
		pages = map[string]any{}
	}
	page := strings.TrimSpace(r.FormValue("page"))
	if page == "" {
		page = "index"
	}
	if _, exists := pages[page]; exists && r.FormValue("overwrite") == "" {
		// Refused rather than merged. A starter's sample content is a complete
		// page, so applying it over one somebody wrote replaces their work
		// with an example, and "it looked like a draft" is not a defence.
		s.transferRedirect(w, r, "", page+" already exists. Applying a starter "+
			"replaces the whole page with its sample content, so this is "+
			"refused unless it is asked for explicitly.")
		return
	}
	pages[page] = t.Sample
	if err := s.Transfer.Save(pages, "apply the "+t.Name+" starter to "+page,
		p.Name, base); err != nil {
		s.transferRedirect(w, r, "", err.Error())
		return
	}
	s.auditPub(p, "template.apply", "/"+page, map[string]string{"starter": t.Name})
	s.transferRedirect(w, r, "applied "+t.Name+" to "+page+". Its fields are "+
		strings.Join(t.Fields, ", ")+".", "")
}

func (s *Server) transferRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/transfer"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}
