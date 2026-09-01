package admin

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
)

// The media library, in the interface, and stored at all.
//
// Two problems at once. The screen was missing, which was the known gap; and
// the thing the screen would have shown did not exist, which was not. `quilzo
// media add` validated an upload thoroughly and then discarded it — see
// internal/medialib for what that looked like from the outside.
//
// So this screen is the first place in the product where an image can be put
// in and then used. It serves the bytes too, under /media/file/, because an
// asset nothing serves is an asset no page can reference.

// Media gives the admin the asset library.
type Media struct {
	Library func() (*medialib.Library, error)
	// Options are the optimisation settings from configuration, read per
	// upload so a change takes effect without a restart.
	Options func() media.Options
}

// MaxUpload caps a single file.
//
// Larger than MaxRequestBody, which is 2 MiB and right for a form: a
// photograph is routinely bigger than any amount of typed text, and applying
// the text limit to a file upload would refuse most cameras. The formats have
// their own caps below this — internal/media bounds each one separately,
// because a 200 MB PNG is not a photograph, it is a decompression bomb with a
// header.
const MaxUpload = 64 << 20 // 64 MiB

func (s *Server) handleMedia(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}
	if s.Media == nil {
		s.unwired(w, r, p, "Media", "the media library")
		return
	}
	lib, err := s.Media.Library()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	files, err := lib.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var total int64
	now := time.Now().UTC()
	rights := make(map[string]rightsRow, len(files))
	undeclared := 0
	for _, f := range files {
		total += f.Size
		if f.Kind != media.Image {
			continue
		}
		row := rightsOf(f, now)
		rights[f.ID] = row
		if row.State == "undeclared" {
			undeclared++
		}
	}

	webp, haveWebP := media.HaveWebP()

	s.render(w, r, "media.html", map[string]any{
		"Nav": "media", "Title": "Media", "Principal": p,
		"Files": files, "Total": total, "Accepted": media.Accepted(),
		"Rights": rights, "Undeclared": undeclared,
		"WebP": webp, "HaveWebP": haveWebP,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"CanWrite": s.Policy.Evaluate(p.Name, auth.ActEditDraft, "/").Allowed,
	})
}

// handleMediaUpload accepts a file from the browser.
func (s *Server) handleMediaUpload(w http.ResponseWriter, r *http.Request) {
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
	if s.Media == nil {
		s.unwired(w, r, p, "Media", "the media library")
		return
	}

	// The body limit applied by the middleware is for forms. A file upload
	// needs its own, larger, and it is still a limit: without one a single
	// request makes the process allocate until it dies, which needs no
	// credential and no cleverness.
	r.Body = http.MaxBytesReader(w, r.Body, MaxUpload)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		s.mediaRedirect(w, r, "", fmt.Sprintf(
			"that upload could not be read: %v. The limit is %d MB.",
			err, MaxUpload>>20))
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		s.mediaRedirect(w, r, "", "no file was attached")
		return
	}
	defer file.Close()

	body, err := io.ReadAll(file)
	if err != nil {
		s.mediaRedirect(w, r, "", err.Error())
		return
	}

	now := time.Now()
	f, err := media.Accept(header.Filename, body, now)
	if err != nil {
		// The refusal explains itself. internal/media says why a format is not
		// accepted rather than listing what is, because "svg is not in the
		// list" does not tell somebody that an SVG is a script container.
		s.mediaRedirect(w, r, "", err.Error())
		return
	}

	// Optimised after acceptance, never before. Accept decodes the file to
	// prove it is what it claims to be; optimising first would hand the
	// encoder bytes nothing had validated — which is the polyglot the format
	// check exists to catch.
	var did []string
	stripped := false
	if f.Kind == media.Image && s.Media.Options != nil {
		if opt, oerr := media.Optimise(f.Format, body, s.Media.Options()); oerr == nil &&
			len(opt.Did) > 0 {

			body, did, stripped = opt.Body, opt.Did, opt.StrippedMetadata
			// Re-accepted so the stored id is the hash of what is actually
			// stored. Skipping this files the optimised bytes under the
			// original's hash, and every integrity check downstream then
			// verifies a claim about a file that no longer exists.
			f, err = media.Accept(header.Filename, body, now)
			if err != nil {
				s.mediaRedirect(w, r, "", "the optimised image no longer "+
					"validates, so it has not been stored: "+err.Error())
				return
			}
		}
	}

	// Alt text is required at the point an image enters, not audited later. A
	// library full of undescribed images is a library somebody has to go back
	// through, and nobody ever does.
	alt := strings.TrimSpace(r.FormValue("alt"))
	if f.Kind == media.Image && alt == "" && r.FormValue("decorative") == "" {
		s.mediaRedirect(w, r, "", "this image needs a description. Say what it "+
			"conveys, not that it is an image — or mark it decorative, which "+
			"is a claim somebody is making rather than a box being skipped.")
		return
	}
	f.Alt, f.UploadedBy = alt, p.Name

	lib, err := s.Media.Library()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := lib.Put(f, body); err != nil {
		s.mediaRedirect(w, r, "", err.Error())
		return
	}

	detail := map[string]string{"file": f.Name, "id": shortHash(f.ID),
		"format": f.Format, "size": strconv.FormatInt(f.Size, 10)}
	if len(did) > 0 {
		detail["optimised"] = strings.Join(did, "; ")
	}
	if stripped {
		detail["metadata"] = "stripped"
	}
	s.auditPub(p, "media.add", "/", detail)

	msg := "stored " + f.Name
	if len(did) > 0 {
		msg += " — " + strings.Join(did, ", ")
	}
	if stripped {
		msg += ". The original carried metadata; a photograph from a phone " +
			"usually holds GPS coordinates, and it has been removed."
	}
	s.mediaRedirect(w, r, msg, "")
}

// handleMediaDelete removes a file.
func (s *Server) handleMediaDelete(w http.ResponseWriter, r *http.Request) {
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
	if s.Media == nil {
		s.unwired(w, r, p, "Media", "the media library")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	lib, err := s.Media.Library()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := r.FormValue("id")
	if err := lib.Remove(id); err != nil {
		s.mediaRedirect(w, r, "", err.Error())
		return
	}
	s.auditPub(p, "media.remove", "/", map[string]string{"id": shortHash(id)})
	s.mediaRedirect(w, r, "removed. Any page still pointing at it will now get "+
		"a 404, which is visible — better than an image that quietly changed.", "")
}

// handleMediaFile serves the bytes.
//
// The MIME type comes from the format table, never from anything the upload
// said: a caller-supplied Content-Type is a request, not a fact. Anything the
// media package does not fully understand is sent as an attachment rather than
// rendered, so a format with an unclear parser cannot become a page inside
// this origin.
func (s *Server) handleMediaFile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}
	if s.Media == nil {
		http.NotFound(w, r)
		return
	}
	lib, err := s.Media.Library()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/media/file/")
	f, body, err := lib.Get(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	h := w.Header()
	h.Set("Content-Type", f.MIME())
	h.Set("X-Content-Type-Options", "nosniff")
	if f.Inline() {
		h.Set("Content-Disposition", "inline")
	} else {
		h.Set("Content-Disposition", `attachment; filename="`+f.DownloadName()+`"`)
	}
	// The id is the hash of the bytes, so it is the ETag rather than something
	// derived from it. A different file is a different URL, which is why this
	// can be cached hard and never purged.
	h.Set("ETag", `"`+f.ID+`"`)
	h.Set("Cache-Control", "private, max-age=31536000, immutable")
	// Through ServeContent, so a preview of a film can be scrubbed and Safari
	// will play it at all: it asks for a byte range before it starts and gives
	// up on a server that answers 200 with the whole file. Conditional
	// requests are answered against the ETag set above, which is what the
	// hand-rolled 304 here used to do.
	modtime := time.Time{}
	if f.UploadedAt > 0 {
		modtime = time.Unix(f.UploadedAt, 0).UTC()
	}
	http.ServeContent(w, r, "", modtime, bytes.NewReader(body))
}

func (s *Server) mediaRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/media"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}
