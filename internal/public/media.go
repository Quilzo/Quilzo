package public

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/quilzo/quilzo/internal/media"
)

// Serving the assets, which nothing did.
//
// An image could be uploaded, stored, described and listed, and then only ever
// looked at from inside the admin — so a published page could not carry one.
// That is the same shape as the bug in internal/medialib, one layer out: the
// feature was finished except for the part that makes it useful, and every
// test passed because each layer was correct about its own job.
//
// Found by uploading an image and then trying to put it on a page.

// Media returns a file for the public site. Nil means /media/ answers 404,
// which is the right state for a deployment that has no library rather than an
// error.
//
// A function rather than a directory, for the same reason nothing else here
// takes a path: a public server that maps a URL onto a filename is one
// traversal bug away from serving the token store. The library validates the
// identifier and does the lookup; this package never builds a path.
type MediaLookup func(id string) (media.File, []byte, error)

// reID is the shape of a stored asset's name: a SHA-256 in lowercase hex.
//
// Checked here, before the lookup, and not only inside it.
//
// Go's ServeMux normalises a path before routing, so `/media/../../x` never
// reaches this handler — it is answered with a redirect. That is not the whole
// story, and a test found the rest: `..%2f..%2f.scrivet%2ftokens.json` and
// `....//....//.scrivet/tokens.json` both survive normalisation and arrive
// here as `../../.scrivet/tokens.json`. Nothing was served either way, because
// the library validates the identifier before it builds a path — but the
// handler was passing a relative path to a function field somebody else
// supplies, and "it is safe because the callee checks" is a property of the
// current callee rather than of this route.
//
// So the check is on both sides of the boundary. This one makes the route safe
// whatever is wired behind it.
var reID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// mediaFile serves one asset.
func (st *Site) mediaFile(w http.ResponseWriter, r *http.Request) {
	if st.Media == nil {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/media/")
	if !reID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	f, body, err := st.Media(id)
	if err != nil {
		// Not found, whatever went wrong. Distinguishing "no such file" from
		// "malformed identifier" here would tell somebody probing the library
		// which of their guesses were the right shape.
		http.NotFound(w, r)
		return
	}

	h := w.Header()
	// From the format table, never from anything the upload said: a
	// caller-supplied content type is a request, not a fact. Anything this
	// program does not fully understand is sent as an attachment, so a format
	// with an unclear parser cannot become a page inside this origin.
	h.Set("Content-Type", f.MIME())
	h.Set("X-Content-Type-Options", "nosniff")
	if f.Inline() {
		h.Set("Content-Disposition", "inline")
	} else {
		h.Set("Content-Disposition", `attachment; filename="`+f.DownloadName()+`"`)
	}

	// The name is the hash of the bytes, so it is the ETag rather than
	// something derived from it, and different content is a different URL.
	// That is what makes this cacheable forever with nothing to purge — the
	// same property the pages have, for the same reason.
	etag := `"` + f.ID + `"`
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("ETag", etag)
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(body)
}
