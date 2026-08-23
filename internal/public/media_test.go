package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/media"
)

// An asset that nothing serves is an asset no page can use.
//
// The library stored files, the admin listed them, and the public site had no
// route at all — so an image could be uploaded, described, optimised and
// listed, and then never appear on a published page. Every layer was correct
// about its own job and the product could not do the thing.
func TestThePublishedSiteServesTheAssets(t *testing.T) {
	f, body := fixtureImage(t)
	st := &Site{Media: func(id string) (media.File, []byte, error) {
		if id != f.ID {
			return media.File{}, nil, http.ErrMissingFile
		}
		return f, body, nil
	}}
	h := st.Handler()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/media/"+f.ID, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("serving a stored asset answered %d", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "image/png" {
		t.Errorf("content type is %q; it must come from the format table, "+
			"never from the upload", got)
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Error("a served asset must forbid sniffing")
	}
	if w.Body.Len() != len(body) {
		t.Errorf("served %d bytes of %d", w.Body.Len(), len(body))
	}

	// The name is the hash of the content, so the ETag is the name and a
	// conditional request answers itself. That is what makes these cacheable
	// forever with nothing to purge.
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag; a content-addressed asset has one by construction")
	}
	req := httptest.NewRequest(http.MethodGet, "/media/"+f.ID, nil)
	req.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req)
	if w2.Code != http.StatusNotModified {
		t.Errorf("a conditional request answered %d, not 304", w2.Code)
	}
}

// A deployment with no library says so by 404ing, rather than failing.
func TestASiteWithNoLibraryAnswersNotFound(t *testing.T) {
	w := httptest.NewRecorder()
	(&Site{}).Handler().ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/media/anything", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("a site with no media answered %d, not 404", w.Code)
	}
}

// An unknown identifier is a 404 and nothing more.
//
// Not a 400, and not a different message for "that is not a valid id" — the
// difference would tell somebody probing which of their guesses had the right
// shape.
func TestAnUnknownAssetIsIndistinguishableFromAMalformedOne(t *testing.T) {
	st := &Site{Media: func(string) (media.File, []byte, error) {
		return media.File{}, nil, http.ErrMissingFile
	}}
	for _, id := range []string{"nope", "0123456789abcdef", ""} {
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/media/"+id, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%q answered %d, not 404", id, w.Code)
		}
	}
}

// A traversal in the identifier never reaches the library.
//
// Three things have to fail for this to work, and it is worth naming which
// does what rather than trusting the outermost one. The mux normalises the
// path before any handler sees it, so `/media/../../x` becomes a redirect to
// `/x` — the request never arrives at the media handler at all. If it did, the
// library validates the identifier as 64 hex characters before it builds a
// path. And the handler never joins anything itself.
//
// The test asserts the outcome rather than the mechanism: whatever the layers
// do between them, the bytes of the token store do not come back.
func TestATraversalInAnAssetPathGetsNothing(t *testing.T) {
	reached := ""
	st := &Site{Media: func(id string) (media.File, []byte, error) {
		reached = id
		return media.File{}, nil, http.ErrMissingFile
	}}
	for _, id := range []string{
		"../../.quilzo/tokens.json",
		"..%2f..%2f.quilzo%2ftokens.json",
		"....//....//.quilzo/tokens.json",
	} {
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/media/"+id, nil))
		if w.Code == http.StatusOK {
			t.Errorf("%q was served", id)
		}
		if strings.Contains(w.Body.String(), "qz_") {
			t.Fatalf("%q returned something that looks like a credential", id)
		}
		if strings.Contains(reached, "..") {
			t.Errorf("%q reached the library as %q; the lookup should never "+
				"see a relative path", id, reached)
		}
	}
}

func fixtureImage(t *testing.T) (media.File, []byte) {
	t.Helper()
	body := []byte{
		0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
		0, 0, 0, 0x0d, 'I', 'H', 'D', 'R',
		0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0,
		0x3a, 0x7e, 0x9b, 0x55,
		0, 0, 0, 0x0a, 'I', 'D', 'A', 'T',
		0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01,
		0x0d, 0x0a, 0x2d, 0xb4,
		0, 0, 0, 0, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82,
	}
	f, err := media.Accept("pixel.png", body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return f, body
}

// A video has to be seekable, or on Safari it does not play at all.
//
// This handler wrote the whole body for every request and advertised no
// Accept-Ranges. Images did not care. Safari asks for bytes 0-1 before it will
// play any media and treats a 200 carrying the whole file as a server that
// cannot be seeked — so the video section kind this program ships produced a
// player that never started, and seeking was broken in every other browser too.
//
// Found by serving a real film from a real store and reading the headers.
func TestARangeRequestForAnAssetIsHonoured(t *testing.T) {
	f, body := fixtureImage(t)
	st := &Site{Media: func(id string) (media.File, []byte, error) {
		if id != f.ID {
			return media.File{}, nil, http.ErrMissingFile
		}
		return f, body, nil
	}}
	h := st.Handler()

	whole := httptest.NewRecorder()
	h.ServeHTTP(whole, httptest.NewRequest(http.MethodGet, "/media/"+f.ID, nil))
	if got := whole.Header().Get("Accept-Ranges"); got != "bytes" {
		t.Errorf("Accept-Ranges is %q; a player reads this before it decides "+
			"whether it can seek", got)
	}

	req := httptest.NewRequest(http.MethodGet, "/media/"+f.ID, nil)
	req.Header.Set("Range", "bytes=0-7")
	part := httptest.NewRecorder()
	h.ServeHTTP(part, req)
	if part.Code != http.StatusPartialContent {
		t.Fatalf("a range request answered %d, not 206", part.Code)
	}
	if part.Body.Len() != 8 {
		t.Errorf("asked for 8 bytes and got %d", part.Body.Len())
	}
	if !strings.HasPrefix(part.Body.String(), string(body[:8])) {
		t.Error("the bytes returned are not the bytes asked for")
	}
	if got := part.Header().Get("Content-Range"); got == "" {
		t.Error("a 206 without a Content-Range is not a partial response")
	}
}

// Audio and video render in the page rather than downloading.
//
// The format table marked them attachments, which a browser ignores for a media
// subresource — so the video section worked by accident while a direct link to
// the same file produced a download named after its hash.
func TestAVideoIsServedToBePlayed(t *testing.T) {
	body := fixtureFilm(t)
	f, err := media.Accept("dip.mp4", body, time.Now())
	if err != nil {
		t.Skipf("the film fixture is not accepted by this build: %v", err)
	}
	st := &Site{Media: func(string) (media.File, []byte, error) {
		return f, body, nil
	}}
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/media/"+f.ID, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("serving a film answered %d", w.Code)
	}
	if got := w.Header().Get("Content-Disposition"); strings.Contains(got, "attachment") {
		t.Errorf("a video is served as %q; the video section puts this in a "+
			"page, and a link to it should play rather than download", got)
	}
	if got := w.Header().Get("Content-Type"); got != "video/mp4" {
		t.Errorf("content type is %q", got)
	}
}

// fixtureFilm is the smallest thing this program accepts as an mp4.
func fixtureFilm(t *testing.T) []byte {
	t.Helper()
	// An ISO base media file: a size, "ftyp", a brand, then a free box.
	head := []byte{
		0, 0, 0, 0x18, 'f', 't', 'y', 'p',
		'i', 's', 'o', 'm', 0, 0, 0x02, 0,
		'i', 's', 'o', 'm', 'm', 'p', '4', '1',
		0, 0, 0, 0x10, 'f', 'r', 'e', 'e',
	}
	return append(head, make([]byte, 64)...)
}

// The installed app opens in the site's own colours.
//
// background_color and theme_color were two constants — white, and the shipped
// palette's teal — so every site that had been themed at all installed with a
// white splash screen under a title bar borrowed from a different design. The
// values come from the same tokens the stylesheet is generated from now.
func TestTheManifestCarriesTheSitesOwnColours(t *testing.T) {
	st := &Site{Name: "Aster & Alum", Background: "#faf6ef",
		ThemeColour: "#0e5a54"}
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/manifest.webmanifest", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("the manifest answered %d", w.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc["background_color"]; got != "#faf6ef" {
		t.Errorf("background_color is %v, not this site's surface", got)
	}
	if got := doc["theme_color"]; got != "#0e5a54" {
		t.Errorf("theme_color is %v, not this site's primary", got)
	}

	// A deployment with no theme still needs an answer.
	bare := &Site{Name: "Example"}
	w2 := httptest.NewRecorder()
	bare.Handler().ServeHTTP(w2, httptest.NewRequest(http.MethodGet,
		"/manifest.webmanifest", nil))
	var fallback map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &fallback); err != nil {
		t.Fatal(err)
	}
	if fallback["background_color"] == "" || fallback["theme_color"] == "" {
		t.Error("a site with no theme got an empty colour, which a browser " +
			"reads as no colour at all")
	}
}
