package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
)

// An image licence can be recorded from the interface people use.
//
// The publish gate refuses a publication carrying an image whose permission has
// ended, and reports the undeclared ones so somebody goes and declares them —
// and the only place that could declare one was the command line. An editor
// working in a browser could upload a photograph, put it on a page, press
// Publish and be refused by a gate with nothing in the interface that answers
// it. The coverage table said so in as many words: "the admin has no screen for
// image rights at all".
func TestRightsCanBeRecordedFromTheAdmin(t *testing.T) {
	srv, token, id := mediaServer(t)

	// The screen says which files nobody has declared, because that is the
	// question the gate is going to ask.
	page := getPage(t, srv, "/media", token)
	if !strings.Contains(page, "undeclared") {
		t.Errorf("the media screen does not say that a file has no rights "+
			"recorded:\n%s", page)
	}
	if !strings.Contains(page, `action="/media/rights"`) {
		t.Error("the media screen has no way to record rights")
	}

	// Recording one.
	res := postForm(t, srv, "/media/rights", token, url.Values{
		"id":      {id},
		"licence": {"own-work"},
		"holder":  {"Aster & Alum"},
		"note":    {"Drawn by the studio."},
	}.Encode())
	if res.Code != http.StatusSeeOther && res.Code != http.StatusFound {
		t.Fatalf("recording rights answered %d: %s", res.Code, res.Body.String())
	}
	lib := libraryOf(t, srv)
	f, err := lib.Stat(id)
	if err != nil {
		t.Fatal(err)
	}
	if f.Rights.Licence != "own-work" || f.Rights.Holder != "Aster & Alum" {
		t.Fatalf("the rights were not stored: %+v", f.Rights)
	}
	if state := f.Rights.State(time.Now().UTC(), media.LapseWindow); state != "perpetual" {
		t.Errorf("a licence with no end is %q", state)
	}

	// An expiry, in the date form a browser sends.
	if res := postForm(t, srv, "/media/rights", token, url.Values{
		"id": {id}, "licence": {"stock-agency"}, "holder": {"An agency"},
		"until": {time.Now().UTC().AddDate(0, 0, 20).Format("2006-01-02")},
	}.Encode()); res.Code >= 400 {
		t.Fatalf("recording an expiry answered %d", res.Code)
	}
	f, _ = lib.Stat(id)
	if state := f.Rights.State(time.Now().UTC(), media.LapseWindow); state != "lapsing" {
		t.Errorf("a licence ending in twenty days is %q, and the whole point "+
			"of the window is that it is visible while it can still be "+
			"renewed", state)
	}

	// A date the field cannot mean is refused rather than stored as zero,
	// which would silently turn a term into a perpetual licence.
	before := f.Rights
	postForm(t, srv, "/media/rights", token, url.Values{
		"id": {id}, "licence": {"stock-agency"}, "until": {"next tuesday"},
	}.Encode())
	f, _ = lib.Stat(id)
	if f.Rights != before {
		t.Errorf("an unparseable date changed the record to %+v", f.Rights)
	}

	// And clearing removes the whole record, because a partial one is a state
	// media.Rights.Validate refuses.
	if res := postForm(t, srv, "/media/rights", token, url.Values{
		"id": {id}, "clear": {"1"},
	}.Encode()); res.Code >= 400 {
		t.Fatalf("clearing answered %d", res.Code)
	}
	f, _ = lib.Stat(id)
	if f.Rights.Declared() || f.Rights.Until != 0 {
		t.Errorf("clearing left %+v behind", f.Rights)
	}
}

// Recording a licence is a write, so a reader cannot do it.
func TestRecordingRightsNeedsPermissionToEdit(t *testing.T) {
	srv, _, id := mediaServer(t)
	res := postForm(t, srv, "/media/rights", "", url.Values{
		"id": {id}, "licence": {"own-work"},
	}.Encode())
	if res.Code < 400 {
		t.Errorf("an unauthenticated request recorded a licence (%d)", res.Code)
	}
}

// mediaServer is a server with one stored image and nothing said about it.
func mediaServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	srv, token := setup(t)

	dir := t.TempDir()
	lib, err := medialib.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	body := pixelPNG()
	f, err := media.Accept("swatch.png", body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.Alt = "A square of linen dyed indigo"
	if err := lib.Put(f, body); err != nil {
		t.Fatal(err)
	}
	srv.Media = &Media{
		Library: func() (*medialib.Library, error) { return medialib.Open(dir) },
		Options: func() media.Options { return media.Options{} },
	}
	return srv, token, f.ID
}

func libraryOf(t *testing.T, srv *Server) *medialib.Library {
	t.Helper()
	lib, err := srv.Media.Library()
	if err != nil {
		t.Fatal(err)
	}
	return lib
}

func getPage(t *testing.T, srv *Server, path, token string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w.Body.String()
}

// pixelPNG is the smallest thing media.Accept takes as an image.
func pixelPNG() []byte {
	return []byte{
		0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
		0, 0, 0, 0x0d, 'I', 'H', 'D', 'R',
		0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0,
		0x3a, 0x7e, 0x9b, 0x55,
		0, 0, 0, 0x0a, 'I', 'D', 'A', 'T',
		0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01,
		0x0d, 0x0a, 0x2d, 0xb4,
		0, 0, 0, 0, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82,
	}
}
