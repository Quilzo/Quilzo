package public

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lithoform/lithoform/internal/form"
	"github.com/lithoform/lithoform/internal/site"
	"github.com/lithoform/lithoform/internal/store"
)

func withForm(t *testing.T) (*Site, *form.Store) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home"}}, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	fs, err := form.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	set := &form.Set{Forms: []form.Form{{
		Name: "contact", Notice: "Kept 90 days, used only to reply.",
		Fields: []form.Field{
			{Name: "name", Label: "Name", Kind: form.Line, Required: true},
			{Name: "email", Label: "Email", Kind: form.Email},
		},
	}}}
	st := New(s, tpl)
	st.Forms = &Forms{
		Set:   func() (*form.Set, error) { return set, nil },
		Store: fs,
	}
	return st, fs
}

func post(t *testing.T, st *Site, path string, v url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.9:1234"
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	return w
}

func good() url.Values {
	return url.Values{
		"name":          {"Dana"},
		"email":         {"dana@example.org"},
		form.StampField: {fmt.Sprint(time.Now().Add(-5 * time.Second).Unix())},
	}
}

func TestASubmissionIsStored(t *testing.T) {
	st, fs := withForm(t)
	if w := post(t, st, "/form/contact", good()); w.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", w.Code, w.Body.String())
	}
	subs, err := fs.List("contact")
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 || subs[0].Values["name"] != "Dana" {
		t.Errorf("stored %v", subs)
	}
	if subs[0].Source == "" {
		t.Error("the source was not recorded, so a rate limit and an abuse " +
			"investigation both have nothing to work with")
	}
}

// A form nobody declared is not found, and does not say what does exist.
func TestAnUnknownFormIsNotFound(t *testing.T) {
	st, _ := withForm(t)
	w := post(t, st, "/form/nope", good())
	if w.Code != http.StatusNotFound {
		t.Errorf("answered %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "contact") {
		t.Error("named a form that does exist; an enumerable list of forms " +
			"is a list of things to spam")
	}
}

// GET does not submit anything.
func TestOnlyPostSubmits(t *testing.T) {
	st, fs := withForm(t)
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w,
		httptest.NewRequest(http.MethodGet, "/form/contact?name=Dana", nil))
	if w.Code == http.StatusOK {
		t.Error("a GET submitted a form, so a link could do it")
	}
	if subs, _ := fs.List("contact"); len(subs) != 0 {
		t.Error("a GET stored something")
	}
}

// The public server can append and cannot read.
//
// The whole argument for running it as a separate process is that the
// internet-facing half cannot read the postbag. There is no route here that
// lists, exports or removes a submission.
func TestThePublicServerCannotReadSubmissions(t *testing.T) {
	st, fs := withForm(t)
	if w := post(t, st, "/form/contact", good()); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	subs, _ := fs.List("contact")
	id := subs[0].ID

	for _, path := range []string{
		"/form/contact", "/form/contact/" + id, "/forms", "/submissions",
		"/form/contact/list", "/form/contact/export",
	} {
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "Dana") {
			t.Errorf("%s returned a stored submission", path)
		}
	}
}

// A refusal does not say which check caught it.
func TestARefusalDoesNotTeachAScriptWhatToChange(t *testing.T) {
	st, _ := withForm(t)
	v := good()
	v.Set(form.Honeypot, "http://spam.example")
	w := post(t, st, "/form/contact", v)
	if w.Code == http.StatusOK {
		t.Fatal("the honeypot did not catch it")
	}
	body := strings.ToLower(w.Body.String())
	for _, leak := range []string{"honeypot", form.Honeypot, "timing", "stamp"} {
		if strings.Contains(body, leak) {
			t.Errorf("the response names %q", leak)
		}
	}
}

// The result page escapes what it prints.
func TestTheResultPageEscapes(t *testing.T) {
	st, _ := withForm(t)
	v := good()
	v.Set("email", `<script>alert(1)</script>@x`)
	w := post(t, st, "/form/contact", v)
	if strings.Contains(w.Body.String(), "<script>") {
		t.Error("a submitted value was reflected unescaped")
	}
}

// An oversized body is refused before it is parsed.
func TestAnOversizedSubmissionIsRefused(t *testing.T) {
	st, _ := withForm(t)
	v := good()
	v.Set("name", strings.Repeat("x", form.MaxSubmission*2))
	w := post(t, st, "/form/contact", v)
	if w.Code == http.StatusOK {
		t.Error("accepted a body twice the limit")
	}
}

// The result is never cached.
func TestTheResultIsNotCached(t *testing.T) {
	st, _ := withForm(t)
	w := post(t, st, "/form/contact", good())
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control is %q; a stored 'thank you' served to the "+
			"next person is a confusing outcome", cc)
	}
}
