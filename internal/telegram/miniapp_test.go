package telegram

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakePublisher struct {
	saved  map[string]any
	handle string
	err    error
}

func (f *fakePublisher) Page(string) (map[string]any, bool, error) { return nil, false, nil }
func (f *fakePublisher) Designs() []Design {
	return []Design{{Name: "sections", Look: "Rounded and generous."}}
}
func (f *fakePublisher) Save(handle string, body map[string]any, _, _ string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.handle, f.saved = handle, body
	return "/" + handle, nil
}

func testApp(t *testing.T, pub Publisher, now time.Time) *App {
	t.Helper()
	return &App{
		BotToken: botToken, Spender: NewMemory(), Publisher: pub,
		Now: func() time.Time { return now },
	}
}

func get(t *testing.T, a *App, target string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	return w
}

func post(t *testing.T, a *App, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}

// Nobody gets in without a signature. This is the whole surface: it is
// authenticated, writable, and reachable by anyone who finds the address.
func TestAnUnsignedArrivalIsRefused(t *testing.T) {
	a := testApp(t, &fakePublisher{}, time.Now())
	for _, target := range []string{"/", "/?u=1", "/?u=1&s=deadbeef&v=q1"} {
		if w := get(t, a, target); w.Code != http.StatusForbidden {
			t.Errorf("GET %s gave %d, want 403", target, w.Code)
		}
	}
	if w := post(t, a, "/publish", url.Values{"title": {"x"}}); w.Code != http.StatusForbidden {
		t.Errorf("an unsigned publish gave %d, want 403", w.Code)
	}
}

// The policy this surface serves. A Mini App is framed by definition, so
// frame-ancestors cannot be 'none' here — but it can name the two origins that
// may, which is the difference between a considered exception and an omission.
func TestTheMiniAppServesItsOwnPolicy(t *testing.T) {
	a := testApp(t, &fakePublisher{}, time.Now())
	policy := get(t, a, "/").Header().Get("Content-Security-Policy")

	for _, want := range []string{
		"default-src 'none'", "script-src 'none'", "form-action 'self'",
		"base-uri 'none'", "frame-ancestors https://web.telegram.org",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("the policy has no %q:\n%s", want, policy)
		}
	}
	if strings.Contains(policy, "unsafe-eval") {
		t.Errorf("the policy permits eval:\n%s", policy)
	}
	// A credential travels in the URL of this surface.
	if cache := get(t, a, "/").Header().Get("Cache-Control"); cache != "no-store" {
		t.Errorf("Cache-Control is %q on a surface whose URL carries a credential", cache)
	}
}

// The round trip somebody actually performs: arrive on a signed link, get a
// form, submit it, and have a page published.
func TestASignedArrivalCanPublish(t *testing.T) {
	now := time.Now()
	pub := &fakePublisher{}
	a := testApp(t, pub, now)

	query, err := NewLink(User{ID: 279058397, Username: "durov"}, botToken, now)
	if err != nil {
		t.Fatal(err)
	}
	form := get(t, a, "/?"+query)
	if form.Code != http.StatusOK {
		t.Fatalf("a signed arrival gave %d:\n%s", form.Code, form.Body.String())
	}
	grant := grantIn(t, form.Body.String())

	done := post(t, a, "/publish", url.Values{
		"grant": {grant},
		"title": {"A page I made in a chat"},
		"lead":  {"One line."},
		"body":  {"First paragraph.\n\nSecond paragraph."},
	})
	if done.Code != http.StatusOK {
		t.Fatalf("publishing gave %d:\n%s", done.Code, done.Body.String())
	}
	if pub.handle != "tg279058397" {
		t.Errorf("published under %q; the handle must be the numeric id, "+
			"because a username can be released and taken by somebody else",
			pub.handle)
	}
	if pub.saved["title"] != "A page I made in a chat" {
		t.Errorf("the title was saved as %v", pub.saved["title"])
	}
	sections, _ := pub.saved["sections"].([]any)
	if len(sections) != 1 {
		t.Fatalf("expected one prose section, got %d", len(sections))
	}
	prose := sections[0].(map[string]any)["prose"].(map[string]any)
	if paragraphs := prose["paragraphs"].([]any); len(paragraphs) != 2 {
		t.Errorf("a blank line did not start a new paragraph: %v", paragraphs)
	}
}

// A grant is not a link and a link is not a grant. They are signed the same way,
// so without the purpose field a captured link could be submitted as a grant and
// skip being single-use entirely.
func TestALinkCannotBeSubmittedAsAGrant(t *testing.T) {
	now := time.Now()
	a := testApp(t, &fakePublisher{}, now)
	link, err := NewLink(User{ID: 1}, botToken, now)
	if err != nil {
		t.Fatal(err)
	}
	w := post(t, a, "/publish", url.Values{"grant": {link}, "title": {"x"}})
	if w.Code != http.StatusForbidden {
		t.Errorf("a link was accepted as a form grant (%d)", w.Code)
	}
}

// The surface a stranger reaches. Nothing they type may become an element,
// anywhere on the page they get back.
func TestHostileInputIsInertOnEveryScreen(t *testing.T) {
	now := time.Now()
	pub := &fakePublisher{}
	a := testApp(t, pub, now)

	query, _ := NewLink(User{ID: 7, Username: `<script>alert(1)</script>`}, botToken, now)
	form := get(t, a, "/?"+query)
	assertInert(t, "the form", form.Body.String())

	grant := grantIn(t, form.Body.String())
	// A gate refusing is the path that renders the person's own words back at
	// them, which is exactly where an escaping mistake would land.
	pub.err = errTest(`refused: <script>alert(1)</script>`)
	again := post(t, a, "/publish", url.Values{
		"grant": {grant},
		"title": {`" onmouseover="alert(1)`},
		"body":  {`<img src=x onerror=alert(1)>`},
	})
	assertInert(t, "the refusal", again.Body.String())
}

type errTest string

func (e errTest) Error() string { return string(e) }

// assertInert checks that no tag in the output carries an event handler and that
// nothing executable survived.
//
// It looks for the *element*, not the characters: `&lt;script&gt;` in text is
// the payload appearing, which is correct, and confusing that with the payload
// working is how this kind of test passes for the wrong reason.
func assertInert(t *testing.T, where, body string) {
	t.Helper()
	lowered := strings.ToLower(body)
	for _, forbidden := range []string{
		"<script>alert", "<img src=x onerror", `href="javascript:`,
		`" onmouseover="alert`,
	} {
		if strings.Contains(lowered, forbidden) {
			t.Errorf("%s emitted %q:\n%s", where, forbidden, body)
		}
	}
}

func grantIn(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="grant" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no grant in the form:\n%s", body)
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatal("the grant field is not closed")
	}
	// The form escapes for HTML; undo exactly that to get the value back.
	return strings.NewReplacer("&amp;", "&", "&#34;", `"`, "&lt;", "<", "&gt;", ">").
		Replace(rest[:j])
}
