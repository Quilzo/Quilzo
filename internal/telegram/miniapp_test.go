package telegram

import (
	"github.com/quilzo/quilzo/internal/chat"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
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
		BotToken: botToken, Spender: chat.NewMemory(), Publisher: pub,
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

// A refusal must hand back what the person typed.
//
// The gate refusing is the likeliest outcome for somebody's first page — that is
// what it is for — and rendering a fresh form each time meant being refused cost
// you the page you had written. A checker that costs you your work is a checker
// people learn to route around, which is the one thing it exists to prevent.
func TestARefusalKeepsWhatWasTyped(t *testing.T) {
	now := time.Now()
	pub := &fakePublisher{err: errTest("refused: an image has no alt attribute")}
	a := testApp(t, pub, now)

	query, _ := NewLink(User{ID: 3}, botToken, now)
	grant := grantIn(t, get(t, a, "/?"+query).Body.String())

	body := "First paragraph.\n\nSecond paragraph."
	w := post(t, a, "/publish", url.Values{
		"grant":  {grant},
		"title":  {"Notes on making things slowly"},
		"lead":   {"A page about paper and ink."},
		"body":   {body},
		"design": {"sections"},
	})
	out := w.Body.String()

	// The reason, in the gate's own words.
	if !strings.Contains(out, "an image has no alt attribute") {
		t.Errorf("the refusal does not say which check said no:\n%s", out)
	}
	// And every field, back where it was.
	for _, kept := range []string{
		`value="Notes on making things slowly"`,
		`value="A page about paper and ink."`,
		"First paragraph.",
		"Second paragraph.",
	} {
		if !strings.Contains(out, kept) {
			t.Errorf("a refusal discarded %q; the person has to retype it", kept)
		}
	}
	if !strings.Contains(out, `value="sections" selected`) {
		t.Error("the chosen design was not kept selected")
	}
}

// The empty-title refusal is the same rule and a different branch, so it gets
// its own check rather than being assumed to share one.
func TestTheEmptyTitleRefusalAlsoKeepsTheBody(t *testing.T) {
	now := time.Now()
	a := testApp(t, &fakePublisher{}, now)
	query, _ := NewLink(User{ID: 4}, botToken, now)
	grant := grantIn(t, get(t, a, "/?"+query).Body.String())

	out := post(t, a, "/publish", url.Values{
		"grant": {grant}, "title": {"  "}, "body": {"Words worth keeping."},
	}).Body.String()

	if !strings.Contains(out, "A page needs a title") {
		t.Errorf("the empty title was not explained:\n%s", out)
	}
	if !strings.Contains(out, "Words worth keeping.") {
		t.Error("a missing title discarded the body")
	}
}

// Every link between editor screens has to carry a usable grant.
//
// A grant is itself a signed query string, so it contains & and =. HTML-escaping
// it into an href is not enough: the browser sends it and the server reads only
// the part before the first &, so every link reports an expired session.
//
// The form tests never saw this, because a hidden field needs no URL escaping.
// It appeared the first time a browser followed a link, which is the argument
// for driving a surface the way somebody uses it.
func TestALinkBetweenScreensCarriesAUsableGrant(t *testing.T) {
	now := time.Now()
	a := testApp(t, &fakePublisher{}, now)
	a.Drafts = &fakeDrafts{}

	query, _ := NewLink(User{ID: 279058397, Username: "durov"}, botToken, now)
	home := get(t, a, "/?"+query)
	if home.Code != http.StatusOK {
		t.Fatalf("arrival gave %d", home.Code)
	}

	// Every href carrying a grant, followed the way a browser would.
	for _, href := range hrefsWithGrant(t, home.Body.String()) {
		page := get(t, a, href)
		if page.Code != http.StatusOK {
			t.Errorf("following %s gave %d — the grant did not survive the link",
				href, page.Code)
			continue
		}
		if strings.Contains(page.Body.String(), "This session has ended") {
			t.Errorf("following %s reported an expired session; the grant was "+
				"cut off at its first &", href)
		}
	}
}

// hrefsWithGrant pulls out every link that carries a g= parameter, unescaping
// the HTML the way a browser does before requesting it.
func hrefsWithGrant(t *testing.T, body string) []string {
	t.Helper()
	var out []string
	for _, m := range regexp.MustCompile(`href="(/[^"]*\bg=[^"]*)"`).
		FindAllStringSubmatch(body, -1) {
		out = append(out, strings.ReplaceAll(m[1], "&amp;", "&"))
	}
	if len(out) == 0 {
		t.Fatal("no links carrying a grant; this test would pass by checking nothing")
	}
	return out
}

// fakeDrafts is a working copy in memory.
type fakeDrafts struct {
	body map[string]any
	base string
}

func (f *fakeDrafts) Draft(string) (map[string]any, string, error) {
	if f.body == nil {
		return map[string]any{}, f.base, nil
	}
	return f.body, f.base, nil
}

func (f *fakeDrafts) Keep(_ string, body map[string]any, _, _, _ string) error {
	f.body = body
	return nil
}

// The way back in has to work, and a grant is not a link.
//
// Every editor screen links to "/" carrying a grant, because that is the
// credential a multi-screen editor passes along. For a while "/" understood
// only the single-use arrival link, so every one of those links reported that
// the link could not be used — and the form tests never noticed, because they
// posted rather than following a link back.
func TestTheWayBackAcceptsAGrantAndStillSpendsALink(t *testing.T) {
	now := time.Now()
	a := testApp(t, &fakePublisher{}, now)
	a.Drafts = &fakeDrafts{}

	grant, err := NewGrant(User{ID: 7}, botToken, now)
	if err != nil {
		t.Fatal(err)
	}
	back := get(t, a, "/?g="+url.QueryEscape(grant))
	if back.Code != http.StatusOK {
		t.Fatalf("returning with a grant gave %d:\n%s", back.Code, back.Body.String())
	}
	if !strings.Contains(back.Body.String(), "Your page") {
		t.Error("returning with a grant did not reach the editor")
	}
	// And again, because a grant is deliberately reusable inside its window.
	if again := get(t, a, "/?g="+url.QueryEscape(grant)); again.Code != http.StatusOK {
		t.Errorf("a grant stopped working on second use (%d)", again.Code)
	}

	// A real arrival link must still be single-use, or a forwarded message is
	// a way in twice.
	query, _ := NewLink(User{ID: 8}, botToken, now)
	if first := get(t, a, "/?"+query); first.Code != http.StatusOK {
		t.Fatalf("arrival gave %d", first.Code)
	}
	if second := get(t, a, "/?"+query); second.Code == http.StatusOK {
		t.Error("an arrival link worked twice; accepting grants must not have " +
			"turned off spending")
	}
}

// Adding an entry keeps what was typed above it.
//
// The add button used to be a form of its own containing nothing but the
// button, so pressing it posted the button and discarded every field on the
// screen. In a recording of the editor a picture was chosen from the library,
// "add another" was pressed to make room for a second, and the first one was
// gone — with no message, because as far as the server was concerned nothing
// had been submitted.
//
// The fix is that adding saves first. This test posts the way the browser does:
// the field values, and the add button's own name and value.
func TestAddingAnEntryKeepsTheOnesAlreadyFilledIn(t *testing.T) {
	now := time.Now()
	drafts := &fakeDrafts{body: map[string]any{
		"title": "Marginalia",
		"sections": []any{
			map[string]any{"gallery": map[string]any{
				"title": "From the bench",
				"items": []any{map[string]any{
					"image": "", "alt": "", "caption": "A caption"}},
			}},
		},
	}}
	a := testApp(t, &fakePublisher{}, now)
	a.Drafts = drafts

	grant, err := NewGrant(User{ID: 11}, botToken, now)
	if err != nil {
		t.Fatal(err)
	}
	res := post(t, a, "/section", url.Values{
		"grant":             {grant},
		"at":                {"0"},
		"v.items.0.image":   {"/media/abc123"},
		"v.items.0.alt":     {"A type case"},
		"v.items.0.caption": {"The upper case"},
		"additem":           {"items"},
	})
	if res.Code != http.StatusSeeOther {
		t.Fatalf("adding an entry gave %d:\n%s", res.Code, res.Body.String())
	}

	items := galleryItems(t, drafts.body)
	if len(items) != 2 {
		t.Fatalf("wanted two entries after adding one, got %d", len(items))
	}
	first, _ := items[0].(map[string]any)
	if got := first["image"]; got != "/media/abc123" {
		t.Errorf("the picture chosen before adding an entry was lost: image = %q",
			got)
	}
	if got := first["alt"]; got != "A type case" {
		t.Errorf("the description was lost: alt = %q", got)
	}
}

// Removing an entry is offered once there is more than one to remove.
func TestRemovingAnEntryIsOfferedAndWorks(t *testing.T) {
	now := time.Now()
	drafts := &fakeDrafts{body: map[string]any{
		"title": "Marginalia",
		"sections": []any{
			map[string]any{"gallery": map[string]any{
				"title": "From the bench",
				"items": []any{
					map[string]any{"image": "/media/a", "alt": "one",
						"caption": "one"},
					map[string]any{"image": "/media/b", "alt": "two",
						"caption": "two"},
				},
			}},
		},
	}}
	a := testApp(t, &fakePublisher{}, now)
	a.Drafts = drafts

	grant, err := NewGrant(User{ID: 12}, botToken, now)
	if err != nil {
		t.Fatal(err)
	}
	screen := get(t, a, "/section?g="+url.QueryEscape(grant)+"&at=0")
	if !strings.Contains(screen.Body.String(), "Remove the last item") {
		t.Error("no way to remove an entry; the only exit from an entry added " +
			"by mistake was deleting the whole section")
	}

	res := post(t, a, "/section", url.Values{
		"grant": {grant}, "at": {"0"}, "do": {"removeitem"},
		"list": {"items"}, "index": {"1"},
	})
	if res.Code != http.StatusSeeOther {
		t.Fatalf("removing an entry gave %d:\n%s", res.Code, res.Body.String())
	}
	if items := galleryItems(t, drafts.body); len(items) != 1 {
		t.Errorf("wanted one entry left, got %d", len(items))
	}
}

func galleryItems(t *testing.T, body map[string]any) []any {
	t.Helper()
	sections, ok := body["sections"].([]any)
	if !ok || len(sections) == 0 {
		t.Fatalf("the draft lost its sections: %v", body)
	}
	first, ok := sections[0].(map[string]any)
	if !ok {
		t.Fatalf("the first section is not a section: %v", sections[0])
	}
	inner, ok := first["gallery"].(map[string]any)
	if !ok {
		t.Fatalf("the first section is no longer a gallery: %v", first)
	}
	items, _ := inner["items"].([]any)
	return items
}
