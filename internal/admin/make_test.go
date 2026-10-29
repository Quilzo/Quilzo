// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/feature"
)

type featureCalls struct {
	installed []string
	rows      []string
	drafted   []string
	fromName  string
	decided   []string
	removed   []string
	secrets   []string
	pending   []feature.Pending
}

func wireFeatures(srv *Server) *featureCalls {
	c := &featureCalls{}
	srv.Features = &FeatureHooks{
		Installed: func() ([]feature.Installed, error) {
			return []feature.Installed{{Name: "lab-samples", Version: "1.1.0", Title: "Lab sample tracker",
				At: time.Now(), By: []string{"dana", "sam"}, Owns: make([]feature.Ref, 4),
				History: []feature.Version{{Version: "1.0.0"}}}}, nil
		},
		Pending: func() ([]feature.Pending, error) { return c.pending, nil },
		Check: func(body []byte, _ bool) (*feature.Package, feature.Card, feature.Plan, error) {
			p, err := feature.Decode(bytes.NewReader(body))
			if err != nil {
				return nil, feature.Card{}, feature.Plan{}, err
			}
			return p, p.MakeCard(), p.MakePlan(feature.State{}, nil), nil
		},
		Install: func(body []byte, rows string, _ bool, act Actor) (string, []string, error) {
			by := act.Name
			c.installed = append(c.installed, by)
			c.rows = append(c.rows, rows)
			return "", c.secrets, nil
		},
		Draft: func(description string, _ Actor) ([]byte, []string, string, error) {
			c.drafted = append(c.drafted, description)
			if strings.Contains(description, "broken") {
				return []byte(`{"format":1,"name":"x"}`), nil, "the package is not usable: a title is required", nil
			}
			return feature.Example(), []string{`left out "agents": a draft holds content blocks only`}, "", nil
		},
		FromData: func(name string, data []byte, _ Actor) ([]byte, string, int, string, []string, error) {
			c.fromName = name
			return feature.Example(), "0123456789abcdef01234567", 3, "samples", nil, nil
		},
		Decide: func(id string, approve bool, act Actor) error {
			by := act.Name
			c.decided = append(c.decided, id+" "+by)
			return nil
		},
		Remove: func(name string, _ Actor) error {
			c.removed = append(c.removed, name)
			return nil
		},
		Rollback: func(name string, _ Actor) (string, error) { return "", nil },
	}
	return c
}

// A package is checked before anything is installed, and what is installed
// is exactly what was read: bytes changed after the check are refused.
func TestMakeChecksAPackageAndInstallsExactlyWhatWasRead(t *testing.T) {
	srv, token := setup(t)
	calls := wireFeatures(srv)

	page := get(t, srv, "/make", token).Body.String()
	whole(t, page)
	for _, want := range []string{"Add a feature", "Lab sample tracker", "Go back to 1.0.0", "dana and sam"} {
		if !strings.Contains(page, want) {
			t.Errorf("the Make screen does not show %q", want)
		}
	}

	check := postForm(t, srv, "/make/check", token, url.Values{"text": {string(feature.Example())}}.Encode())
	if check.Code != http.StatusOK {
		t.Fatalf("check answered %d: %s", check.Code, check.Body.String())
	}
	body := check.Body.String()
	whole(t, body)
	for _, want := range []string{"Records in", "personal data", "risk medium", "Two different people",
		"Ask for it to be installed", "page", "available_samples"} {
		if !strings.Contains(body, want) {
			t.Errorf("the check page does not say %q", want)
		}
	}
	p, _ := feature.Decode(bytes.NewReader(feature.Example()))
	digest, _ := p.Digest()
	if !strings.Contains(body, digest) {
		t.Fatal("the check page does not carry the digest it was shown under")
	}

	// Changed after the check: refused.
	changed := strings.Replace(string(feature.Example()), "Lab sample tracker", "Something else", 1)
	_, loc := postFormLoc(t, srv, token, "/make/act", url.Values{"do": {"install"}, "body": {changed}, "digest": {digest}})
	if !strings.Contains(loc, "e=") || len(calls.installed) != 0 {
		t.Fatalf("a package changed after its check was installed: %s %v", loc, calls.installed)
	}
	// As read: installed, by the person signed in.
	_, loc = postFormLoc(t, srv, token, "/make/act", url.Values{"do": {"install"}, "body": {string(feature.Example())},
		"digest": {digest}})
	if !strings.Contains(loc, "m=") || len(calls.installed) != 1 || calls.installed[0] != "editor" {
		t.Fatalf("install went to %s, installed %v", loc, calls.installed)
	}
}

// A new webhook's secret is shown once, on the response to the install,
// and never travels in a redirect.
func TestMakeShowsAWebhookSecretOnceAndNotInARedirect(t *testing.T) {
	srv, token := setup(t)
	calls := wireFeatures(srv)
	calls.secrets = []string{"https://hooks.example/x  s3cr3t-value"}
	p, _ := feature.Decode(bytes.NewReader(feature.Example()))
	digest, _ := p.Digest()
	res := postForm(t, srv, "/make/act", token,
		url.Values{"do": {"install"}, "body": {string(feature.Example())}, "digest": {digest}}.Encode())
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "s3cr3t-value") {
		t.Fatalf("the secret was not shown: %d", res.Code)
	}
	if strings.Contains(res.Header().Get("Location"), "s3cr3t") {
		t.Fatal("the secret went into a redirect")
	}
	if res.Header().Get("Cache-Control") != "no-store" {
		t.Error("the page carrying a secret may be cached")
	}
	whole(t, res.Body.String())
}

// The person who asked for an install is not offered to approve it, the
// other administrator is, and the approvals screen lists it for them.
func TestMakeOffersApprovalOnlyToSomebodyElse(t *testing.T) {
	srv, token := setup(t)
	calls := wireFeatures(srv)
	calls.pending = []feature.Pending{{ID: "0123456789ab", Name: "lab-samples", Version: "1.0.0",
		RequestedBy: "editor", At: time.Now(),
		Card: feature.Card{Title: "Lab sample tracker", Risk: "medium", Because: []string{"it stores personal data"}}}}
	page := get(t, srv, "/make", token).Body.String()
	if strings.Contains(page, "Approve and install") || !strings.Contains(page, "somebody else approves it") {
		t.Error("the person who asked was offered to approve their own install")
	}
	calls.pending[0].RequestedBy = "dana"
	page = get(t, srv, "/make", token).Body.String()
	if !strings.Contains(page, "Approve and install") {
		t.Error("another administrator was not offered to approve it")
	}
	approvals := get(t, srv, "/approvals", token).Body.String()
	if !strings.Contains(approvals, "Install Lab sample tracker 1.0.0") || !strings.Contains(approvals, "installs") {
		t.Error("the approvals screen does not list the waiting install")
	}
	postFormLoc(t, srv, token, "/make/act", url.Values{"do": {"approve"}, "id": {"0123456789ab"}})
	postFormLoc(t, srv, token, "/make/act", url.Values{"do": {"approve"}, "id": {"../../etc"}})
	if len(calls.decided) != 1 || calls.decided[0] != "0123456789ab editor" {
		t.Errorf("decided %v", calls.decided)
	}
	postFormLoc(t, srv, token, "/make/act", url.Values{"do": {"remove"}, "name": {"Lab Samples/.."}})
	postFormLoc(t, srv, token, "/make/act", url.Values{"do": {"remove"}, "name": {"lab-samples"}})
	if len(calls.removed) != 1 {
		t.Errorf("removed %v", calls.removed)
	}
}

// Make is an administrator's screen.
func TestMakeIsForAdministrators(t *testing.T) {
	srv, _ := setup(t)
	calls := wireFeatures(srv)
	if err := srv.Policy.Grant(auth.Binding{Principal: "rae", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	rae, _, err := srv.Tokens.IssueSession("rae", "rae", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if code := get(t, srv, "/make", rae).Code; code != http.StatusForbidden {
		t.Errorf("an author reached Make: %d", code)
	}
	code, _ := postFormLoc(t, srv, rae, "/make/act", url.Values{"do": {"remove"}, "name": {"lab-samples"}})
	if code != http.StatusForbidden || len(calls.removed) != 0 {
		t.Errorf("an author removed a feature: %d %v", code, calls.removed)
	}
	srv.Features.Check = func([]byte, bool) (*feature.Package, feature.Card, feature.Plan, error) {
		return nil, feature.Card{}, feature.Plan{}, errors.New("unused")
	}
}

// A description becomes a draft shown as any package is, with what was left
// out; a draft that does not pass is shown with its problems and no
// install button.
func TestMakeDraftsFromADescriptionAndShowsWhatWasLeftOut(t *testing.T) {
	srv, token := setup(t)
	calls := wireFeatures(srv)
	res := postForm(t, srv, "/make/draft", token, url.Values{"description": {"track lab samples"}}.Encode())
	body := res.Body.String()
	if res.Code != http.StatusOK || !strings.Contains(body, "Ask for it to be installed") ||
		!strings.Contains(body, "a draft holds content blocks only") {
		t.Fatalf("draft page %d", res.Code)
	}
	whole(t, body)
	res = postForm(t, srv, "/make/draft", token, url.Values{"description": {"something broken"}}.Encode())
	body = res.Body.String()
	if strings.Contains(body, `name="do" value="install"`) || !strings.Contains(body, "a title is required") ||
		!strings.Contains(body, "Check it again") {
		t.Error("a draft that does not pass was offered for install")
	}
	whole(t, body)
	if len(calls.drafted) != 2 {
		t.Errorf("drafted %v", calls.drafted)
	}
}

// A spreadsheet's rows travel to the install by the id they were kept
// under, and nothing else is accepted in their place.
func TestMakeFromASpreadsheetCarriesItsRowsToTheInstall(t *testing.T) {
	srv, token := setup(t)
	calls := wireFeatures(srv)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("data", "lab samples.csv")
	fw.Write([]byte("code\nS-1\n"))
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/make/from", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	body := res.Body.String()
	if res.Code != http.StatusOK || !strings.Contains(body, "0123456789abcdef01234567") ||
		!strings.Contains(body, "records from the file go into") {
		t.Fatalf("from page %d: %.300s", res.Code, body)
	}
	if calls.fromName != "lab samples" {
		t.Errorf("named %q", calls.fromName)
	}
	p, _ := feature.Decode(bytes.NewReader(feature.Example()))
	digest, _ := p.Digest()
	postFormLoc(t, srv, token, "/make/act", url.Values{"do": {"install"}, "body": {string(feature.Example())},
		"digest": {digest}, "rows": {"../../../etc/passwd"}})
	postFormLoc(t, srv, token, "/make/act", url.Values{"do": {"install"}, "body": {string(feature.Example())},
		"digest": {digest}, "rows": {"0123456789abcdef01234567"}})
	if len(calls.rows) != 1 || calls.rows[0] != "0123456789abcdef01234567" {
		t.Errorf("rows reached the install as %v", calls.rows)
	}
}

// A site package over a site somebody set up by hand cannot be installed
// as it stands; the screen offers to let it take the site over, checks it
// again that way, and installs it that way.
func TestASitePackageTakesOverAHandMadeSiteOnlyWhenAsked(t *testing.T) {
	srv, token := setup(t)
	wireFeatures(srv)
	var tookOver []bool
	srv.Features.Check = func(body []byte, takeSite bool) (*feature.Package, feature.Card, feature.Plan, error) {
		p, err := feature.Decode(bytes.NewReader(body))
		if err != nil {
			return nil, feature.Card{}, feature.Plan{}, err
		}
		plan := feature.Plan{Steps: []feature.Step{{Ref: feature.SiteRef, Action: feature.Add}}}
		if !takeSite {
			plan = feature.Plan{Conflicts: []string{feature.SiteByHand + "; …"}}
		}
		return p, p.MakeCard(), plan, nil
	}
	srv.Features.Install = func(body []byte, rows string, takeSite bool, act Actor) (string, []string, error) {
		tookOver = append(tookOver, takeSite)
		return "", nil, nil
	}
	pkg := `{"format":1,"name":"bakery","version":"1.0","title":"Hart's Bakery","purpose":"The bakery's site.",` +
		`"site":{"name":"Hart's Bakery","style":"soft"}}`

	w := postForm(t, srv, "/make/check", token, url.Values{"text": {pkg}}.Encode())
	body := w.Body.String()
	whole(t, body)
	if !strings.Contains(body, "Let it take over the site") || strings.Contains(body, `value="install"`) {
		t.Fatalf("the conflict did not offer to take the site over:\n%s", body)
	}
	w = postForm(t, srv, "/make/check", token, url.Values{"text": {pkg}, "take_site": {"1"}}.Encode())
	body = w.Body.String()
	if !strings.Contains(body, `value="install"`) || !strings.Contains(body, `name="take_site" value="1"`) {
		t.Fatalf("checked again to take over, it cannot be installed:\n%s", body)
	}
	digest := regexp.MustCompile(`name="digest" value="([0-9a-f]+)"`).FindStringSubmatch(body)
	if digest == nil {
		t.Fatal("no digest on the page")
	}
	postFormLoc(t, srv, token, "/make/act", url.Values{"do": {"install"}, "digest": {digest[1]}, "body": {pkg},
		"take_site": {"1"}})
	if len(tookOver) != 1 || !tookOver[0] {
		t.Fatalf("the install did not take the site over: %v", tookOver)
	}
}

// A whole site is built from what somebody says it is for and shown as any
// package is, with what they will have to fill in; the only administrator
// is told they approve it alone.
func TestMakeBuildsAWholeSiteAndListsWhatToFillIn(t *testing.T) {
	srv, token := setup(t)
	wireFeatures(srv)
	var asked feature.SiteBrief
	var model bool
	srv.Features.Site = func(b feature.SiteBrief, useModel bool, _ Actor) ([]byte, []string, error) {
		asked, model = b, useModel
		p, err := feature.BuildSite(b, "dana", time.Now())
		if err != nil {
			return nil, nil, err
		}
		body, err := json.Marshal(p)
		return body, nil, err
	}
	srv.Features.OnlyAdmin = func(string) bool { return true }

	page := get(t, srv, "/make", token).Body.String()
	if !strings.Contains(page, `action="/make/site"`) || !strings.Contains(page, "A café, restaurant or bar") {
		t.Fatal("Make offers no way to build a whole site")
	}
	whole(t, page)

	res := postForm(t, srv, "/make/site", token, url.Values{"description": {"A bakery in Leeds"},
		"name": {"Hart's Bakery"}, "style": {"bold"}, "colour": {"#15803d"}}.Encode())
	body := res.Body.String()
	if res.Code != http.StatusOK || asked.Name != "Hart's Bakery" || asked.Style != "bold" || asked.Colour != "#15803d" || model {
		t.Fatalf("built %d from %+v, model %v", res.Code, asked, model)
	}
	for _, want := range []string{`Names the site &#34;Hart&#39;s Bakery&#34;`, "To fill in", "your opening hours, in a sentence",
		"you approve it alone", ">Install it<"} {
		if !strings.Contains(body, want) {
			t.Errorf("the check page does not say %q", want)
		}
	}
	whole(t, body)

	res = postForm(t, srv, "/make/site", token, url.Values{"description": {"A bakery"}}.Encode())
	if loc := res.Header().Get("Location"); !strings.Contains(loc, "e=") {
		t.Errorf("a site with no name and no model went to %q", loc)
	}
}

// What only the owner knows is written in from one screen, once for every
// page it is on, by somebody who may edit the draft.
func TestFillInWritesTheBlanksIntoTheDraft(t *testing.T) {
	srv, token := setup(t)
	wireFeatures(srv)
	var filled map[string]string
	srv.Features.Blanks = func() ([]string, map[string][]string, error) {
		return []string{"your address", "your opening hours"}, map[string][]string{
			"your address": {"contact", "visit"}, "your opening hours": {"visit"}}, nil
	}
	srv.Features.Fill = func(v map[string]string, _ Actor) (int, []string, error) {
		filled = v
		return 3, []string{"contact", "visit"}, nil
	}
	if page := get(t, srv, "/make", token).Body.String(); !strings.Contains(page, "2 things to fill in") {
		t.Error("Make does not say there are blanks to fill in")
	}
	page := get(t, srv, "/make/fill", token).Body.String()
	if !strings.Contains(page, "Your address") || !strings.Contains(page, "<code>visit</code>") {
		t.Fatal("the Fill in screen does not list the blanks")
	}
	whole(t, page)

	code, loc := postFormLoc(t, srv, token, "/make/fill", url.Values{"what": {"your address", "your opening hours"},
		"value0": {"4 Mill Lane, Leeds"}, "value1": {""}, "leave1": {"1"}})
	if code != http.StatusSeeOther || !strings.Contains(loc, "Filled+in+3+blanks") {
		t.Fatalf("filling went %d to %q", code, loc)
	}
	if filled["your address"] != "4 Mill Lane, Leeds" || filled["your opening hours"] != "" || len(filled) != 2 {
		t.Fatalf("filled %v", filled)
	}

	// Nothing written in is a mistake to say, not a write.
	filled = nil
	if _, loc := postFormLoc(t, srv, token, "/make/fill", url.Values{"what": {"your address"}}); !strings.Contains(loc, "e=") || filled != nil {
		t.Errorf("an empty form went to %q and filled %v", loc, filled)
	}

	// A reader may not fill anything in.
	if err := srv.Policy.Grant(auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	rae, _, err := srv.Tokens.IssueSession("rae", "rae", auth.RoleReader, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := postFormLoc(t, srv, rae, "/make/fill", url.Values{"what": {"your address"}, "value0": {"x"}}); code != http.StatusForbidden || filled != nil {
		t.Errorf("a reader filled in a blank: %d", code)
	}
}

// An old site is brought in from its address and shown as any package is,
// with what was left behind.
func TestMakeBringsASiteInFromItsAddress(t *testing.T) {
	srv, token := setup(t)
	wireFeatures(srv)
	var asked string
	var pages int
	var pictures bool
	srv.Features.Import = func(address, name string, n int, pics bool, _ Actor) ([]byte, []string, error) {
		asked, pages, pictures = address, n, pics
		p, err := feature.BuildSite(feature.SiteBrief{Name: "Hart's Bakery", Kind: "restaurant"}, "dana", time.Now())
		if err != nil {
			return nil, nil, err
		}
		body, err := json.Marshal(p)
		return body, []string{"1 form(s) were left behind"}, err
	}
	page := get(t, srv, "/make", token).Body.String()
	if !strings.Contains(page, `action="/make/import"`) || !strings.Contains(page, "robots.txt is obeyed") {
		t.Fatal("Make offers no way to bring a site in")
	}
	whole(t, page)
	res := postForm(t, srv, "/make/import", token, url.Values{"address": {"https://hartsbakery.example"},
		"pages": {"25"}, "pictures": {"1"}}.Encode())
	body := res.Body.String()
	if res.Code != http.StatusOK || asked != "https://hartsbakery.example" || pages != 25 || !pictures ||
		!strings.Contains(body, "1 form(s) were left behind") {
		t.Fatalf("bringing it in: %d, asked %q for %d pages", res.Code, asked, pages)
	}
	whole(t, body)
}

// What an agent proposed is on Make and Approvals for a person: read as
// any package is read, installed only by them, or set aside.
func TestMakeShowsWhatAnAgentProposed(t *testing.T) {
	srv, token := setup(t)
	wireFeatures(srv)
	p, err := feature.BuildSite(feature.SiteBrief{Name: "Hart's Bakery", Kind: "restaurant"}, "dana", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pkg, _ := json.Marshal(p)
	waiting := []Proposal{{ID: "0123456789ab", Name: p.Name, Version: p.Version, Title: p.Title,
		What: "a site built from a description", By: "mcp-client", For: "dana", At: time.Now().Add(-time.Hour), Notes: 1}}
	var dismissed string
	srv.Features.Proposals = func() ([]Proposal, error) { return waiting, nil }
	srv.Features.Proposal = func(id string) ([]byte, string, []string, error) {
		if id != waiting[0].ID {
			return nil, "", nil, errors.New("no proposal " + id + " is waiting")
		}
		return pkg, "Proposed by mcp-client for dana", nil, nil
	}
	srv.Features.Dismiss = func(id string, _ Actor) error { dismissed = id; return nil }

	page := get(t, srv, "/make", token).Body.String()
	if !strings.Contains(page, "Proposed for you") || !strings.Contains(page, `href="/make/proposal?id=0123456789ab"`) {
		t.Fatal("Make does not show what an agent proposed")
	}
	whole(t, page)
	card := get(t, srv, "/make/proposal?id=0123456789ab", token)
	if card.Code != http.StatusOK || !strings.Contains(card.Body.String(), "Proposed by mcp-client for dana") ||
		!strings.Contains(card.Body.String(), `value="install"`) {
		t.Fatalf("the proposal: %d", card.Code)
	}
	whole(t, card.Body.String())
	if gone := get(t, srv, "/make/proposal?id=ffffffffffff", token); gone.Code != http.StatusOK ||
		!strings.Contains(gone.Body.String(), "no proposal ffffffffffff is waiting") {
		t.Fatalf("a proposal that is not there: %d", gone.Code)
	}
	if approvals := get(t, srv, "/approvals", token).Body.String(); !strings.Contains(approvals, "proposed by an agent for dana") {
		t.Fatal("Approvals does not show what an agent proposed")
	}
	if code, _ := postFormLoc(t, srv, token, "/make/proposal", url.Values{"do": {"dismiss"}, "id": {"0123456789ab"}}); code != http.StatusSeeOther || dismissed != "0123456789ab" {
		t.Fatalf("setting it aside: %d, %q", code, dismissed)
	}
}

// A feature that comes with Quilzo is offered until it is installed, and
// then said to be there rather than offered again.
func TestMakeSaysAReadyFeatureIsAlreadyInstalled(t *testing.T) {
	srv, token := setup(t)
	wireFeatures(srv)
	srv.Features.Ready = func() []ReadyFeature {
		return []ReadyFeature{{Name: "lab-samples", Title: "Samples", About: "Track them."},
			{Name: "blog", Title: "Blog", About: "Posts, newest first."}}
	}
	body := get(t, srv, "/make", token).Body.String()
	if !strings.Contains(body, `name="ready" value="blog"`) {
		t.Error("a feature that is not installed is not offered")
	}
	if strings.Contains(body, `name="ready" value="lab-samples"`) || !strings.Contains(body, "Installed on this site") {
		t.Error("an installed feature is offered again")
	}
}
