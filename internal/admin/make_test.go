// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		Check: func(body []byte) (*feature.Package, feature.Card, feature.Plan, error) {
			p, err := feature.Decode(bytes.NewReader(body))
			if err != nil {
				return nil, feature.Card{}, feature.Plan{}, err
			}
			return p, p.MakeCard(), p.MakePlan(feature.State{}, nil), nil
		},
		Install: func(body []byte, rows string, act Actor) (string, []string, error) {
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
	rae, _, err := srv.Tokens.Issue("rae", "rae", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
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
	srv.Features.Check = func([]byte) (*feature.Package, feature.Card, feature.Plan, error) {
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
