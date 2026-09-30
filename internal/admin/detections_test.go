// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/detect"
)

type fakeDetections struct {
	ring       detect.Ring
	because    string
	suppressed []detect.Suppression
	removed    string
	kind       audit.Kind
}

func (f *fakeDetections) wire() *Detections {
	return &Detections{
		Load: func(now time.Time) (DetectionView, error) {
			return DetectionView{
				Rules: []detect.Rule{
					{ID: "auth.privileged-failed", Title: `Failed <script>alert(1)</script> sign-in`,
						Why: "a sprayed password", Sources: []string{"okta/system"},
						Severity: 4, Technique: []string{"T1110"}},
					{ID: "auth.quiet", Title: "Never fires", Sources: []string{"okta/system"}},
				},
				Stats: []detect.Stats{
					{Rule: "auth.privileged-failed", Ring: detect.Live,
						Findings: 14, Fired: 40, Real: 1, False: 9, Benign: 2,
						Undecided: 2, Last: now.Add(-time.Hour),
						NoisyEntity: "okta:svc-backup", NoisyCount: 9},
					{Rule: "auth.quiet", Ring: detect.Trial},
				},
				Proposals: []detect.Proposal{{Rule: "auth.privileged-failed",
					Do: "suppress", What: "suppress auth.privileged-failed for okta:svc-backup",
					Why: "9 of its 11 false or benign verdicts are about it"}},
				Suppressions: []detect.Suppression{{ID: "abc123",
					Rule: "auth.privileged-failed", Field: "actor",
					Value: "okta:old", Owner: "dana", Because: "migration",
					Until: now.Add(-24 * time.Hour)}},
				Hits: map[string]int{"abc123": 7},
			}, nil
		},
		Ring: func(rule string, ring detect.Ring, because, by string,
			kind audit.Kind) error {
			f.ring, f.because, f.kind = ring, because, kind
			return nil
		},
		Suppress: func(s detect.Suppression) error {
			f.suppressed = append(f.suppressed, s)
			return nil
		},
		Unsuppress: func(id, by string, kind audit.Kind) error {
			f.removed = id
			return nil
		},
	}
}

func postDetect(t *testing.T, srv *Server, token string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/security/detections/act",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestTheDetectionsScreenShowsWhatEachRuleIsWorth(t *testing.T) {
	srv, token := setup(t)
	f := &fakeDetections{}
	srv.Detections = f.wire()
	body := get(t, srv, "/security/detections", token).Body.String()
	if strings.Contains(body, "render error") || !strings.Contains(body, "</html>") {
		t.Fatal("the page did not render to the end")
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("a rule's title reached the page as markup")
	}
	for _, want := range []string{
		"8% real (likely", // 1 of 12 decided
		"0 of the 10 verdicts needed",
		"Worth considering", "okta:svc-backup", "expired", "T1110",
		"Named, not covered", "1 real, 9 false, 2 benign, 2 undecided",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
}

// One false positive about an account is not "most of the noise", and the
// screen must not offer to suppress it.
func TestASingleFalsePositiveIsNotOfferedForSuppression(t *testing.T) {
	srv, token := setup(t)
	srv.Detections = &Detections{Load: func(now time.Time) (DetectionView, error) {
		return DetectionView{
			Rules: []detect.Rule{{ID: "r", Title: "Rule"}},
			Stats: []detect.Stats{{Rule: "r", Ring: detect.Live, Findings: 12,
				Fired: 12, Real: 2, False: 10, NoisyEntity: "okta:admin-li",
				NoisyCount: 1}},
		}, nil
	}}
	body := get(t, srv, "/security/detections", token).Body.String()
	if strings.Contains(body, "okta:admin-li") {
		t.Error("an account behind one false positive in ten was named as " +
			"the source of the noise and filled into the suppression form")
	}
}

func TestChangingADetectionIsAnAdministratorsAndAPersons(t *testing.T) {
	srv, token := setup(t)
	f := &fakeDetections{}
	srv.Detections = f.wire()
	postDetect(t, srv, token, url.Values{"do": {"ring"},
		"rule": {"auth.privileged-failed"}, "ring": {"trial"},
		"because": {"noisy since the migration"}})
	if f.ring != detect.Trial || f.because == "" || f.kind != audit.KindHuman {
		t.Errorf("ring %q because %q as %q", f.ring, f.because, f.kind)
	}
	until := time.Now().AddDate(0, 0, 20).Format("2006-01-02")
	postDetect(t, srv, token, url.Values{"do": {"suppress"},
		"rule": {"auth.privileged-failed"}, "field": {"actor"},
		"value": {"okta:svc-backup"}, "owner": {"dana"}, "until": {until},
		"because": {"backup retries"}})
	if len(f.suppressed) != 1 || f.suppressed[0].Kind != audit.KindHuman ||
		f.suppressed[0].By == "" || f.suppressed[0].Until.IsZero() {
		t.Errorf("suppression: %+v", f.suppressed)
	}
	postDetect(t, srv, token, url.Values{"do": {"suppress"},
		"rule": {"auth.privileged-failed"}, "field": {"actor"},
		"value": {"okta:x"}, "owner": {"dana"}, "because": {"b"}})
	if len(f.suppressed) != 1 {
		t.Error("a suppression with no end date reached the store")
	}
	postDetect(t, srv, token, url.Values{"do": {"unsuppress"}, "id": {"abc123"}})
	if f.removed != "abc123" {
		t.Error("the suppression was not removed")
	}

	// An author can do none of it, and sees none of it.
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer",
		Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.Issue("w", "writer", auth.RoleAuthor, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeDetections{}
	srv.Detections = g.wire()
	postDetect(t, srv, secret, url.Values{"do": {"ring"},
		"rule": {"auth.privileged-failed"}, "ring": {"off"}, "because": {"x"}})
	if g.ring != "" {
		t.Error("an author switched a detection off")
	}
	if w := get(t, srv, "/security/detections", secret); w.Code == 200 {
		t.Error("an author opened the detections screen")
	}
}
