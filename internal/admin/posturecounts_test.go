// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/posture"
)

// tagged is an HTML tag, comment or the inside of a style or script element:
// what a person does not read on the page.
var tagged = regexp.MustCompile(`(?s)<style.*?</style>|<script.*?</script>|<!--.*?-->|<[^>]*>`)

// scoreShaped is a figure out of a hundred however it is written, or the
// word itself.
var scoreShaped = regexp.MustCompile(`(?i)\b\d{1,3}\s*(/|out of)\s*100\b|\bscore`)

// The Security screen opens on the findings counted by severity and on how
// much the scan covered, and shows no score: not in what it says, and not
// as a coloured numeral out of a hundred.
//
// It opened on "62/100" in a colour banded from the score. A number like
// that puts a world-readable token file and an input nobody supplied on one
// scale, and it is the figure that gets reported and argued about instead
// of the findings, which is the opposite of what this screen is for.
func TestSecurityPageHasNoScore(t *testing.T) {
	srv, token := setup(t)
	rep := brokenPosture()
	withPosture(srv, rep)
	tl := rep.Tally()

	w := get(t, srv, "/security", token)
	if w.Code != http.StatusOK {
		t.Fatalf("/security returned %d", w.Code)
	}
	body := w.Body.String()
	said := html.UnescapeString(tagged.ReplaceAllString(body, " "))
	said = strings.Join(strings.Fields(said), " ")

	if m := scoreShaped.FindString(said); m != "" {
		t.Errorf("the Security screen says %q, a score", m)
	}
	// The score as a bare figure, where it is not also one of the counts.
	counted := map[int]bool{tl.Findings: true, tl.Rules: true, tl.Checked: true, tl.NotChecked: true, tl.Suppressed: true}
	for _, c := range tl.Severities {
		counted[c.Count] = true
	}
	if !counted[rep.Score] && strings.Contains(body, fmt.Sprintf(">%d<", rep.Score)) {
		t.Errorf("the Security screen shows %d, the scan's score, as a figure of its own", rep.Score)
	}
	if strings.Contains(body, `class="score`) || strings.Contains(body, "outof") {
		t.Error("the Security screen still draws the score's numeral")
	}

	// What it shows instead: every severity with its count, in a table a
	// screen reader can read as one.
	if !strings.Contains(said, "Findings by severity") {
		t.Errorf("the counts have no caption: %s", said)
	}
	if strings.Count(body, `<th scope="row">`) < len(tl.Severities) {
		t.Error("the counts have no row headers")
	}
	for _, c := range tl.Severities {
		if want := fmt.Sprintf("%s %d", sentenceOf(string(c.Severity)), c.Count); !strings.Contains(said, want) {
			t.Errorf("the Security screen does not say %q", want)
		}
	}
	if !strings.Contains(said, tl.Coverage()) {
		t.Errorf("the Security screen does not say %q", tl.Coverage())
	}
	if want := fmt.Sprintf("%d not checked", tl.NotChecked); tl.NotChecked > 0 && !strings.Contains(said, want) {
		t.Errorf("the Security screen does not say %q", want)
	}

	r := a11y.Check("/security", body)
	for _, f := range r.Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("%s (%s): %s", f.Rule, f.Criterion, f.Detail)
		}
	}
}

// A scan that found nothing still says so with its counts, and with what it
// did not check, rather than with a perfect mark.
func TestACleanScanSaysItsCountsAndCoverage(t *testing.T) {
	srv, token := setup(t)
	rep := posture.Report{At: "2026-11-24T10:00:00Z", Counts: map[string]int{}, Checked: len(posture.Rules()),
		Skipped: []string{"token.admin-role"}, Score: 100}
	withPosture(srv, rep)
	body := get(t, srv, "/security", token).Body.String()
	said := strings.Join(strings.Fields(html.UnescapeString(tagged.ReplaceAllString(body, " "))), " ")
	if m := scoreShaped.FindString(said); m != "" {
		t.Errorf("a clean scan says %q", m)
	}
	if strings.Contains(body, ">100<") {
		t.Error("a clean scan shows 100 as a figure of its own")
	}
	if !strings.Contains(said, rep.Tally().Coverage()) || !strings.Contains(said, "1 not checked") {
		t.Errorf("a clean scan does not say what it covered: %s", said)
	}
}

func sentenceOf(s string) string { return strings.ToUpper(s[:1]) + s[1:] }
