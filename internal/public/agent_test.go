// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
)

func launcherBot(l assistant.Launcher) assistant.Assistant {
	a := shopBot
	a.Launcher = &l
	return a
}

// The button is on the page, as a link that works without a script; the
// script is allowed by exactly its hash and the panel by frame-src 'self',
// and nothing else is loosened.
func TestAPageCarriesTheLauncherAndAllowsOnlyItsScript(t *testing.T) {
	st, _ := askSite(t, launcherBot(assistant.Launcher{Style: "pill", Label: "Questions?"}))
	w := get(st, "/returns", nil)
	body, csp := w.Body.String(), w.Header().Get("Content-Security-Policy")
	if w.Code != 200 || !strings.Contains(body, `<a class="qz-launch-btn" href="/ask/help">`) || !strings.Contains(body, "<span>Questions?</span>") {
		t.Fatalf("the launcher is not on the page: %d", w.Code)
	}
	if !strings.Contains(body, `<link rel="stylesheet" href="/agent.css">`) {
		t.Error("the launcher's stylesheet is not linked")
	}
	m := regexp.MustCompile(`(?s)<script>(.*?)</script>\s*</body>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no script at the end of the body")
	}
	sum := sha256.Sum256([]byte(m[1]))
	if want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"; !strings.Contains(csp, want) {
		t.Errorf("the policy does not allow the script that is on the page: %s", csp)
	}
	if !strings.Contains(csp, "frame-src 'self'") || strings.Contains(csp, "frame-src *") {
		t.Errorf("the panel's frame is not allowed from this site alone: %s", csp)
	}
	if strings.Contains(csp, "'unsafe-inline'") && regexp.MustCompile(`script-src[^;]*'unsafe-inline'`).MatchString(csp) {
		t.Errorf("inline script was allowed wholesale: %s", csp)
	}
}

func TestTheLauncherKeepsToItsPages(t *testing.T) {
	st, _ := askSite(t, launcherBot(assistant.Launcher{Pages: []string{"/returns"}, Nudge: "Returning something?", NudgePages: []string{"/returns"}}))
	if body := get(st, "/", nil).Body.String(); strings.Contains(body, "qz-launch") {
		t.Error("the launcher is on a page outside its prefixes")
	}
	if body := get(st, "/returns", nil).Body.String(); !strings.Contains(body, `data-nudge="Returning something?"`) {
		t.Error("the nudge is missing where it was asked for")
	}
	// Not on the conversation itself, nor on a static copy.
	if body := get(st, "/ask/help", nil).Body.String(); strings.Contains(body, "qz-launch-btn") {
		t.Error("the conversation page carries a button to itself")
	}
	if body := get(st, "/returns", map[string]string{CopyHeader: "1"}).Body.String(); strings.Contains(body, "qz-launch") {
		t.Error("a static copy carries a launcher with no server behind it")
	}
}

// A page whose button changes is not the page a cache holds.
func TestTheLauncherIsInThePagesETag(t *testing.T) {
	st, _ := askSite(t, shopBot)
	plain := get(st, "/returns", nil).Header().Get("ETag")
	st2, _ := askSite(t, launcherBot(assistant.Launcher{}))
	with := get(st2, "/returns", nil).Header().Get("ETag")
	st3, _ := askSite(t, launcherBot(assistant.Launcher{Style: "tab"}))
	tab := get(st3, "/returns", nil).Header().Get("ETag")
	if plain == with || with == tab {
		t.Errorf("ETags %s %s %s", plain, with, tab)
	}
}

// The panel is this site framing itself: allowed from here, with its links
// going to the page behind it and the mode carried on its forms.
func TestThePanelIsFramedByThisSiteAlone(t *testing.T) {
	st, _ := askSite(t, launcherBot(assistant.Launcher{Suggestions: []string{"Can I return opened ink?"}}))
	w := get(st, "/ask/help?embed=panel", nil)
	body, csp := w.Body.String(), w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'self'") || strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("the panel cannot be framed by this site: %s", csp)
	}
	if !strings.Contains(body, `name="embed" value="panel"`) {
		t.Error("the panel's question form does not carry the mode")
	}
	// A suggestion is a link that asks it, in the panel, with no script.
	if !strings.Contains(body, `<a href="/ask/help?q=Can%20I%20return%20opened%20ink%3f&amp;embed=panel">Can I return opened ink?</a>`) {
		t.Errorf("the suggestion is not a link that asks it: %s", body)
	}
	answered := get(st, "/ask/help?q=Can%20I%20return%20opened%20ink%3f&embed=panel", nil).Body.String()
	if !strings.Contains(answered, "cannot be returned") || !strings.Contains(answered, `href="/returns" target="_top"`) {
		t.Errorf("following a suggestion in the panel: %s", answered)
	}
	// Without the launcher's mode, framing stays as it was: nobody.
	if csp := get(st, "/ask/help", nil).Header().Get("Content-Security-Policy"); strings.Contains(csp, "frame-ancestors 'self'") {
		t.Errorf("the plain conversation page became framable: %s", csp)
	}
}

// A page with live updates and the launcher allows both scripts.
func TestTwoScriptsOnAPageAreBothAllowed(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Security-Policy", "default-src 'none'; script-src 'none'")
	allowScript(hdr, liveHash)
	allowScript(hdr, agentHash)
	csp := hdr.Get("Content-Security-Policy")
	if !strings.Contains(csp, liveHash) || !strings.Contains(csp, agentHash) || strings.Contains(csp, "'none' 'sha") {
		t.Errorf("%s", csp)
	}
}

// Another site's embed is not the launcher's panel: framing stays as the
// owner declared it, and links open apart from the page that framed it.
func TestAnotherSitesEmbedIsNotThePanel(t *testing.T) {
	st, _ := askSite(t, launcherBot(assistant.Launcher{}))
	w := get(st, "/ask/help?embed=1&q=Can%20I%20return%20opened%20ink%3f", nil)
	if csp := w.Header().Get("Content-Security-Policy"); strings.Contains(csp, "frame-ancestors 'self'") {
		t.Errorf("an embed with no declared origin became framable: %s", csp)
	}
	body := w.Body.String()
	if !strings.Contains(body, `target="_blank"`) || strings.Contains(body, `target="_top"`) ||
		strings.Contains(body, `value="panel"`) {
		t.Error("another site's embed was treated as the launcher's panel")
	}
}
