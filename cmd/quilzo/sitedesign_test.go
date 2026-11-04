// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/theme"
)

// designStore is a new store with the sections layout, an administrator,
// and a templates directory to design in.
func designStore(t *testing.T) (root, tpl string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root = t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "admin"})
	tpl = filepath.Join(t.TempDir(), "templates")
	if _, err := installStarter(tpl, "sections"); err != nil {
		t.Fatal(err)
	}
	return root, tpl
}

// aClip makes a short real recording, with or without a tone under it, and
// stores it with a description, or skips: what is tested is what the probe
// says about a real container, and a fixture invented here would test
// nothing but itself.
func aClip(t *testing.T, root string, sound bool) media.File {
	t.Helper()
	bin, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("no ffmpeg here, which is a configuration this supports")
	}
	if _, ok := media.HaveFFprobe(); !ok {
		t.Skip("no ffprobe here, so no recording's sound can be read")
	}
	out := filepath.Join(t.TempDir(), "clip.webm")
	args := []string{"-v", "error", "-f", "lavfi", "-i", "testsrc=size=320x240:rate=10:duration=3"}
	if sound {
		args = append(args, "-f", "lavfi", "-i", "sine=frequency=440:duration=3", "-c:a", "libvorbis", "-shortest")
	}
	args = append(args, "-c:v", "libvpx", "-b:v", "100k", "-y", out)
	if err := exec.Command(bin, args...).Run(); err != nil {
		t.Skipf("this ffmpeg cannot make the fixture: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	f, err := media.Accept(map[bool]string{true: "loud.webm", false: "loop.webm"}[sound], body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.Alt = "Violet light drifting over a neon grid"
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := lib.Put(f, body); err != nil {
		t.Fatal(err)
	}
	stored, err := lib.Stat(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// aPicture stores a small picture with a description.
func aPicture(t *testing.T, root string) media.File {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 64, 40))
	for x := 0; x < 64; x++ {
		for y := 0; y < 40; y++ {
			img.Set(x, y, color.RGBA{uint8(x * 4), 20, uint8(y * 6), 255})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	f, err := media.Accept("halo.png", b.Bytes(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.Alt = "A neon halo over a night valley"
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := lib.Put(f, b.Bytes()); err != nil {
		t.Fatal(err)
	}
	return f
}

// draftOf commits pages as the draft and returns the commit.
func draftOf(t *testing.T, root string, pages map[string]any) (*store.Store, string) {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := site.SaveDraftFrom(s, pages, "a page to judge", "dana", s.GetRef(site.RefDraft))
	if err != nil {
		t.Fatal(err)
	}
	return s, commit
}

// refusals is every blocking rule the gate found, by page.
func refusals(reports []*a11y.Report) map[string][]string {
	out := map[string][]string{}
	for _, r := range reports {
		for _, f := range r.Findings {
			if f.Severity == a11y.Blocking {
				out[r.Page] = append(out[r.Page], f.Rule)
			}
		}
	}
	return out
}

func has(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// G2 and G3 at the gate a publish runs: a backdrop behind the hero is drawn
// by the shipped layout with its stop control, and is accepted when the
// library recorded the recording as silent and refused when it has sound.
func TestTheGateKnowsASilentBackdropFromOneWithSound(t *testing.T) {
	root, tpl := designStore(t)
	quiet := aClip(t, root, false)
	loud := aClip(t, root, true)
	if !quiet.Silent() || loud.Silent() {
		t.Fatalf("the probe recorded sound as %s and %s", quiet.SoundWord(), loud.SoundWord())
	}
	pages := map[string]any{
		"index": map[string]any{"title": "Home", "hero": map[string]any{"lead": "Games for after dark",
			"backdrop_url": "/media/" + quiet.ID}},
		"loud": map[string]any{"title": "Loud", "hero": map[string]any{"lead": "A trailer",
			"backdrop_url": "/media/" + loud.ID}},
	}
	s, commit := draftOf(t, root, pages)
	reports, err := checkAccessibility(root, s, commit, tpl)
	if err != nil {
		t.Fatal(err)
	}
	got := refusals(reports)
	if len(got["index"]) > 0 {
		t.Errorf("a silent backdrop with its stop control was refused: %v", got["index"])
	}
	if !has(got["loud"], "backdrop-has-sound") {
		t.Errorf("a recording with sound became a muted backdrop: %v", got["loud"])
	}
}

// A silent recording in a video section publishes with its description and
// no captions; one with sound still needs captions.
func TestASilentVideoPublishesWithItsDescription(t *testing.T) {
	root, tpl := designStore(t)
	quiet := aClip(t, root, false)
	loud := aClip(t, root, true)
	video := func(id string) map[string]any {
		return map[string]any{"title": "Watch", "sections": []any{map[string]any{"video": map[string]any{
			"title": "The title loop", "src": "/media/" + id}}}}
	}
	s, commit := draftOf(t, root, map[string]any{"quiet": video(quiet.ID), "loud": video(loud.ID)})
	reports, err := checkAccessibility(root, s, commit, tpl)
	if err != nil {
		t.Fatal(err)
	}
	got := refusals(reports)
	if len(got["quiet"]) > 0 {
		t.Errorf("a described silent video was refused: %v", got["quiet"])
	}
	if !has(got["loud"], "video-has-no-captions") {
		t.Errorf("a video with sound published without captions: %v", got["loud"])
	}
}

// The words over a backdrop are judged against the worst picture the veil
// could cover, on the page that has one and on no other.
func TestTheGateHoldsTheWordsOverABackdropToTheVeil(t *testing.T) {
	root, tpl := designStore(t)
	halo := aPicture(t, root)
	pages := map[string]any{
		"index": map[string]any{"title": "Home", "sections": []any{map[string]any{"prose": map[string]any{
			"title": "After dark", "paragraphs": []any{"Three games."},
			"surface": "media", "backdrop_url": "/media/" + halo.ID}}}},
		"about": map[string]any{"title": "About", "hero": map[string]any{"lead": "Fifteen people in a cinema."}},
	}
	if err := cmdTheme(root, []string{"set", "scrim-strength", "30%", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	s, commit := draftOf(t, root, pages)
	reports, err := checkAccessibility(root, s, commit, tpl)
	if err != nil {
		t.Fatal(err)
	}
	got := refusals(reports)
	if !has(got["index"], "backdrop-contrast") {
		t.Errorf("a weak veil over a picture passed: %v", got["index"])
	}
	if has(got["about"], "backdrop-contrast") || has(got["theme"], "backdrop-contrast") {
		t.Errorf("a page without a backdrop was refused over the veil: %v", got)
	}
	if err := cmdTheme(root, []string{"set", "scrim-strength", "90%", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	reports, err = checkAccessibility(root, s, commit, tpl)
	if err != nil {
		t.Fatal(err)
	}
	if got := refusals(reports); len(got["index"]) > 0 {
		t.Errorf("a strong veil is still refused: %v", got["index"])
	}
}

// asPublisher presents a token for dana, an administrator, as the command
// line would: changing a style layer asks for publish authority itself.
func asPublisher(t *testing.T, root string) {
	t.Helper()
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := ts.Issue("dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	old := flagToken
	t.Cleanup(func() { flagToken = old })
	flagToken = secret
}

// G1 through the commands: a layer that breaks the rule is not saved, one
// that keeps it is saved, served, reported and recorded, and taken away —
// and only by somebody who may publish, since it is on every page.
func TestAStyleLayerIsCheckedSavedServedAndTakenAway(t *testing.T) {
	root, tpl := designStore(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.css")
	good := filepath.Join(dir, "good.css")
	if err := os.WriteFile(bad, []byte(".hero { color: #ff00ff; }"), 0o600); err != nil {
		t.Fatal(err)
	}
	layer := ".section-head h2 { text-shadow: 0 0 1rem color-mix(in srgb, var(--primary) 50%, transparent); }\n"
	if err := os.WriteFile(good, []byte(layer), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdTheme(root, []string{"layer", "set", good, "--dir", tpl}); err == nil ||
		!strings.Contains(err.Error(), "publish") {
		t.Fatalf("a layer was set by nobody in particular: %v", err)
	}
	asPublisher(t, root)
	if err := cmdTheme(root, []string{"layer", "set", bad, "--dir", tpl}); err == nil {
		t.Fatal("a layer with a hex colour was saved")
	}
	if fileExists(filepath.Join(tpl, theme.LayerFile)) {
		t.Fatal("a refused layer reached the templates directory")
	}
	if err := cmdTheme(root, []string{"layer", "set", good, "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	d, err := loadDesign(tpl)
	if err != nil {
		t.Fatal(err)
	}
	if !d.LayerServed || !strings.HasSuffix(d.Stylesheet, layer) {
		t.Fatal("a layer that passed is not the last thing in the stylesheet")
	}
	if err := cmdTheme(root, []string{"check", "--dir", tpl}); err != nil {
		t.Errorf("theme check fails a site whose layer passed: %v", err)
	}

	// Edited by hand into something refused, it is not served and the check
	// says so — the site keeps the stylesheet it can stand behind.
	if err := os.WriteFile(filepath.Join(tpl, theme.LayerFile), []byte("@import url(/fonts/x.css);"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, _ = loadDesign(tpl)
	if d.LayerServed || strings.Contains(d.Stylesheet, "@import") || len(d.Notes) == 0 {
		t.Fatal("a refused layer was served")
	}
	if err := cmdTheme(root, []string{"check", "--dir", tpl}); err == nil {
		t.Error("theme check passed a site whose layer is refused")
	}
	if err := cmdTheme(root, []string{"layer", "unset", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	if fileExists(filepath.Join(tpl, theme.LayerFile)) {
		t.Fatal("the layer is still there")
	}

	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var set, unset int
	for _, e := range evs {
		switch e.Action {
		case "theme.layer.set":
			set++
		case "theme.layer.unset":
			unset++
		}
	}
	if set != 1 || unset != 1 {
		t.Errorf("recorded %d set and %d unset, want one each", set, unset)
	}
}

// G4 and G5 through the commands: neon, a chamfer and a dark scheme are
// ordinary settings, and the generated stylesheet carries them.
func TestNeonADarkSchemeAndAChamferAreSettings(t *testing.T) {
	root, tpl := designStore(t)
	if err := cmdTheme(root, []string{"set", "style", "neon", "scheme", "dark", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	if err := cmdTheme(root, []string{"check", "--dir", tpl}); err != nil {
		t.Fatalf("neon on a dark site fails the check: %v", err)
	}
	d, err := loadDesign(tpl)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/* style: neon */", "corner-shape: bevel", "color-scheme: dark", "--glow: 16px;"} {
		if !strings.Contains(d.Stylesheet, want) {
			t.Errorf("the stylesheet lacks %q", want)
		}
	}
	for _, f := range d.Theme.Check() {
		if strings.Contains(f.Detail, "same colour in both schemes") {
			t.Errorf("a dark site is told its colours match: %s", f.Detail)
		}
	}
	if err := cmdTheme(root, []string{"set", "scheme", "dusk", "--dir", tpl}); err == nil {
		t.Error("an unknown scheme was saved")
	}
}

// G2 through the commands: a backdrop goes behind a section or the hero,
// and comes away again.
func TestABackdropIsPutBehindASectionFromTheTerminal(t *testing.T) {
	root, _ := designStore(t)
	halo := aPicture(t, root)
	draftOf(t, root, map[string]any{"index": map[string]any{"title": "Home",
		"hero":     map[string]any{"lead": "x"},
		"sections": []any{map[string]any{"features": map[string]any{"title": "Games"}}}}})
	if err := cmdSection(root, []string{"backdrop", "index", "0", halo.ID}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSection(root, []string{"backdrop", "index", "hero", "/media/" + halo.ID}); err != nil {
		t.Fatal(err)
	}
	page := draftedPage(t, root, "index")
	inner := page["sections"].([]any)[0].(map[string]any)["features"].(map[string]any)
	if inner["surface"] != "media" || inner["backdrop_url"] != "/media/"+halo.ID {
		t.Errorf("the section is %v", inner)
	}
	if page["hero"].(map[string]any)["backdrop_url"] != "/media/"+halo.ID {
		t.Errorf("the hero is %v", page["hero"])
	}
	if err := cmdSection(root, []string{"backdrop", "index", "0", "https://example.com/x.png"}); err == nil {
		t.Error("a remote address became a backdrop")
	}
	if err := cmdSection(root, []string{"backdrop", "index", "0", "--off"}); err != nil {
		t.Fatal(err)
	}
	inner = draftedPage(t, root, "index")["sections"].([]any)[0].(map[string]any)["features"].(map[string]any)
	if _, has := inner["backdrop_url"]; has {
		t.Errorf("--off left %v", inner)
	}
}

func draftedPage(t *testing.T, root, name string) map[string]any {
	t.Helper()
	pages, err := draftPages(root)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := pages[name].(map[string]any)
	return page
}

// G3 at upload: whether a recording has sound is recorded, in the file and
// in the audit record of adding it.
func TestAddingARecordingRecordsWhetherItHasSound(t *testing.T) {
	root, _ := designStore(t)
	bin, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("no ffmpeg here")
	}
	if _, ok := media.HaveFFprobe(); !ok {
		t.Skip("no ffprobe here")
	}
	clip := filepath.Join(t.TempDir(), "loop.webm")
	if err := exec.Command(bin, "-v", "error", "-f", "lavfi", "-i", "testsrc=size=320x240:rate=10:duration=2",
		"-c:v", "libvpx", "-b:v", "100k", "-y", clip).Run(); err != nil {
		t.Skipf("this ffmpeg cannot make the fixture: %v", err)
	}
	if err := cmdMedia(root, []string{"add", clip, "--alt", "A neon grid"}); err != nil {
		t.Fatal(err)
	}
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		if e.Action == "media.add" && e.Detail["sound"] == "no" {
			found = true
		}
	}
	if !found {
		t.Error("adding a silent recording did not record that it is silent")
	}
}

// G1 in a site package: the layer is checked with the package, written when
// it installs, taken away by a version that drops it, and a layer the site
// had by hand is put back when the package goes.
func TestASitePackageCarriesItsStyleLayer(t *testing.T) {
	root, design := siteStore(t)
	layer := ".hero h1 { text-shadow: 0 0 1rem color-mix(in srgb, var(--primary) 40%, transparent); }\n"
	withLayer := func(version, css string) string {
		path := sitePackage(t, "arcade", version, "#7c3aed")
		var p feature.Package
		b, _ := os.ReadFile(path)
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatal(err)
		}
		p.Site.Layer, p.Site.Scheme, p.Site.Style = css, "dark", "neon"
		b, _ = json.Marshal(p)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if err := installFeatureFile(root, withLayer("1.0", ".hero { color: red; }"), "", "", asAdmin("dana")); err == nil {
		t.Fatal("a package whose layer would not be served was installed")
	}

	// The site's own layer, by hand: the package has to be told to take the
	// site, and gives the layer back when it goes.
	if err := os.MkdirAll(design, 0o700); err != nil {
		t.Fatal(err)
	}
	mine := ".card { border-width: 2px; }\n"
	if err := os.WriteFile(filepath.Join(design, theme.LayerFile), []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installFeatureFile(root, withLayer("1.0", layer), "", "", asAdmin("dana")); err == nil {
		t.Fatal("a site with a layer set up by hand was taken over without asking")
	}
	if err := installFeatureFileWith(root, withLayer("1.0", layer), "", "", true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(design, theme.LayerFile)); string(b) != layer {
		t.Fatalf("the package's layer is %q", b)
	}
	if look := siteLook(t, design); look["scheme"] != "dark" || look["style"] != "neon" {
		t.Fatalf("the look is %v", look)
	}
	// A version without a layer puts back the one the site had.
	if err := installFeatureFile(root, withLayer("1.1", ""), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(design, theme.LayerFile)); string(b) != mine {
		t.Fatalf("dropping the layer left %q", b)
	}
	if err := installFeatureFile(root, withLayer("1.2", layer), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if err := removeFeature(root, "arcade", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(design, theme.LayerFile)); string(b) != mine {
		t.Fatalf("removing the package left the layer %q", b)
	}
}

// A package written before layers existed touches no layer.
func TestAnOlderSitePackageLeavesTheLayerAlone(t *testing.T) {
	root, design := siteStore(t)
	if err := installFeatureFile(root, sitePackage(t, "bakery", "1.0", "#c2410c"), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if fileExists(filepath.Join(design, theme.LayerFile)) {
		t.Fatal("a package with no layer wrote one")
	}
	if look := siteLook(t, design); look["scheme"] != "" || look["corner"] != "" {
		t.Fatalf("a package with no scheme or corner set one: %v", look)
	}
}

// Over MCP: an agent may build a dark neon site, and may not propose CSS.
func TestAnAgentChoosesASchemeAndProposesNoLayer(t *testing.T) {
	root, _ := siteStore(t)
	call := siteCrew(t, root)
	got := call("quilzo_write", "site_build", map[string]any{
		"description": "A games studio's site", "name": "Nyxvale", "style": "neon", "scheme": "dark"})
	id, _ := got["proposal"].(string)
	if id == "" {
		t.Fatalf("the build: %v", got)
	}
	b, err := os.ReadFile(proposalPath(root, id))
	if err != nil {
		t.Fatal(err)
	}
	var p feature.Package
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if p.Site.Style != "neon" || p.Site.Scheme != "dark" || p.Site.Layer != "" {
		t.Errorf("the built site is %+v", p.Site)
	}

	var pkg map[string]any
	if err := json.Unmarshal(b, &pkg); err != nil {
		t.Fatal(err)
	}
	pkg["site"].(map[string]any)["layer"] = ".hero { display: none; }"
	if refused := call("quilzo_write", "propose_feature", map[string]any{"package": pkg}); refused["error"] == nil ||
		!strings.Contains(refused["error"].(string), "style layer") {
		t.Errorf("an agent proposed CSS: %v", refused)
	}
}
