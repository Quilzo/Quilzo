// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/theme"
)

// asMachine points the command line's writer at a buffer, in --json mode
// when asked, for one test.
func asMachine(t *testing.T, json bool) *bytes.Buffer {
	t.Helper()
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(json)
	w.Out = &buf
	return &buf
}

// `theme layer --json` answers a script in one shape, whatever it did: the
// layer that is there, the rules a refused one broke, a saved one, and one
// taken away. It printed nothing for set and unset, "findings": null for a
// layer with none, and only a count when it refused one.
func TestTheLayerAnswersAScriptInOneShape(t *testing.T) {
	root, tpl := designStore(t)
	asPublisher(t, root)
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.css")
	good := filepath.Join(dir, "good.css")
	if err := os.WriteFile(bad, []byte(".hero { color: #ff00ff; }\n.lead { background: red; }"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, []byte(".card { border-color: var(--outline); }"), 0o600); err != nil {
		t.Fatal(err)
	}
	type doc struct {
		Path     string          `json:"path"`
		Bytes    int             `json:"bytes"`
		Served   bool            `json:"served"`
		Saved    bool            `json:"saved"`
		Removed  *bool           `json:"removed"`
		Refused  int             `json:"refused"`
		Findings []theme.Finding `json:"findings"`
	}
	run := func(args ...string) (doc, string, error) {
		t.Helper()
		buf := asMachine(t, true)
		err := cmdTheme(root, append([]string{"layer"}, append(args, "--dir", tpl)...))
		var d doc
		raw := buf.String()
		if raw != "" {
			if jerr := json.Unmarshal([]byte(raw), &d); jerr != nil {
				t.Fatalf("theme layer %v printed something that is not one document: %v\n%s", args, jerr, raw)
			}
		}
		return d, raw, err
	}

	if d, raw, err := run(); err != nil || d.Findings == nil || !strings.Contains(raw, `"findings": []`) {
		t.Errorf("no layer: %v %s", err, raw)
	}
	d, _, err := run("set", bad)
	if err == nil || d.Refused != 2 || len(d.Findings) != 2 || d.Saved {
		t.Errorf("a refused layer: %v %+v", err, d)
	}
	if d, _, err := run("set", good); err != nil || !d.Saved || !d.Served || d.Bytes == 0 {
		t.Errorf("a saved layer: %v %+v", err, d)
	}
	if d, _, err := run("unset"); err != nil || d.Removed == nil || !*d.Removed {
		t.Errorf("a layer taken away: %v %+v", err, d)
	}
	if d, _, err := run("unset"); err != nil || d.Removed == nil || *d.Removed {
		t.Errorf("no layer to take away: %v %+v", err, d)
	}
}

// `theme styles --json` lists the choices a site package or a script can
// name: every style with neon among them, the corners and the schemes. It
// printed nothing under --json.
func TestTheChoicesAreListedForAScript(t *testing.T) {
	root, _ := designStore(t)
	buf := asMachine(t, true)
	if err := cmdTheme(root, []string{"styles"}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Styles, Corners, Schemes []struct{ Name, Words string }
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, buf.String())
	}
	names := func(list []struct{ Name, Words string }) string {
		var n []string
		for _, c := range list {
			if c.Words == "" {
				t.Errorf("%s has no words", c.Name)
			}
			n = append(n, c.Name)
		}
		return strings.Join(n, " ")
	}
	if s := names(got.Styles); !strings.Contains(s, "neon") || !strings.Contains(s, "glass") {
		t.Errorf("styles: %s", s)
	}
	if s := names(got.Corners); s != "round chamfer" {
		t.Errorf("corners: %s", s)
	}
	if s := names(got.Schemes); s != "both dark light" {
		t.Errorf("schemes: %s", s)
	}
}

// Lowering the veil is not refused, since only a page with a backdrop is,
// but it is said when it is set rather than first heard of at publish.
func TestAWeakVeilIsSaidWhenItIsSet(t *testing.T) {
	root, tpl := designStore(t)
	buf := asMachine(t, false)
	if err := cmdTheme(root, []string{"set", "scrim-strength", "20%", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "a page with a backdrop will not publish") {
		t.Errorf("a veil too weak to read through was set in silence:\n%s", buf.String())
	}
	// A script reading `theme check --json` sees it too, as advice: it
	// refuses only a page with a backdrop, and the exit status does not
	// count it.
	doc := asMachine(t, true)
	if err := cmdTheme(root, []string{"check", "--dir", tpl}); err != nil {
		t.Fatalf("a weak veil failed the whole check: %v", err)
	}
	var findings []theme.Finding
	if err := json.Unmarshal(doc.Bytes(), &findings); err != nil {
		t.Fatalf("%v: %s", err, doc.String())
	}
	over := 0
	for _, f := range findings {
		if strings.Contains(f.Detail, "over a backdrop") {
			over++
			if f.Blocking {
				t.Errorf("the veil is counted as refusing every page: %s", f.Detail)
			}
		}
	}
	if over == 0 {
		t.Errorf("theme check --json does not say the veil is too weak:\n%s", doc.String())
	}
	buf = asMachine(t, false)
	if err := cmdTheme(root, []string{"set", "scrim-strength", "90%", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "backdrop") {
		t.Errorf("a strong veil was reported as weak:\n%s", buf.String())
	}
}

// `section backdrop` refuses, before it writes, what the publish gate would
// refuse later: a recording with sound, and an id the library does not hold.
// An outside address is quoted as typed, not as "/media/https://…".
func TestABackdropTheGateWouldRefuseIsRefusedWhenItIsPut(t *testing.T) {
	root, _ := designStore(t)
	draftOf(t, root, map[string]any{"index": map[string]any{"title": "Home",
		"sections": []any{map[string]any{"features": map[string]any{"title": "Games"}}}}})
	loud := aClip(t, root, true)
	quiet := aClip(t, root, false)

	err := cmdSection(root, []string{"backdrop", "index", "0", loud.ID})
	if err == nil || !strings.Contains(err.Error(), "has sound") {
		t.Errorf("a recording with sound became a backdrop: %v", err)
	}
	missing := strings.Repeat("a", 64)
	if err := cmdSection(root, []string{"backdrop", "index", "0", missing}); err == nil ||
		!strings.Contains(err.Error(), "not in the media library") {
		t.Errorf("an id the library does not hold became a backdrop: %v", err)
	}
	if err := cmdSection(root, []string{"backdrop", "index", "0", "https://example.com/x.png"}); err == nil ||
		strings.Contains(err.Error(), "/media/https") {
		t.Errorf("an outside address was not quoted as typed: %v", err)
	}
	if _, has := draftedPage(t, root, "index")["sections"].([]any)[0].(map[string]any)["features"].(map[string]any)["backdrop_url"]; has {
		t.Error("a refused backdrop was written")
	}
	if err := cmdSection(root, []string{"backdrop", "index", "0", quiet.ID}); err != nil {
		t.Errorf("a silent recording was refused: %v", err)
	}
}

// A recording nothing could listen to is not known to be silent, so it is
// refused as a backdrop with the reason, not with "has sound".
func TestARecordingOfUnknownSoundIsNotABackdrop(t *testing.T) {
	root, _ := designStore(t)
	t.Setenv("PATH", "/nonexistent")
	draftOf(t, root, map[string]any{"index": map[string]any{"title": "Home",
		"sections": []any{map[string]any{"features": map[string]any{"title": "Games"}}}}})
	body := append([]byte{0x1A, 0x45, 0xDF, 0xA3}, []byte("webm")...)
	body = append(body, make([]byte, 2048)...)
	f, err := media.Accept("old.webm", body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := lib.Put(f, body); err != nil {
		t.Fatal(err)
	}
	err = cmdSection(root, []string{"backdrop", "index", "0", "/media/" + f.ID})
	if err == nil || !strings.Contains(err.Error(), "was not recorded") {
		t.Errorf("a recording of unknown sound: %v", err)
	}
}

// Whether a recording has sound is said wherever the library is listed, so
// somebody choosing a backdrop, or an agent writing one into a page, can
// tell which recordings can be one. It was said once, when the file was
// added.
func TestTheLibraryListSaysWhichRecordingsHaveSound(t *testing.T) {
	root, _ := designStore(t)
	loud := aClip(t, root, true)
	aClip(t, root, false)

	buf := asMachine(t, false)
	if err := cmdMedia(root, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"loud.webm · webm", "· has sound", "loop.webm · webm", "· no sound"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("media list does not say %q:\n%s", want, buf.String())
		}
	}

	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	resp := callOp(t, buildMCP(root, s, asAdmin("dana"), "templates"), "quilzo_read", "list_media")
	if resp.Error != nil {
		t.Fatal(resp.Error.Message)
	}
	raw, _ := json.Marshal(resp.Result)
	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &res); err != nil || len(res.Content) == 0 {
		t.Fatalf("list_media answered %s", raw)
	}
	text := res.Content[0].Text
	if !strings.Contains(text, "/media/"+loud.ID+" loud.webm") || !strings.Contains(text, "(has sound)") ||
		!strings.Contains(text, "(no sound)") {
		t.Errorf("list_media does not say which recordings have sound:\n%s", text)
	}
}
