// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/theme"
)

func designFake(srv *Server, saved map[string]string) {
	srv.DesignSet = &Design{
		Tokens: func() (map[string]string, error) {
			out := map[string]string{}
			for k, v := range saved {
				out[k] = v
			}
			return out, nil
		},
		Save: func(v map[string]string) error {
			for k := range saved {
				delete(saved, k)
			}
			for k, v2 := range v {
				saved[k] = v2
			}
			return nil
		},
	}
}

// A style and a motion are chosen on the screen and saved like any token; a
// palette is made from a colour, a scheme and a contrast level, replaces
// the colours, keeps everything else, and passes the checks.
func TestTheLookIsChosenOnTheDesignScreen(t *testing.T) {
	srv, token := setup(t)
	saved := map[string]string{"radius": "10px", "primary": "#333333", "primary.dark": "#cccccc"}
	designFake(srv, saved)
	page := get(t, srv, "/design", token).Body.String()
	for _, want := range []string{`name="light" value="glass"`, `name="light" value="none"`, `name="scheme" value="vibrant"`, `name="contrast" value="high"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the screen does not offer %s", want)
		}
	}
	postForm(t, srv, "/design/save", token, "token=style&light=glass")
	postForm(t, srv, "/design/save", token, "token=motion&light=expressive")
	if saved["style"] != "glass" || saved["motion"] != "expressive" {
		t.Fatalf("saved %v", saved)
	}
	postForm(t, srv, "/design/save", token, "token=style&light=rainbow")
	if saved["style"] != "glass" {
		t.Error("an unknown style was saved")
	}
	w := postForm(t, srv, "/design/generate", token, "seed=%230b57d0&scheme=vibrant&contrast=high")
	if w.Code >= 400 || saved["primary"] == "#333333" || saved["radius"] != "10px" || saved["style"] != "glass" {
		t.Fatalf("generating: %d %v", w.Code, saved)
	}
	th, problems := theme.New(saved, nil)
	if theme.Blocks(problems) || theme.Blocks(th.Check()) {
		t.Errorf("the generated palette does not pass: %v %v", problems, th.Check())
	}
	fg, _ := th.Value("on-surface", false)
	bg, _ := th.Value("surface", false)
	if theme.Contrast(fg, bg) < 7 {
		t.Errorf("high contrast gave body text at %.2f:1", theme.Contrast(fg, bg))
	}
	before := len(saved)
	postForm(t, srv, "/design/generate", token, "seed=%230b57d0&scheme=rainbow")
	if len(saved) != before {
		t.Error("an unknown scheme changed the palette")
	}
}
