// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package render

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/icons"
	"github.com/quilzo/quilzo/internal/tmpl"
)

func TestAnIconAPageNamesIsDrawnInTheThemesStyle(t *testing.T) {
	body := map[string]any{"title": "Home", "sections": []any{map[string]any{"features": map[string]any{
		"items": []any{
			map[string]any{"icon": "bolt", "title": "Fast"},
			map[string]any{"icon": "no-such-icon", "title": "Odd"},
			map[string]any{"icon": `bolt"><script>`, "title": "Hostile"},
		}}}}}
	ctx, err := Sources{Name: "S", IconStyle: "sharp-filled"}.For("index", body, nil)
	if err != nil {
		t.Fatal(err)
	}
	items := ctx["page"].(map[string]any)["sections"].([]any)[0].(map[string]any)["features"].(map[string]any)["items"].([]any)
	got, ok := items[0].(map[string]any)["icon_svg"].(tmpl.Markup)
	if !ok || string(got) != icons.SVG("bolt", "sharp-filled") {
		t.Errorf("bolt drew %q", got)
	}
	for _, i := range []int{1, 2} {
		if _, drawn := items[i].(map[string]any)["icon_svg"]; drawn {
			t.Errorf("item %d drew an icon", i)
		}
	}
	// The stored page is not changed by being rendered.
	if _, touched := body["sections"].([]any)[0].(map[string]any)["features"].(map[string]any)["items"].([]any)[0].(map[string]any)["icon_svg"]; touched {
		t.Error("rendering wrote into the stored content")
	}
	// Markup where markup belongs, text everywhere else.
	out, err := tmpl.Render(`{% for f in page.sections %}{% for i in f.features.items %}<span>{{ i.icon_svg }}</span><a title="{{ i.icon_svg }}"></a>{% end %}{% end %}`, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "<span><svg class=\"icon\"") || strings.Contains(out, `title="<svg`) {
		t.Errorf("rendered %s", out)
	}
}
