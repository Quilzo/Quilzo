// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package theme

import "fmt"

// Schemes a site can be drawn in, and the checks that follow from each.
//
// # Why a site may declare one scheme
//
// A site meant to be dark set each colour once, which applies it to both
// schemes, and `theme check` then listed twenty-three "the same colour in
// both schemes" advisories, one per colour, each correct and none useful.
// Worse was the colour nobody set: it kept its shipped light value, a reader
// whose system asked for light got a dark page with one light-scheme green on
// it, and the check — told the site had two schemes — judged that green
// against the light background it was never drawn on.
//
// So the scheme is a choice. Both is what every site had and stays the
// default. Dark or light means the stylesheet serves that palette to every
// reader, whatever their setting, and the contrast check judges that palette
// and only that one: the scheme it checks is the scheme it serves.

// SchemeChoices are the colour schemes a site can be drawn in, the default
// first.
var SchemeChoices = []string{"both", "dark", "light"}

// SchemeWords says what each scheme choice does, for a screen and the help.
var SchemeWords = map[string]string{
	"both":  "Light or dark, as each reader's system asks. The default.",
	"dark":  "Dark for every reader, whatever their system asks; checked in dark only.",
	"light": "Light for every reader, whatever their system asks; checked in light only.",
}

// Corners are how corners are made, the default first.
var Corners = []string{"round", "chamfer"}

// CornerWords says what each corner choice does.
var CornerWords = map[string]string{
	"round":   "Rounded by the radius. The default.",
	"chamfer": "Cut off at an angle, by the radius. A browser that cannot cut a corner rounds it instead.",
}

// Scheme is the colour scheme a site is drawn in: both, dark or light.
func (t *Theme) Scheme() string {
	if t != nil {
		if v, ok := t.light["scheme"]; ok && contains(SchemeChoices, v) {
			return v
		}
	}
	return "both"
}

// Corner is how the site's corners are made: round or chamfer.
func (t *Theme) Corner() string {
	if t != nil {
		if v, ok := t.light["corner"]; ok && contains(Corners, v) {
			return v
		}
	}
	return "round"
}

type schemeOf struct {
	name string
	dark bool
}

// checkedSchemes are the schemes a reader can be served, which are the ones
// the contrast check judges.
func (t *Theme) checkedSchemes() []schemeOf {
	switch t.Scheme() {
	case "dark":
		return []schemeOf{{"dark", true}}
	case "light":
		return []schemeOf{{"light", false}}
	}
	return []schemeOf{{"light", false}, {"dark", true}}
}

// schemeCSS declares the one scheme a site is drawn in, after the components
// that declare both, so it wins over them for every reader.
func (t *Theme) schemeCSS() string {
	s := t.Scheme()
	if s == "both" {
		return ""
	}
	return fmt.Sprintf("\n/* scheme: %s */\n:root, :root[data-theme=\"light\"], :root[data-theme=\"dark\"] { color-scheme: %s; }\n", s, s)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
