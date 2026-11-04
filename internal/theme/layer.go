// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package theme

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// A style layer: CSS of a site's own, on top of the generated stylesheet.
//
// # The gap
//
// A site could change every token and nothing else. Anything the tokens
// cannot say — a full-bleed hero, a gradient rule, a hover that lights a card
// — meant templates/site.css, which replaces the generated stylesheet whole:
// the theme stops applying, the component rules where the accessibility work
// lives are gone, and the contrast check stops covering what readers get. The
// one site that needed a single extra rule paid for it with everything.
//
// # The rule it is held to
//
// The one the shipped styles already keep (preset.go): every colour is a
// token, as var(--name), or a mix of tokens with color-mix(). A colour
// written any other way is a colour the contrast check never sees, so it is
// refused — hex, rgb() and its relatives, and the hundred and forty-eight
// colour names. The system colours are allowed only inside a
// forced-colors block, where they are the reader's own palette and the
// point.
//
// And the rest of what keeps the stylesheet the site's own and the page
// readable:
//
//   - url() only to /media/ and /fonts/, this site's own files. A picture
//     from anywhere else is a request to that host on every visit.
//   - No @import, and only the at-rules that arrange rules (@media,
//     @supports, @container, @layer, @keyframes, @scope, @starting-style).
//   - No !important, so the reduced-motion and forced-colours rules, which
//     are !important on purpose, cannot be outvoted.
//   - No redefining a token. --on-surface set to the background colour in a
//     layer would be invisible text the check had passed.
//   - No removing the focus outline.
//   - No backslash escapes, which can spell any word in a way no pattern
//     sees, and no "<", which a stylesheet has no use for.
//   - A rule that sets both a text colour and a background from tokens has
//     that pair held to 4.5:1 in every scheme the site is served in.
//   - At most MaxLayer bytes.
//
// What it cannot see: a colour pair split across two rules, and opacity or a
// filter that fades text after the fact. Those are said in `theme check`
// rather than claimed.

// MaxLayer bounds a style layer. Sixty-four kibibytes is many times the
// shipped styles' layers together, and small enough to read whole.
const MaxLayer = 64 << 10

// LayerFile is where a site's style layer lives, beside its layouts.
const LayerFile = "style.css"

// allowedAtRules are the at-rules a layer may use: the ones that arrange
// rules rather than fetch, declare or define something.
var allowedAtRules = map[string]bool{
	"media": true, "supports": true, "container": true, "layer": true,
	"keyframes": true, "-webkit-keyframes": true, "scope": true, "starting-style": true,
}

// refusedFunctions name another resource, run something or compute a colour
// the check cannot see.
var refusedFunctions = map[string]string{
	"expression":        "runs script in old browsers",
	"image-set":         "names pictures as strings, which the url() rule cannot hold",
	"-webkit-image-set": "names pictures as strings, which the url() rule cannot hold",
	"src":               "names another resource",
	"element":           "paints another part of the page",
	"paint":             "runs a worklet",
	"rgb":               "is a colour the contrast check never sees",
	"rgba":              "is a colour the contrast check never sees",
	"hsl":               "is a colour the contrast check never sees",
	"hsla":              "is a colour the contrast check never sees",
	"hwb":               "is a colour the contrast check never sees",
	"lab":               "is a colour the contrast check never sees",
	"lch":               "is a colour the contrast check never sees",
	"oklab":             "is a colour the contrast check never sees",
	"oklch":             "is a colour the contrast check never sees",
	"color":             "is a colour the contrast check never sees",
	"device-cmyk":       "is a colour the contrast check never sees",
	"contrast-color":    "is a colour the contrast check never sees",
}

// refusedProperties run something.
var refusedProperties = map[string]bool{"behavior": true, "-moz-binding": true, "-ms-behavior": true}

// keywordColours are the colours that are not a value: they say "the same as
// it was" or "none", so no pair can be made worse by them.
var keywordColours = map[string]bool{
	"transparent": true, "currentcolor": true, "inherit": true, "initial": true,
	"unset": true, "revert": true, "revert-layer": true,
}

// systemColours are the reader's own palette, allowed inside forced-colors.
var systemColours = wordSet(`accentcolor accentcolortext activetext buttonborder buttonface
buttontext canvas canvastext field fieldtext graytext highlight highlighttext linktext
mark marktext selecteditem selecteditemtext visitedtext activeborder activecaption
appworkspace background buttonhighlight buttonshadow captiontext inactiveborder
inactivecaption inactivecaptiontext infobackground infotext menu menutext scrollbar
threeddarkshadow threedface threedhighlight threedlightshadow threedshadow window
windowframe windowtext`)

// namedColours are CSS Color 4's named colours.
var namedColours = wordSet(`aliceblue antiquewhite aqua aquamarine azure beige bisque black
blanchedalmond blue blueviolet brown burlywood cadetblue chartreuse chocolate coral
cornflowerblue cornsilk crimson cyan darkblue darkcyan darkgoldenrod darkgray darkgreen
darkgrey darkkhaki darkmagenta darkolivegreen darkorange darkorchid darkred darksalmon
darkseagreen darkslateblue darkslategray darkslategrey darkturquoise darkviolet deeppink
deepskyblue dimgray dimgrey dodgerblue firebrick floralwhite forestgreen fuchsia gainsboro
ghostwhite gold goldenrod gray green greenyellow grey honeydew hotpink indianred indigo
ivory khaki lavender lavenderblush lawngreen lemonchiffon lightblue lightcoral lightcyan
lightgoldenrodyellow lightgray lightgreen lightgrey lightpink lightsalmon lightseagreen
lightskyblue lightslategray lightslategrey lightsteelblue lightyellow lime limegreen linen
magenta maroon mediumaquamarine mediumblue mediumorchid mediumpurple mediumseagreen
mediumslateblue mediumspringgreen mediumturquoise mediumvioletred midnightblue mintcream
mistyrose moccasin navajowhite navy oldlace olive olivedrab orange orangered orchid
palegoldenrod palegreen paleturquoise palevioletred papayawhip peachpuff peru pink plum
powderblue purple rebeccapurple red rosybrown royalblue saddlebrown salmon sandybrown
seagreen seashell sienna silver skyblue slateblue slategray slategrey snow springgreen
steelblue tan teal thistle tomato turquoise violet wheat white whitesmoke yellow
yellowgreen`)

func wordSet(words string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.Fields(words) {
		out[w] = true
	}
	return out
}

// derivedNames are the custom properties the generated stylesheet computes
// from the tokens. A layer may read them and may not redefine them.
var derivedNames = wordSet(`text-sm text-lg text-xl text-2xl text-3xl space-1 space-2 space-3
space-4 space-5 space-6 space-7 space-8 radius-sm radius-md radius-lg radius-xl gradient ease
spring dur`)

var (
	reMediaURL = regexp.MustCompile(`^/media/[0-9a-f]{64}$`)
	reFontURL  = regexp.MustCompile(`^/fonts/[A-Za-z0-9][A-Za-z0-9._-]{0,80}\.woff2?$`)
)

// layerCheck is one pass over a layer.
type layerCheck struct {
	theme    *Theme
	findings []Finding
	declared map[string]bool
	read     map[string]bool
}

func (c *layerCheck) refuse(format string, a ...any) {
	c.findings = append(c.findings, Finding{Token: LayerFile, Blocking: true,
		Detail: fmt.Sprintf(format, a...)})
}

// CheckLayer holds a style layer to the rule the shipped styles keep. The
// theme is the site's, so a colour pair the layer names is judged in the
// schemes the site is served in. Blocking findings mean the layer is not
// served; nothing in it is applied until all of them are fixed.
func CheckLayer(css string, t *Theme) []Finding {
	c := &layerCheck{theme: t, declared: map[string]bool{}, read: map[string]bool{}}
	if len(css) > MaxLayer {
		c.refuse("it is %d bytes, and a style layer may be at most %d. It is a layer over "+
			"a stylesheet, not a second one", len(css), MaxLayer)
		return c.findings
	}
	if !utf8.ValidString(css) || strings.ContainsRune(css, 0) {
		c.refuse("it is not UTF-8 text")
		return c.findings
	}
	if strings.Contains(css, `\`) {
		c.refuse("it has a backslash in it. An escape can spell any word in a way no " +
			"pattern sees — @import written as @\\69mport — so write the character itself")
		return c.findings
	}
	if strings.Contains(css, "<") {
		c.refuse("it has a \"<\" in it, which a stylesheet has no use for and which, put " +
			"inside a page, is how a stylesheet ends its own <style>")
		return c.findings
	}
	body, ok := stripComments(css)
	if !ok {
		c.refuse("a comment is opened with /* and never closed, so everything after it " +
			"would be read as one comment by a browser and as rules by this check")
		return c.findings
	}
	c.rules(body, nil, false, 0)

	var unread []string
	for name := range c.read {
		if !c.declared[name] && !knownProperty(name) {
			unread = append(unread, name)
		}
	}
	sort.Strings(unread)
	for _, name := range unread {
		c.findings = append(c.findings, Finding{Token: LayerFile,
			Detail: fmt.Sprintf("it reads --%s, which neither the theme nor the layer "+
				"defines, so what uses it gets nothing. A typo, perhaps: "+
				"`quilzo theme tokens` lists the names", name)})
	}
	return c.findings
}

// knownProperty is a custom property the generated stylesheet defines.
func knownProperty(name string) bool {
	if _, ok := Lookup(name); ok {
		return true
	}
	return derivedNames[name] || name == "pct"
}

// stripComments removes /* … */, outside strings. False when one is open at
// the end.
func stripComments(s string) (string, bool) {
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			b.WriteByte(ch)
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			b.WriteByte(ch)
			continue
		}
		if ch == '/' && i+1 < len(s) && s[i+1] == '*' {
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return "", false
			}
			i += end + 3
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(ch)
	}
	return b.String(), true
}

// next reads up to the first of ;, { or } outside strings and brackets, and
// says which it was (0 at the end).
func next(s string) (string, byte, string) {
	depth := 0
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '(' || ch == '[':
			depth++
		case (ch == ')' || ch == ']') && depth > 0:
			depth--
		case depth == 0 && (ch == ';' || ch == '{' || ch == '}'):
			return s[:i], ch, s[i+1:]
		}
	}
	return s, 0, ""
}

// block reads a {…} body, s starting just after its {, and returns the body
// and what follows the closing }.
func block(s string) (string, string, bool) {
	depth := 1
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '{':
			depth++
		case ch == '}':
			depth--
			if depth == 0 {
				return s[:i], s[i+1:], true
			}
		}
	}
	return "", "", false
}

// rules reads a list of rules and declarations: the top of the layer, the
// inside of an at-rule, or the inside of a rule with nesting in it.
func (c *layerCheck) rules(s string, selectors []string, forced bool, depth int) {
	if depth > 16 {
		c.refuse("its rules are nested more than sixteen deep")
		return
	}
	decls := map[string]string{}
	defer func() { c.pair(decls, selectors) }()
	for strings.TrimSpace(s) != "" {
		head, stop, rest := next(s)
		head = strings.TrimSpace(head)
		switch stop {
		case '{':
			inner, after, ok := block(rest)
			if !ok {
				c.refuse("a { after %q is never closed", clip(head, 60))
				return
			}
			c.blockRule(head, inner, selectors, forced, depth)
			s = after
		case ';', 0:
			if head != "" {
				if strings.HasPrefix(head, "@") {
					c.statementAtRule(head)
				} else if len(selectors) == 0 {
					c.refuse("%q is a declaration outside any rule", clip(head, 60))
				} else {
					c.declaration(head, selectors, forced)
					if prop, value, found := strings.Cut(head, ":"); found {
						decls[strings.ToLower(strings.TrimSpace(prop))] = strings.TrimSpace(value)
					}
				}
			}
			if stop == 0 {
				return
			}
			s = rest
		case '}':
			c.refuse("there is a } with no { before it, near %q", clip(head, 60))
			return
		}
	}
}

// blockRule is a prelude and its {…}: an at-rule or a style rule.
func (c *layerCheck) blockRule(prelude, inner string, selectors []string, forced bool, depth int) {
	if strings.HasPrefix(prelude, "@") {
		name, cond, _ := strings.Cut(strings.TrimPrefix(prelude, "@"), " ")
		name = strings.ToLower(strings.TrimSpace(name))
		if !allowedAtRules[name] {
			c.refuse("@%s is not something a style layer may use. It may arrange rules "+
				"with @media, @supports, @container, @layer, @keyframes, @scope and "+
				"@starting-style; fonts come from templates/fonts, and @import would "+
				"fetch a stylesheet nothing here has checked", name)
			return
		}
		c.value(cond, "@"+name, false)
		lower := strings.ToLower(strings.ReplaceAll(cond, " ", ""))
		within := forced || name == "media" && strings.Contains(lower, "forced-colors:active")
		if name == "keyframes" || name == "-webkit-keyframes" {
			// The steps are named "from", "to" and percentages; each holds
			// declarations like a rule does.
			c.rules(inner, []string{"@keyframes"}, within, depth+1)
			return
		}
		c.rules(inner, selectors, within, depth+1)
		return
	}
	if prelude == "" {
		c.refuse("a rule has no selector")
		return
	}
	c.rules(inner, append(append([]string(nil), selectors...), prelude), forced, depth+1)
}

func (c *layerCheck) statementAtRule(head string) {
	name, _, _ := strings.Cut(strings.TrimPrefix(head, "@"), " ")
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "layer" {
		return
	}
	c.refuse("@%s is not something a style layer may use; an @import would fetch a "+
		"stylesheet nothing here has checked", name)
}

// declaration checks one property: value.
func (c *layerCheck) declaration(d string, selectors []string, forced bool) {
	prop, value, found := strings.Cut(d, ":")
	if !found {
		c.refuse("%q is not a property and a value", clip(d, 60))
		return
	}
	prop = strings.TrimSpace(prop)
	lower := strings.ToLower(prop)
	value = strings.TrimSpace(value)
	where := strings.Join(selectors, " ")
	if strings.Contains(outsideStrings(value), "!") {
		c.refuse("%s { %s } is marked !important. The reduced-motion and forced-colours "+
			"rules underneath are !important so that nothing outvotes them, and a layer "+
			"wins over everything else by coming last", clip(where, 40), clip(d, 60))
		return
	}
	if refusedProperties[lower] {
		c.refuse("%s runs code in some browsers", prop)
		return
	}
	if name, custom := strings.CutPrefix(prop, "--"); custom {
		if knownProperty(name) {
			c.refuse("it redefines --%s, which the theme owns. A token set here is a "+
				"value the contrast check never sees — set it with `quilzo theme set %s`",
				name, name)
			return
		}
		c.declared[name] = true
	}
	if strings.HasPrefix(lower, "outline") && removesOutline(lower, value) {
		c.refuse("%s { %s } takes away the focus outline, which is how anybody not "+
			"using a mouse knows where they are (WCAG 2.4.7)", clip(where, 40), clip(d, 60))
		return
	}
	c.value(value, prop, forced)
}

// removesOutline is an outline declaration that leaves none to see.
func removesOutline(prop, value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	switch prop {
	case "outline":
		return v == "none" || v == "0" || v == "0px" || strings.HasPrefix(v, "0 ") ||
			strings.HasPrefix(v, "none ") || strings.Contains(v, " none") ||
			strings.Contains(v, "transparent")
	case "outline-style":
		return v == "none" || v == "hidden"
	case "outline-width":
		return v == "0" || v == "0px"
	case "outline-color":
		return v == "transparent"
	}
	return false
}

// value walks one value: its functions, its words and its addresses.
func (c *layerCheck) value(v, prop string, forced bool) {
	for i := 0; i < len(v); {
		ch := v[i]
		switch {
		case ch == '"' || ch == '\'':
			end := strings.IndexByte(v[i+1:], ch)
			if end < 0 {
				c.refuse("a string in %s is never closed", prop)
				return
			}
			i += end + 2
		case ch == '#':
			c.refuse("%s: %s holds a hex colour, which the contrast check never sees. "+
				"Use a token, as var(--primary), or a mix of them with color-mix()",
				prop, clip(v, 60))
			return
		case isIdentStart(ch) || ch == '-' && i+1 < len(v) && (isIdentStart(v[i+1]) || v[i+1] == '-'):
			j := i + 1
			for j < len(v) && isIdentChar(v[j]) {
				j++
			}
			word := v[i:j]
			lw := strings.ToLower(word)
			if j < len(v) && v[j] == '(' {
				if !c.function(lw, v, j, prop) {
					return
				}
				if lw == "url" {
					// The argument was read and judged whole; skip past it.
					if end := strings.IndexByte(v[j:], ')'); end >= 0 {
						j += end + 1
					}
				}
				i = j
				continue
			}
			if !strings.HasPrefix(word, "--") && !keywordColours[lw] {
				if namedColours[lw] {
					c.refuse("%s: %q is a named colour, which the contrast check never "+
						"sees. Use a token, as var(--on-surface), or a mix of them", prop, word)
					return
				}
				if systemColours[lw] && !forced {
					c.refuse("%s: %q is a system colour, which is the reader's own "+
						"palette and belongs inside @media (forced-colors: active)", prop, word)
					return
				}
			}
			i = j
		default:
			i++
		}
	}
	if strings.Contains(strings.ToLower(v), "javascript:") {
		c.refuse("%s names a script", prop)
	}
}

// function checks one function call in a value, at the "(" after its name.
func (c *layerCheck) function(name, v string, open int, prop string) bool {
	if why, refused := refusedFunctions[name]; refused {
		c.refuse("%s uses %s(), which %s. Use a token, as var(--primary), or a mix of "+
			"tokens with color-mix()", prop, name, why)
		return false
	}
	switch name {
	case "url":
		end := strings.IndexByte(v[open:], ')')
		if end < 0 {
			c.refuse("a url( in %s is never closed", prop)
			return false
		}
		arg := strings.TrimSpace(v[open+1 : open+end])
		arg = strings.Trim(arg, `"'`)
		if !reMediaURL.MatchString(arg) && !reFontURL.MatchString(arg) {
			c.refuse("%s: url(%s) is not one of this site's own files. A style layer may "+
				"name /media/ID for a picture in the library and /fonts/NAME.woff2 for a "+
				"typeface the site serves, and nothing on another host", prop, clip(arg, 60))
			return false
		}
	case "var":
		rest := strings.TrimSpace(v[open+1:])
		if name, ok := strings.CutPrefix(rest, "--"); ok {
			j := 0
			for j < len(name) && isIdentChar(name[j]) {
				j++
			}
			c.read[name[:j]] = true
		}
	case "attr":
		rest := v[open+1:]
		end := strings.IndexByte(rest, ')')
		if end < 0 || strings.ContainsAny(strings.TrimSpace(rest[:end]), " ,") {
			c.refuse("%s: attr() may name one attribute and nothing more; a typed attr() "+
				"can turn content into an address", prop)
			return false
		}
	}
	return true
}

// reVarOnly is a value that is one token and nothing else.
var reVarOnly = regexp.MustCompile(`^var\(\s*--([a-z0-9-]+)\s*\)$`)

// pair holds a rule that sets both a text colour and its background from
// tokens to the ratio body text needs, in every scheme the site is served in.
// Every colour in a layer is a token, which keeps it inside the palette; this
// is what keeps it from pairing the palette's text with the palette's text.
func (c *layerCheck) pair(decls map[string]string, selectors []string) {
	fg := reVarOnly.FindStringSubmatch(strings.TrimSpace(decls["color"]))
	bgValue := decls["background-color"]
	if bgValue == "" {
		bgValue = decls["background"]
	}
	bg := reVarOnly.FindStringSubmatch(strings.TrimSpace(bgValue))
	if fg == nil || bg == nil || c.theme == nil {
		return
	}
	ft, okF := Lookup(fg[1])
	bt, okB := Lookup(bg[1])
	if !okF || !okB || ft.Kind != Colour || bt.Kind != Colour {
		return
	}
	for _, scheme := range c.theme.checkedSchemes() {
		ratio := Contrast(c.theme.value(ft, scheme.dark), c.theme.value(bt, scheme.dark))
		if ratio >= 4.5 {
			continue
		}
		c.findings = append(c.findings, Finding{Token: LayerFile, Blocking: true,
			Scheme: scheme.name, Ratio: ratio, Needs: 4.5, Criterion: "WCAG 1.4.3",
			Detail: fmt.Sprintf("%s sets text in --%s on --%s, which is %.2f:1 in the %s "+
				"scheme and needs 4.5:1", clip(strings.Join(selectors, " "), 40),
				fg[1], bg[1], ratio, scheme.name)})
		return
	}
}

// outsideStrings is a value with its quoted strings taken out.
func outsideStrings(v string) string {
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(v); i++ {
		ch := v[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

func isIdentStart(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '_' || ch >= 0x80
}

func isIdentChar(ch byte) bool {
	return isIdentStart(ch) || ch >= '0' && ch <= '9' || ch == '-'
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
