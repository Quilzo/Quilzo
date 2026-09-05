package theme

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Building a whole palette from one colour somebody chose.
//
// # The problem with picking colours by eye
//
// A theme here is thirty-odd tokens and seventeen contrast pairs, each of
// which is a WCAG requirement the publish gate enforces. Somebody who picks a
// brand colour and then hand-tunes the rest is doing constrained optimisation
// in a colour picker, and the way that ends is a theme that fails the gate, a
// deadline, and a decision to turn the gate off. The gate is not the problem
// in that story; being asked to satisfy it by hand is.
//
// # Correct by construction, not by checking afterwards
//
// So the generator does not produce a palette and hope. It reads the same pair
// table the checker reads, and for each foreground it searches for the
// lightness that meets the required ratio against every background that
// foreground is measured against. Contrast() is the oracle -- the function
// that would later refuse the theme is the one choosing the values.
//
// That inverts the usual failure. A generated theme cannot fail the contrast
// gate unless the pair table and the generator disagree about what the pairs
// are, and they cannot disagree because there is one table.
//
// # What it does not do
//
// It does not have taste. It produces a defensible, legible, tonally coherent
// palette from a hue, which is a different thing from a good one, and the
// tokens remain individually overridable for somebody who does have taste.
// What it removes is the part nobody enjoys and everybody gets wrong.

// Generate builds a full set of colour overrides from one seed colour.
//
// The seed becomes the primary. Everything else is derived: neutrals share the
// seed's hue at very low saturation, so the greys read as belonging to the
// palette rather than as the default grey with a colour bolted on; the
// secondary and tertiary sit at fixed angles from it.
func Generate(seed string) (map[string]string, error) {
	h, s, _, ok := toHSL(seed)
	if !ok {
		return nil, fmt.Errorf(
			"%q is not a colour this can read; it wants a hex value like "+
				"#3b6ea5", seed)
	}
	// A seed with no chroma gives a monochrome palette rather than an error:
	// somebody who asks for grey has asked for something coherent.
	if s < 0.05 {
		s = 0.05
	}

	out := map[string]string{}
	for _, scheme := range []string{"light", "dark"} {
		dark := scheme == "dark"
		// Backgrounds first, because every foreground is chosen against them.
		// Their own lightnesses are fixed: this is the one place a number is
		// picked rather than derived, and it is the page's overall
		// brightness, which is a design decision rather than a contrast one.
		surfaces := map[string]float64{
			"surface":                  pick(dark, 0.975, 0.075),
			"surface-container-lowest": pick(dark, 1.000, 0.055),
			"surface-container-low":    pick(dark, 0.955, 0.105),
			"surface-container":        pick(dark, 0.930, 0.125),
			"surface-container-high":   pick(dark, 0.900, 0.155),
		}
		for name, l := range surfaces {
			out[name+"."+scheme] = fromHSL(h, neutralChroma(s), l)
		}

		// The tonal roles. A container is a wash of its role's hue that the
		// role's own text sits on.
		roles := map[string]float64{
			"primary":   h,
			"secondary": math.Mod(h+40, 360),
			"tertiary":  math.Mod(h+200, 360),
		}
		containerL := pick(dark, 0.885, 0.215)
		for role, hue := range roles {
			out[role+"-container."+scheme] = fromHSL(hue, s*0.55, containerL)
		}

		// The gradient stops, which are backgrounds like any other.
		//
		// Generated rather than left at their defaults, because
		// on-primary-container is measured against them: a palette that
		// derived the hero's text colour and kept somebody else's hero
		// gradient produced text at 3.89:1 on it. The two stops sit at the
		// container's own lightness so the text chosen for the container is
		// the text that works on the gradient.
		out["gradient-from."+scheme] = fromHSL(h, s*0.55, containerL)
		out["gradient-to."+scheme] = fromHSL(roles["secondary"], s*0.55,
			containerL)

		// Every foreground, chosen to satisfy the pairs it appears in.
		//
		// In dependency order, not alphabetical order, and that distinction
		// was a real bug: "primary" is both a foreground against the page and
		// the background that "on-primary" sits on. Generated alphabetically,
		// on-primary was chosen while primary did not yet exist, its one
		// requirement was skipped as an unknown background, and the palette
		// came out with an unreadable button label.
		//
		// So this repeats until nothing more can be produced, and a token
		// whose backgrounds never all arrive is an error rather than a token
		// quietly chosen against fewer constraints than it has.
		fg := foregroundHues(h, roles)
		produced := map[string]bool{}
		for name := range surfaces {
			produced[name] = true
		}
		for r := range roles {
			produced[r+"-container"] = true
		}
		produced["gradient-from"] = true
		produced["gradient-to"] = true
		generates := map[string]bool{}
		for name := range fg {
			generates[name] = true
		}
		for name := range produced {
			generates[name] = true
		}

		for progress := true; progress; {
			progress = false
			names := make([]string, 0, len(fg))
			for name := range fg {
				if !produced[name] {
					names = append(names, name)
				}
			}
			sort.Strings(names)

			for _, name := range names {
				if !ready(name, produced, generates, scheme) {
					continue
				}
				hue, sat := fg[name].hue, fg[name].sat
				need, against := requirementsFor(name, out, scheme)
				if len(against) == 0 {
					// Every pair this token appears in is measured against a
					// colour the generator does not produce. Nothing to
					// satisfy, so it keeps its shipped default.
					produced[name] = true
					progress = true
					continue
				}
				value, found := searchLightness(hue, sat, need, against, dark)
				if !found {
					return nil, fmt.Errorf(
						"no lightness of hue %.0f satisfies %.1f:1 against "+
							"%v; this is a bug in the generator rather than "+
							"a property of the seed", hue, need, against)
				}
				out[name+"."+scheme] = value
				produced[name] = true
				progress = true
			}
		}
		for name := range fg {
			if !produced[name] {
				return nil, fmt.Errorf(
					"%s could not be generated: the tokens it sits on form a "+
						"cycle, so there is no order in which to choose them",
					name)
			}
		}
	}
	return out, nil
}

// role carries the hue and saturation a foreground is drawn from.
type role struct{ hue, sat float64 }

// foregroundHues names every foreground token the pair table mentions.
//
// Read from the table rather than listed, so a pair added later is generated
// for rather than silently left at its default and then failing the gate.
func foregroundHues(h float64, roles map[string]float64) map[string]role {
	out := map[string]role{}
	for _, p := range pairs {
		if _, done := out[p.Foreground]; done {
			continue
		}
		name := p.Foreground
		switch {
		case strings.HasPrefix(name, "on-surface"):
			// Text on the page: the neutral hue, nearly desaturated, so long
			// reading is not tinted.
			out[name] = role{hue: h, sat: 0.06}
		case name == "outline":
			out[name] = role{hue: h, sat: 0.10}
		case name == "focus-ring", name == "primary":
			out[name] = role{hue: h, sat: 0.65}
		case strings.HasPrefix(name, "on-"):
			base := strings.TrimSuffix(strings.TrimPrefix(name, "on-"),
				"-container")
			hue, known := roles[base]
			if !known {
				hue = h
			}
			out[name] = role{hue: hue, sat: 0.55}
		default:
			out[name] = role{hue: h, sat: 0.55}
		}
	}
	return out
}

// ready reports whether every background this token is measured against, that
// the generator itself produces, has already been produced.
//
// The qualifier matters. Some backgrounds -- the gradient stops -- are not
// generated at all, and waiting for them would deadlock. Waiting for the ones
// that are is the whole point: choosing a foreground before its background
// exists silently drops a contrast requirement.
func ready(name string, produced, generates map[string]bool, scheme string) bool {
	for _, p := range pairs {
		if p.Foreground != name {
			continue
		}
		if generates[p.Background] && !produced[p.Background] {
			return false
		}
	}
	return true
}

// requirementsFor returns the strictest ratio this foreground must meet and
// the colours it must meet it against.
func requirementsFor(name string, out map[string]string,
	scheme string) (float64, []string) {

	need := 0.0
	var against []string
	for _, p := range pairs {
		if p.Foreground != name {
			continue
		}
		bg, known := out[p.Background+"."+scheme]
		if !known {
			// A background this generator does not produce -- the gradient
			// stops, which a site sets or leaves at its default. Skipped
			// rather than guessed at: inventing one would put this token's
			// value at the mercy of a colour nobody chose.
			continue
		}
		if p.Min > need {
			need = p.Min
		}
		against = append(against, bg)
	}
	return need, against
}

// searchLightness finds a lightness meeting the ratio against every background.
//
// A scan rather than a binary search, because contrast is not monotonic in
// lightness once several backgrounds are involved -- a value that passes
// against the page can fail against the raised surface, and the passing region
// is not an interval. Two hundred steps over the range is exact enough for
// eight-bit colour and costs nothing at build time.
//
// It walks away from the backgrounds: darker text on a light scheme, lighter
// on a dark one, taking the first value that clears every requirement. That is
// the one nearest the surface, so the palette stays as gentle as the
// requirement allows instead of driving everything to black and white.
func searchLightness(hue, sat, need float64, against []string,
	dark bool) (string, bool) {

	const steps = 200
	for i := 0; i <= steps; i++ {
		frac := float64(i) / steps
		l := frac
		if !dark {
			l = 1 - frac // start light, walk down
		}
		candidate := fromHSL(hue, sat, l)
		ok := true
		for _, bg := range against {
			if Contrast(candidate, bg) < need {
				ok = false
				break
			}
		}
		if ok {
			return candidate, true
		}
	}
	return "", false
}

// neutralChroma keeps a trace of the seed in the greys.
//
// Enough that the surfaces belong to the palette, little enough that a page of
// text is not tinted. A pure grey beside a coloured accent reads as unfinished;
// a grey at the accent's hue reads as chosen.
func neutralChroma(s float64) float64 {
	c := s * 0.08
	if c > 0.05 {
		c = 0.05
	}
	return c
}

func pick(dark bool, light, darkValue float64) float64 {
	if dark {
		return darkValue
	}
	return light
}

// -- colour conversion --------------------------------------------------------
//
// HSL rather than a perceptual space, deliberately. A perceptual model would
// give more even-looking steps, and it would also be several hundred lines of
// matrices in a program whose contrast decisions are made by measurement
// anyway. The generator never relies on HSL lightness meaning anything
// precise: it produces candidates, and Contrast decides.

func toHSL(hex string) (h, s, l float64, ok bool) {
	r, g, b, ok := rgb(hex)
	if !ok {
		return 0, 0, 0, false
	}
	max := math.Max(r, math.Max(g, b))
	min := math.Min(r, math.Min(g, b))
	l = (max + min) / 2
	if max == min {
		return 0, 0, l, true
	}
	d := max - min
	if l > 0.5 {
		s = d / (2 - max - min)
	} else {
		s = d / (max + min)
	}
	switch max {
	case r:
		h = (g - b) / d
		if g < b {
			h += 6
		}
	case g:
		h = (b-r)/d + 2
	default:
		h = (r-g)/d + 4
	}
	return h * 60, s, l, true
}

// HexFromHSL is fromHSL, exported for tests that need to build a seed at a
// known hue. Not part of the theme vocabulary otherwise: a caller with a
// colour has a hex value, not three floats.
func HexFromHSL(h, s, l float64) string { return fromHSL(h, s, l) }

func fromHSL(h, s, l float64) string {
	h = math.Mod(math.Mod(h, 360)+360, 360)
	s = clamp01(s)
	l = clamp01(l)
	c := (1 - math.Abs(2*l-1)) * s
	x := c * (1 - math.Abs(math.Mod(h/60, 2)-1))
	m := l - c/2

	var r, g, b float64
	switch {
	case h < 60:
		r, g, b = c, x, 0
	case h < 120:
		r, g, b = x, c, 0
	case h < 180:
		r, g, b = 0, c, x
	case h < 240:
		r, g, b = 0, x, c
	case h < 300:
		r, g, b = x, 0, c
	default:
		r, g, b = c, 0, x
	}
	return fmt.Sprintf("#%02x%02x%02x",
		round8(r+m), round8(g+m), round8(b+m))
}

func round8(v float64) int {
	n := int(math.Round(clamp01(v) * 255))
	if n < 0 {
		return 0
	}
	if n > 255 {
		return 255
	}
	return n
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
