// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/starter"
	"github.com/quilzo/quilzo/internal/theme"
)

// A whole site in a package.
//
// A feature adds blocks to a site. A site package also declares the site
// itself: what it is called, a sentence about it, the layouts it renders
// through and how it looks. That is what lets one package be a whole site,
// drafted by the site builder, read and approved as one decision, taken
// to another installation signed, and taken back.
//
// A site has one name and one look, so the site block is owned by at most
// one installed package. A site somebody set up by hand is a conflict, as a
// page of the same name would be, until they let a package take it over;
// what it was is then kept, and put back when the package goes.

// Site is the site itself.
type Site struct {
	// Name is what the site is called: in its header, its title, and the
	// name an installed copy of it carries.
	Name string `json:"name"`
	// Description is a sentence about it, for search results and the
	// installed app.
	Description string `json:"description,omitempty"`
	// Starter is the layouts the site renders through, written when the
	// site has none yet; a site with layouts of its own keeps them.
	Starter string `json:"starter,omitempty"`
	// Style, Colour and Motion are the look: one of the theme's styles, the
	// colour the palette is generated from, and how much moves.
	Style  string `json:"style,omitempty"`
	Colour string `json:"colour,omitempty"`
	Motion string `json:"motion,omitempty"`
	// Tokens are any other theme tokens, by name, applied after the rest.
	Tokens map[string]string `json:"tokens,omitempty"`
}

// SiteRef is the site block's ref: a site has one.
var SiteRef = Ref{Kind: "site", Name: "site"}

// Bounds on what a site says about itself, which are a header and a
// search result, not prose.
const (
	MaxSiteName        = 80
	MaxSiteDescription = 300
)

// Look is the theme the site block asks for, as token overrides: the
// palette generated from its colour, then its style and motion, then its
// own tokens.
func (s *Site) Look() (map[string]string, error) {
	over := map[string]string{}
	if c := strings.TrimSpace(s.Colour); c != "" {
		gen, err := theme.Generate(c)
		if err != nil {
			return nil, fmt.Errorf("colour %q: %w", c, err)
		}
		for k, v := range gen {
			over[k] = v
		}
	}
	if s.Style != "" {
		over["style"] = s.Style
	}
	if s.Motion != "" {
		over["motion"] = s.Motion
	}
	for k, v := range s.Tokens {
		over[k] = v
	}
	return over, nil
}

// validate holds the site block to what a site's name and look are held
// to anywhere else: a name that renders, a starter that ships, and a theme
// the theme itself accepts, contrast included.
func (s *Site) validate(bad func(string, ...any)) {
	name := strings.TrimSpace(s.Name)
	switch {
	case name == "":
		bad("site: a name is required, because every page prints it")
	case utf8.RuneCountInString(name) > MaxSiteName:
		bad("site: the name is %d characters; at most %d, because it is a header", utf8.RuneCountInString(name), MaxSiteName)
	case !printable(name):
		bad("site: the name has a control character in it")
	}
	if utf8.RuneCountInString(s.Description) > MaxSiteDescription {
		bad("site: the description is longer than %d characters; it is one sentence for a search result", MaxSiteDescription)
	} else if !printable(s.Description) {
		bad("site: the description has a control character in it")
	}
	if s.Starter != "" {
		if _, ok := starter.Get(s.Starter); !ok {
			bad("site: there is no starter called %q; one of %s", s.Starter, strings.Join(starter.Names(), ", "))
		}
	}
	over, err := s.Look()
	if err != nil {
		bad("site: %v", err)
		return
	}
	th, findings := theme.New(over, nil)
	findings = append(findings, th.Check()...)
	var refused []string
	for _, f := range findings {
		if f.Blocking {
			refused = append(refused, f.String())
		}
	}
	sort.Strings(refused)
	for _, r := range refused {
		bad("site: the look is refused: %s", r)
	}
}

// printable is text with no control characters in it.
func printable(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// siteLine is what the card says about the site block.
func (s *Site) siteLine() Line {
	var look []string
	if s.Style != "" {
		look = append(look, "the "+s.Style+" style")
	}
	if s.Colour != "" {
		look = append(look, "a palette from "+s.Colour)
	}
	if s.Motion != "" {
		look = append(look, s.Motion+" motion")
	}
	if n := len(s.Tokens); n > 0 {
		look = append(look, fmt.Sprintf("%d more theme %s", n, map[bool]string{true: "token", false: "tokens"}[n == 1]))
	}
	text := fmt.Sprintf("Names the site %q", strings.TrimSpace(s.Name))
	if len(look) > 0 {
		text += " and sets how it looks: " + strings.Join(look, ", ")
	}
	if s.Starter != "" {
		text += "; its layouts are the " + s.Starter + " starter's when it has none"
	}
	return Line{Text: text}
}
