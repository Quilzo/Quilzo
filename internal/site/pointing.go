// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"fmt"

	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/schema"
)

// PointingAt names the things that would break if the page name went away
// from pages: menu entries, pages reusing it as a block, reference fields,
// and a type binding. pages is what remains, so what names a page that is
// going too does not count. menus and types may be nil.
//
// One function for every surface that removes a page. It was the browser's
// own (internal/admin), and `quilzo add --remove` checked only for blocks:
// the browser refused to delete a page the foot menu linked to and the
// terminal deleted it, after which the menu pointed at nothing and every
// publish was refused until somebody re-created the page by hand. Checked
// before the removal rather than caught by the publish gate afterwards,
// because at that point the page is gone, the complaint is about the menu,
// and putting it back means remembering what was in it.
func PointingAt(name string, pages map[string]any, menus *menu.Set, types *schema.Store) []string {
	var out []string

	// Menus, which are the case that produces a 404 for a reader.
	if menus != nil {
		for _, m := range menus.Mentioning(name) {
			out = append(out, fmt.Sprintf("%q in the %q menu", m.Item, m.Menu))
		}
	}

	// Pages that reuse it as a block, which would lose those sections
	// without a word.
	for _, u := range BlockUses(pages)[name] {
		out = append(out, fmt.Sprintf("%q, which reuses it as a block", u))
	}

	if types == nil {
		return out
	}
	// Content references, which are the other way a reader meets a 404, and
	// which schema.Unresolved refuses at the publish gate anyway.
	for _, l := range types.LinksTo(pages, name) {
		out = append(out, fmt.Sprintf("the %q field of %q", l.Field, l.From))
	}
	// A type binding: harmless on its own, and worth clearing so a later
	// page of the same name is not silently bound to something nobody chose.
	if bound, is := types.Bound[name]; is {
		out = append(out, fmt.Sprintf(
			"a binding to the type %q (unbind it on Types, or with quilzo type unbind %s)",
			bound, name))
	}
	return out
}
