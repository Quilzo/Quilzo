// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"fmt"
	"sort"
	"strings"
)

// Reusable blocks: sections written once and shown on many pages.
//
// A block is a page of the draft marked "block": true. It is saved,
// reviewed, published and rolled back with everything else, and never
// served on its own: no address, no sitemap entry, no search result, no
// chatbot passage of its own. A page reuses it with a section that names
// it,
//
//	{"block": {"page": "footer-cta"}}
//
// and every renderer puts the block's sections where that section is, so
// changing the block changes every page that reuses it, at the next
// publish. One level only: a block that reuses another shows nothing in
// that place, so there is no loop to follow and no depth to bound. A
// reference to a page that is not a block, or to a block for members
// only, shows nothing either: a public page cannot pull in what is not
// meant for it.

// BlockField marks a page as a block.
const BlockField = "block"

// membersField is the public site's members-only flag (internal/public);
// a block carrying it is never shown on a page.
const membersField = "members_only"

// IsBlock reports whether a page is a reusable block.
func IsBlock(body any) bool {
	m, ok := body.(map[string]any)
	if !ok {
		return false
	}
	v, _ := m[BlockField].(bool)
	return v
}

// BlockRef is the block a section reuses, if it is a reference to one: the
// block's name and nothing else but the section's id.
func BlockRef(sec any) (string, bool) {
	m, ok := sec.(map[string]any)
	if !ok {
		return "", false
	}
	for k := range m {
		if k != BlockField && k != "id" {
			return "", false
		}
	}
	ref, ok := m[BlockField].(map[string]any)
	if !ok {
		return "", false
	}
	name, _ := ref["page"].(string)
	return name, name != ""
}

// ExpandBlocks is a page with each reference replaced by the sections of
// the block it names, from pages; used are the blocks it reused, sorted.
// A page with no references is returned as it is, and nothing passed in
// is changed.
func ExpandBlocks(body any, pages map[string]any) (any, []string) {
	m, ok := body.(map[string]any)
	if !ok || IsBlock(body) {
		return body, nil
	}
	sections, ok := m["sections"].([]any)
	if !ok {
		return body, nil
	}
	refs := false
	for _, s := range sections {
		if _, ok := BlockRef(s); ok {
			refs = true
			break
		}
	}
	if !refs {
		return body, nil
	}
	seen := map[string]bool{}
	out := make([]any, 0, len(sections))
	for _, s := range sections {
		name, ok := BlockRef(s)
		if !ok {
			out = append(out, s)
			continue
		}
		inner, ok := blockSections(pages[name])
		if !ok {
			continue
		}
		seen[name] = true
		for _, is := range inner {
			if _, nested := BlockRef(is); !nested {
				out = append(out, is)
			}
		}
	}
	page := make(map[string]any, len(m))
	for k, v := range m {
		page[k] = v
	}
	page["sections"] = out
	used := make([]string, 0, len(seen))
	for n := range seen {
		used = append(used, n)
	}
	sort.Strings(used)
	return page, used
}

// blockSections are a block's sections, when it is one a page may show.
func blockSections(body any) ([]any, bool) {
	if !IsBlock(body) {
		return nil, false
	}
	m := body.(map[string]any)
	if v, _ := m[membersField].(bool); v {
		return nil, false
	}
	s, _ := m["sections"].([]any)
	return s, true
}

// BlockUses are the pages that reuse each block, sorted; a block nothing
// reuses is there with none.
func BlockUses(pages map[string]any) map[string][]string {
	out := map[string][]string{}
	for name, body := range pages {
		if IsBlock(body) {
			if _, ok := out[name]; !ok {
				out[name] = []string{}
			}
			continue
		}
		m, ok := body.(map[string]any)
		if !ok {
			continue
		}
		sections, _ := m["sections"].([]any)
		for _, s := range sections {
			if ref, ok := BlockRef(s); ok {
				out[ref] = appendOnce(out[ref], name)
			}
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

func appendOnce(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// WithBlocks is a set of pages as readers get them: blocks put where pages
// reuse them, and not there on their own. For what reads a site's text
// without rendering it, such as a chatbot's knowledge.
func WithBlocks(pages map[string]any) map[string]any {
	out := make(map[string]any, len(pages))
	for name, body := range pages {
		if IsBlock(body) {
			continue
		}
		out[name], _ = ExpandBlocks(body, pages)
	}
	return out
}

// BlockChange refuses what would leave a page showing nothing it meant to:
// the home page made a block, a block made a page again while pages reuse
// it, a page that reuses blocks made one, a page reusing what is not a
// block. on is whether name is to be a block.
func BlockChange(name string, pages map[string]any, on bool) error {
	body, ok := pages[name]
	if !ok {
		return fmt.Errorf("no page %q", name)
	}
	if !on {
		if uses := BlockUses(pages)[name]; len(uses) > 0 {
			return fmt.Errorf("%s is reused on %s; take it off them first", name, strings.Join(uses, ", "))
		}
		return nil
	}
	if name == "index" {
		return fmt.Errorf("the home page cannot be a block: it is the site's address")
	}
	if _, used := ExpandBlocks(body, pages); len(used) > 0 {
		return fmt.Errorf("%s reuses %s, and a block in a block shows nothing", name, strings.Join(used, ", "))
	}
	return nil
}

// CanReuse refuses a block reused where it would show nothing.
func CanReuse(page, block string, pages map[string]any) error {
	if !IsBlock(pages[block]) {
		return fmt.Errorf("%s is not a block", block)
	}
	if IsBlock(pages[page]) {
		return fmt.Errorf("%s is a block itself, and a block in a block shows nothing", page)
	}
	return nil
}

// Blocks are the names of the blocks among pages, sorted.
func Blocks(pages map[string]any) []string {
	var out []string
	for name, body := range pages {
		if IsBlock(body) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
