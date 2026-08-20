package collab

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Merging two people's work on one draft.
//
// # What compare-and-swap leaves undone
//
// A write declares the commit it was based on, and a write whose base is no
// longer current is refused. That is exact and it never loses anything, which
// is the important half. It is also the whole of what most systems do, and it
// puts the cost on the person who saved second: they are told the draft moved
// and left to redo their work by hand, or to overwrite somebody else's.
//
// Almost none of those refusals are real collisions. Two people editing
// different pages collide on the ref and on nothing else. Two people editing
// the same page usually touch different fields — one writes the body, the
// other fixes the title. A system that refuses all of it teaches people to
// retry without reading, which is how the real collisions get overwritten too.
//
// # Why this is the honest version of "real-time collaboration"
//
// The feature people mean by that phrase is two cursors in one document, and
// it is JavaScript by construction: an editor, a transport, and a CRDT or an
// operational transform running in the browser. None of that can exist here.
//
// What people actually need from it can. Two people working on one site at the
// same time should both keep their work, and should be told plainly when they
// genuinely disagree. That is a three-way merge, it runs on the server, it
// needs no script, and it is exact rather than eventually-consistent.
//
// # The rule that decides every case
//
// Never resolve a disagreement by picking a side. A merge may take a change
// only when the other side did not make one, or when both sides made the same
// one. Anything else is reported, not decided.
//
// That rule is what makes this safe to run automatically. A merge that guessed
// would be a merge somebody has to audit, and nobody audits a merge that says
// it succeeded.

// Merged is the result of a three-way merge.
type Merged struct {
	// Pages is the merged draft. Complete and ready to write when Clean is
	// true; when it is false this holds the merge as far as it got, with the
	// conflicting fields left at the value the current draft has.
	Pages map[string]any
	// TookMine and TookTheirs name what came from each side, as "page.field"
	// or just "page" when a whole page came from one side. Reported so the
	// person can see what happened rather than being told it worked.
	TookMine   []string
	TookTheirs []string
	// Conflicts are the genuine disagreements: both sides changed the same
	// thing to different values. Never resolved automatically.
	Conflicts []FieldConflict
}

// Clean reports whether the merge resolved everything.
func (m Merged) Clean() bool { return len(m.Conflicts) == 0 }

// FieldConflict is one thing two people changed differently.
type FieldConflict struct {
	// Page and Field name it. Field is empty when the disagreement is about
	// the page itself — one side deleted it and the other changed it.
	Page  string
	Field string
	// Base, Mine and Theirs are the three values, so a person deciding can see
	// all of them rather than being told the names of two.
	Base   any
	Mine   any
	Theirs any
	// Why says what kind of disagreement this is, in words somebody can act on.
	Why string
}

func (f FieldConflict) String() string {
	where := f.Page
	if f.Field != "" {
		where += "." + f.Field
	}
	return where + ": " + f.Why
}

// Merge combines two sets of changes to one base.
//
// `mine` is the draft the writer built from `base`; `theirs` is what the draft
// actually became while they worked. The result keeps every change either side
// made, except where they made different ones to the same field.
//
// Deletion is never silent. A page one side removed and the other edited is a
// conflict, because "they deleted it" and "I was writing it" are not the same
// claim and no rule can tell which was meant.
func Merge(base, mine, theirs map[string]any) Merged {
	out := Merged{Pages: map[string]any{}}

	names := map[string]bool{}
	for _, m := range []map[string]any{base, mine, theirs} {
		for n := range m {
			names[n] = true
		}
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)

	for _, name := range sorted {
		b, inBase := base[name]
		m, inMine := mine[name]
		th, inTheirs := theirs[name]

		mineChanged := !inBase && inMine || inBase && !inMine ||
			inBase && inMine && !reflect.DeepEqual(b, m)
		theirsChanged := !inBase && inTheirs || inBase && !inTheirs ||
			inBase && inTheirs && !reflect.DeepEqual(b, th)

		switch {
		case !mineChanged && !theirsChanged:
			// Untouched by both. Present in the result only if it was there.
			if inBase {
				out.Pages[name] = b
			}

		case mineChanged && !theirsChanged:
			if inMine {
				out.Pages[name] = m
				out.TookMine = append(out.TookMine, name)
			} else {
				out.TookMine = append(out.TookMine, name+" (removed)")
			}

		case !mineChanged && theirsChanged:
			if inTheirs {
				out.Pages[name] = th
				out.TookTheirs = append(out.TookTheirs, name)
			} else {
				out.TookTheirs = append(out.TookTheirs, name+" (removed)")
			}

		default:
			// Both changed it. Same change is agreement, not conflict.
			if reflect.DeepEqual(m, th) {
				if inMine {
					out.Pages[name] = m
				}
				continue
			}
			// One side removed the page and the other changed it. No rule can
			// say which was meant, so neither is applied and the page stays as
			// the current draft has it.
			if !inMine || !inTheirs {
				gone, kept := "you removed", "they changed"
				if !inTheirs {
					gone, kept = "they removed", "you changed"
				}
				if inTheirs {
					out.Pages[name] = th
				}
				out.Conflicts = append(out.Conflicts, FieldConflict{
					Page: name, Base: b, Mine: m, Theirs: th,
					Why: gone + " this page and " + kept + " it. Removing a " +
						"page somebody is writing is not a merge either way, " +
						"so nothing was applied.",
				})
				continue
			}
			mergePage(name, b, m, th, &out)
		}
	}
	return out
}

// mergePage descends into a page both sides changed.
func mergePage(name string, b, m, th any, out *Merged) {
	bf, bok := b.(map[string]any)
	mf, mok := m.(map[string]any)
	tf, tok := th.(map[string]any)
	if !mok || !tok {
		// A page that is not an object on one side. Nothing to descend into,
		// and picking one would be picking a side.
		out.Pages[name] = th
		out.Conflicts = append(out.Conflicts, FieldConflict{
			Page: name, Base: b, Mine: m, Theirs: th,
			Why: "both changed this page and at least one version is not an " +
				"object, so there are no fields to merge",
		})
		return
	}
	if !bok {
		bf = map[string]any{}
	}

	merged := map[string]any{}
	keys := map[string]bool{}
	for _, f := range []map[string]any{bf, mf, tf} {
		for k := range f {
			keys[k] = true
		}
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	for _, k := range sorted {
		bv, inBase := bf[k]
		mv, inMine := mf[k]
		tv, inTheirs := tf[k]

		mineChanged := inMine != inBase || inMine && !reflect.DeepEqual(bv, mv)
		theirsChanged := inTheirs != inBase || inTheirs && !reflect.DeepEqual(bv, tv)

		switch {
		case !mineChanged && !theirsChanged:
			if inBase {
				merged[k] = bv
			}
		case mineChanged && !theirsChanged:
			if inMine {
				merged[k] = mv
			}
			out.TookMine = append(out.TookMine, name+"."+k)
		case !mineChanged && theirsChanged:
			if inTheirs {
				merged[k] = tv
			}
			out.TookTheirs = append(out.TookTheirs, name+"."+k)
		default:
			if reflect.DeepEqual(mv, tv) {
				if inMine {
					merged[k] = mv
				}
				continue
			}
			// A real disagreement. The current draft's value is kept, so the
			// merged result is never a value nobody wrote.
			if inTheirs {
				merged[k] = tv
			}

			out.Conflicts = append(out.Conflicts, FieldConflict{
				Page: name, Field: k, Base: bv, Mine: mv, Theirs: tv,
				Why: describe(inBase, inMine, inTheirs),
			})
		}
	}
	out.Pages[name] = merged
}

func describe(inBase, inMine, inTheirs bool) string {
	switch {
	case !inMine:
		return "you removed this field and they changed it"
	case !inTheirs:
		return "they removed this field and you changed it"
	case !inBase:
		return "you both added this field, with different values"
	}
	return "you both changed this field, to different values"
}

// Summary describes a merge in one paragraph somebody can act on.
func (m Merged) Summary() string {
	var b strings.Builder
	if m.Clean() {
		fmt.Fprintf(&b, "merged cleanly: %d change(s) of yours and %d of "+
			"theirs, none in the same place",
			len(m.TookMine), len(m.TookTheirs))
		return b.String()
	}
	fmt.Fprintf(&b, "%d thing(s) need a decision", len(m.Conflicts))
	for _, c := range m.Conflicts {
		fmt.Fprintf(&b, "\n  %s", c)
	}
	fmt.Fprintf(&b, "\n\n  everything else merged: %d change(s) of yours and "+
		"%d of theirs.\n  Nothing was overwritten — the draft still has "+
		"their version of\n  each disagreement, so no work is lost either way.",
		len(m.TookMine), len(m.TookTheirs))
	return b.String()
}
