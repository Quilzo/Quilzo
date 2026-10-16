// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evolve

import (
	"fmt"
	"strings"
)

// The evolved region, and the diff grammar that changes it.
//
// # One block, marked
//
// AlphaEvolve marks what may evolve with # EVOLVE-BLOCK-START and
// EVOLVE-BLOCK-END, and the same markers are used here: a program says
// which part of itself is the search's to change, and everything outside
// the markers is fixed — the scaffolding, the output path, whatever the
// operator wrote to make the program runnable and honest. At most one
// block: a first version that evolved several regions at once would be a
// first version whose diffs could not say which region they meant. A
// program with no markers evolves whole, which is right for the small
// programs this starts from.
const (
	BlockStart = "# EVOLVE-BLOCK-START"
	BlockEnd   = "# EVOLVE-BLOCK-END"
)

// ValidateProgram checks a program's shape before anything runs it: within
// the size bound, at most one block, the block closed after it opened.
func ValidateProgram(code []byte) error {
	if len(code) == 0 {
		return fmt.Errorf("the program is empty")
	}
	if len(code) > MaxProgram {
		return fmt.Errorf("the program is %d bytes, and %d is the most", len(code), MaxProgram)
	}
	s := string(code)
	opens, closes := strings.Count(s, BlockStart), strings.Count(s, BlockEnd)
	if opens > 1 || closes > 1 {
		return fmt.Errorf("the program marks %d blocks to evolve, and one is the most", opens)
	}
	if opens != closes {
		return fmt.Errorf("the program opens %d blocks and closes %d", opens, closes)
	}
	if i, j := strings.Index(s, BlockStart), strings.Index(s, BlockEnd); i >= 0 && j >= 0 && j < i {
		return fmt.Errorf("the program closes its block before it opens it")
	}
	return nil
}

// region is where diffs may land: the whole program, or its one block.
type region struct {
	// whole is the full text. inner is the evolvable part, and at is where
	// it sits in whole.
	whole string
	inner string
	at    int
}

func regionOf(code []byte) region {
	whole := string(code)
	i := strings.Index(whole, BlockStart)
	j := strings.Index(whole, BlockEnd)
	if i < 0 || j < 0 || j < i {
		return region{whole: whole, inner: whole, at: 0}
	}
	start := i + len(BlockStart)
	end := j
	return region{whole: whole, inner: whole[start:end], at: start}
}

// Replace swaps the region's content and returns the whole program.
func (r region) Replace(inner string) string {
	return r.whole[:r.at] + inner + r.whole[r.at+len(r.inner):]
}

// A diff in the form the model is asked for, from AlphaEvolve's convention:
// a fence of SEARCH lines, a divider, and REPLACE lines — the searched text
// replaced exactly where it is found. The grammar here is strict on purpose:
// a block that does not parse, or whose search text is not found once and
// exactly once in the region, is refused and the refusal recorded. A loose
// differ that guessed where a patch belonged would be a loose differ whose
// guesses were optimised against.
const (
	diffSearch  = "<<<<<<< SEARCH"
	diffDivide  = "======="
	diffReplace = ">>>>>>> REPLACE"
)

// ParseDiff reads the model's answer into diff blocks.
//
// Everything outside the blocks is ignored: models write prose around their
// code, and the answer's words are not this program's to act on. An
// unterminated block, or a divider with no search before it, is an error —
// the same strictness as the rest of the parse.
func ParseDiff(answer string) ([]Diff, error) {
	var diffs []Diff
	lines := strings.Split(answer, "\n")
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], diffSearch) {
			continue
		}
		var search, replace []string
		i++
		for ; i < len(lines) && lines[i] != diffDivide; i++ {
			if strings.HasPrefix(lines[i], diffReplace) {
				return nil, fmt.Errorf("a diff block has no %s divider", diffDivide)
			}
			search = append(search, lines[i])
		}
		if i >= len(lines) {
			return nil, fmt.Errorf("a diff block opens and never divides")
		}
		i++
		for ; i < len(lines) && !strings.HasPrefix(lines[i], diffReplace); i++ {
			replace = append(replace, lines[i])
		}
		if i >= len(lines) {
			return nil, fmt.Errorf("a diff block divides and never ends")
		}
		s, rep := strings.Join(search, "\n"), strings.Join(replace, "\n")
		if s == "" && rep == "" {
			return nil, fmt.Errorf("a diff block changes nothing")
		}
		diffs = append(diffs, Diff{Search: s, Replace: rep})
	}
	if len(diffs) == 0 {
		return nil, fmt.Errorf("the answer contains no diff block")
	}
	if len(diffs) > 16 {
		return nil, fmt.Errorf("the answer contains %d diff blocks, and 16 is the most", len(diffs))
	}
	return diffs, nil
}

// Diff is one search-and-replace.
type Diff struct {
	Search, Replace string
}

// Apply changes a program by its diffs, in order, and returns the whole
// program with its region replaced.
//
// Each search must appear exactly once in the region as it stands after the
// diffs before it: found twice, the diff could mean either place, and found
// not at all, the model was looking at a program that is not this one. Both
// are errors naming the search text, so the journal says what failed to
// match rather than that something did.
func Apply(r region, diffs []Diff) (string, error) {
	inner := r.inner
	for n, d := range diffs {
		if d.Search == "" {
			return "", fmt.Errorf("diff %d searches for nothing", n+1)
		}
		first := strings.Index(inner, d.Search)
		if first < 0 {
			return "", notFound(d)
		}
		// From one past the first match, not its end: a second occurrence
		// can overlap the first ("aa" twice in "aaa"), and an overlapping
		// match is still a second match.
		if strings.Contains(inner[first+1:], d.Search) {
			return "", fmt.Errorf("diff %d's searched text appears more than once", n+1)
		}
		inner = inner[:first] + d.Replace + inner[first+len(d.Search):]
	}
	return r.Replace(inner), nil
}

// notFound says what a diff searched for, bounded: the journal quotes
// enough to recognise the failure, not the whole model answer again.
func notFound(d Diff) error {
	s := strings.ReplaceAll(d.Search, "\n", "␤")
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return fmt.Errorf("no text matches %q", s)
}
