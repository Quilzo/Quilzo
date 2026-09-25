// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/quilzo/quilzo/internal/baseline"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Stacking: sort by how rare a thing is and read the top.
//
// The oldest technique in security analysis and the one that keeps earning its
// place, because malicious activity is rare by definition and rarity here is
// absolute — within whatever data exists — rather than relative to a peer
// group. That is exactly why it works at a size where peer comparison does
// not: a ten-person company has no peers for a role, and it still has a
// rarest user agent.
//
// No model, no baselining period, no cold start. A hash map and a sort, and
// every number it prints is one somebody can check by counting.

func cmdHunt(root string, args []string) error {
	fs := flag.NewFlagSet("hunt", flag.ContinueOnError)
	field := fs.String("field", "", "the field to stack, e.g. raw.user_agent")
	by := fs.String("by", "", "count per entity: actor, device or target")
	top := fs.Int("top", 20, "how many of the rarest to show")
	rest, err := eventFileArgs(fs, args)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*field) == "" {
		return fmt.Errorf(
			"usage: quilzo hunt --field FIELD [--by actor] [FILE]\n" +
				"  quilzo telemetry fields FILE lists what a file carries")
	}

	in := os.Stdin
	if len(rest) > 0 && rest[0] != "-" {
		f, err := os.Open(rest[0])
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}

	pop := baseline.NewPopulation()
	whole := baseline.NewProfile("everything")
	// Not named dim: that is the package-level escape code for dim text,
	// and shadowing it printed the field name where the colour belonged.
	stack := baseline.Dimension(*field)

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), MaxTelemetryLine)
	var read, used int
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		read++
		var e telemetry.Event
		if err := json.Unmarshal([]byte(text), &e); err != nil {
			return fmt.Errorf("line %d is not an event: %w", line, err)
		}
		if err := e.Validate(); err != nil {
			// Refused rather than skipped. A hunt that quietly drops the
			// events it could not read reports a rarity computed over an
			// unknown fraction of the data, which is worse than no answer:
			// the rarest value might be rare because most of the file was
			// discarded.
			return fmt.Errorf("line %d cannot be used: %w", line, err)
		}
		value, present := e.Fields()[*field]
		if !present {
			continue
		}
		used++
		whole.Observe(stack, value, e.Time)
		if *by != "" {
			entity, ok := e.Fields()[*by]
			if !ok {
				continue
			}
			pop.For(entity).Observe(stack, value, e.Time)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading: %w", err)
	}
	if used == 0 {
		return fmt.Errorf(
			"none of the %d event(s) carries %s. A field the data does not "+
				"have is the commonest reason an analysis returns nothing "+
				"and reads as a clean result", read, *field)
	}

	counts := whole.Values(stack)
	if len(counts) > *top {
		counts = counts[:*top]
	}
	if w.JSON(map[string]any{
		"field": *field, "events": used, "distinct": len(whole.Values(stack)),
		"rarest": counts, "entities": pop.Size(),
	}) {
		return nil
	}

	w.Human("%s%s%s across %d event(s), %d distinct value(s)\n",
		bold, *field, reset, used, len(whole.Values(stack)))
	for _, c := range counts {
		w.Human("  %6d  %s\n", c.Seen, c.Value)
	}
	if *by == "" {
		return nil
	}

	w.Human("\n%sper %s%s\n", bold, *by, reset)
	if pop.Size() < 50 {
		// Said rather than silently skipped. A comparison against eleven
		// people is not a peer comparison, and printing one would read as
		// evidence while being noise.
		w.Human("  %s%d %s(s) seen, and a peer comparison needs at least 50. "+
			"The counts above are the answer at this size, and they are a "+
			"real one%s\n", dim, pop.Size(), *by, reset)
		return nil
	}
	rare := pop.Rare(stack, 2)
	if len(rare) == 0 {
		w.Human("  %severy value is held by more than two %ss%s\n",
			dim, *by, reset)
		return nil
	}
	for _, c := range rare {
		w.Human("  %6d %s(s)  %s\n", c.Seen, *by, c.Value)
	}
	return nil
}
