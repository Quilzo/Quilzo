// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/source"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// One person, several identifiers.
//
// Okta knows Dana as 00u1a2b3, Entra as a GUID, GitHub as dana-gh, and a
// correlation across the three has nothing to group by: the same person is
// three strangers. What they have in common is an address, and most
// platforms' logs carry it beside their own identifier.
//
// So each event keeps the platform's identifier as its actor — it is the
// one that does not change — and carries the person's address as well,
// where the platform gave one. The pairing is remembered, so a later event
// from the same identifier that arrives without an address still gets it.
// For a platform that never gives one (GitHub knows a login, not an
// address) a person says who it is, once: `quilzo identity link`.
//
// A link somebody made is never overwritten by one that was learned.

// alias is what one identifier is known to be.
type alias struct {
	Person string `json:"person"`
	// How is "learned" from an event or "linked" by a person.
	How string    `json:"how"`
	By  string    `json:"by,omitempty"`
	At  time.Time `json:"at"`
}

// MaxAliases bounds how many identifiers are remembered.
const MaxAliases = 200_000

func aliasesPath(root string) string {
	return filepath.Join(root, "identity", "aliases.json")
}

func loadAliases(root string) (map[string]alias, error) {
	out := map[string]alias{}
	b, err := os.ReadFile(aliasesPath(root))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	return out, json.Unmarshal(b, &out)
}

func saveAliases(root string, a map[string]alias) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(aliasesPath(root)), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(aliasesPath(root), b, 0o600)
}

// personOf gives an event its person: the one it arrived with, which is
// remembered, or the one its identifier is known by. It reports whether the
// table changed.
func personOf(e *telemetry.Event, aliases map[string]alias, now time.Time) bool {
	if e.Actor.Zero() {
		return false
	}
	id := e.Actor.String()
	known, have := aliases[id]
	if p := e.Raw[source.PersonField]; p != "" {
		if have && (known.How == "linked" || known.Person == p) {
			if known.How == "linked" {
				// What a person said stands, on the event too.
				e.Raw[source.PersonField] = known.Person
			}
			return false
		}
		if !have && len(aliases) >= MaxAliases {
			return false
		}
		aliases[id] = alias{Person: p, How: "learned", At: now}
		return true
	}
	if have {
		if e.Raw == nil {
			e.Raw = map[string]string{}
		}
		e.Raw[source.PersonField] = known.Person
	}
	return false
}

func cmdIdentity(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return identityList(root)
	case "link", "unlink":
		caller := resolveCaller(root, flagToken)
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return err
		}
		if caller.Kind == audit.KindAI {
			return fmt.Errorf("who an identifier belongs to is said by a " +
				"person. A model that could say it could make one person's " +
				"activity count as another's")
		}
		aliases, err := loadAliases(root)
		if err != nil {
			return err
		}
		if args[0] == "unlink" {
			if len(args) != 2 {
				return fmt.Errorf("usage: quilzo identity unlink ISSUER:VALUE")
			}
			if _, ok := aliases[args[1]]; !ok {
				return fmt.Errorf("%s is not linked to anybody", args[1])
			}
			delete(aliases, args[1])
		} else {
			if len(args) != 3 {
				return fmt.Errorf("usage: quilzo identity link ISSUER:VALUE " +
					"PERSON@EXAMPLE.COM")
			}
			issuer, value, ok := strings.Cut(args[1], ":")
			person := strings.ToLower(strings.TrimSpace(args[2]))
			if !ok || issuer == "" || value == "" || len(args[1]) > 512 {
				return fmt.Errorf("an identifier is issuer:value, as github:dana-gh")
			}
			if !strings.Contains(person, "@") || strings.ContainsAny(person, " \t\r\n") ||
				len(person) > 254 {
				return fmt.Errorf("a person is named by their address")
			}
			aliases[args[1]] = alias{Person: person, How: "linked",
				By: caller.Name, At: time.Now().UTC()}
		}
		if err := saveAliases(root, aliases); err != nil {
			return err
		}
		record(root, audit.Record{Action: "identity." + args[0],
			Resource: "/identity", Outcome: audit.Success,
			Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
			Detail: map[string]string{"subject": args[1]}})
		if !w.JSON(map[string]any{args[0]: args[1]}) {
			w.Human("%s %s\n", args[0]+"ed", args[1])
		}
		return nil
	default:
		return fmt.Errorf("unknown identity command %q; try list, link or "+
			"unlink", args[0])
	}
}

// peopleOf turns the table round: each person and the identifiers known to
// be theirs.
func peopleOf(aliases map[string]alias) map[string][]string {
	out := map[string][]string{}
	for id, a := range aliases {
		out[a.Person] = append(out[a.Person], id)
	}
	for p := range out {
		sort.Strings(out[p])
	}
	return out
}

func identityList(root string) error {
	aliases, err := loadAliases(root)
	if err != nil {
		return err
	}
	people := peopleOf(aliases)
	if w.JSON(map[string]any{"people": len(people), "identifiers": len(aliases)}) {
		return nil
	}
	if len(aliases) == 0 {
		w.Human("Nobody is known yet. Identifiers are learned as events " +
			"are collected; quilzo identity link adds one by hand.\n")
		return nil
	}
	several := 0
	for _, ids := range people {
		if len(ids) > 1 {
			several++
		}
	}
	w.Human("%s%d identifier(s) of %d person(s)%s; %d known on more than "+
		"one platform\n", bold, len(aliases), len(people), reset, several)
	names := make([]string, 0, len(people))
	for p := range people {
		names = append(names, p)
	}
	sort.Strings(names)
	for n, p := range names {
		if n == 40 {
			w.Human("  %s%d more%s\n", dim, len(names)-40, reset)
			break
		}
		w.Human("  %s%s%s  %s%s%s\n", bold, p, reset, dim,
			strings.Join(people[p], ", "), reset)
	}
	return nil
}
