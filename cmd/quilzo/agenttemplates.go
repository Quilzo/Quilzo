// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// Templates of this store's own: archetypes a person authors, so the
// kinds of agents this program runs are not the ones somebody compiled
// into it.
//
// A template is a starting manifest with a name and a description of when
// to reach for it — the same shape the built-in archetypes have — kept as
// one JSON file per kind beside the agents they make. The rule that keeps
// it safe is the rule the built-ins already follow: a template is the
// narrow answer, the person widens what they need, and every template
// validates as written or it is not kept. A kind nobody compiled is a
// label and not a power: nothing downstream special-cases a kind except
// the supervisor's, and no template may claim that one.
//
// What this is for: the patterns arrive faster than any program can ship
// them — the typed-question deciders arrived that way, and the next one
// will too. With templates in the store, the person who sees the next
// pattern first writes the archetype for it, and `quilzo agent new` knows
// it the same minute.

// templatesDir is where this store's own archetypes live.
func templatesDir(root string) string { return filepath.Join(root, "agenttemplates") }

// reCustomKind is what a person's kind may be called.
var reCustomKind = regexp.MustCompile(agent.CustomKindPattern)

// customTemplateFile is one archetype as it sits on disk.
type customTemplateFile struct {
	Kind    string `json:"kind"`
	Summary string `json:"summary"`
	When    string `json:"when,omitempty"`
	// Research is where the shape came from, in the built-ins' spirit: a
	// claim somebody can check.
	Research string         `json:"research,omitempty"`
	Manifest agent.Manifest `json:"manifest"`
}

// loadCustomTemplates reads this store's archetypes. A file that cannot
// be read or does not validate is an error, not a skip: a template that
// quietly stopped existing would make every agent of its kind
// undeclarable, and the person should know that when it happens.
func loadCustomTemplates(root string) (map[agent.Kind]agent.Template, error) {
	out := map[agent.Kind]agent.Template{}
	entries, err := os.ReadDir(templatesDir(root))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	known := knownCapabilities(root)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(templatesDir(root), e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var f customTemplateFile
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("%s is not a template: %w", path, err)
		}
		t, err := f.template(path, known, out)
		if err != nil {
			return nil, err
		}
		out[agent.Kind(f.Kind)] = t
	}
	return out, nil
}

// template checks one file's archetype and turns it into a Template.
func (f customTemplateFile) template(path string, known map[string]bool, seen map[agent.Kind]agent.Template) (agent.Template, error) {
	kind := agent.Kind(f.Kind)
	fail := func(why string) (agent.Template, error) {
		return agent.Template{}, fmt.Errorf("%s: %s", path, why)
	}
	if !reCustomKind.MatchString(f.Kind) {
		return fail("the kind's name is not one a kind may carry (lowercase letters and dashes)")
	}
	if kind.Valid() {
		return fail(fmt.Sprintf("%q is one of this program's own kinds; its template is here already", f.Kind))
	}
	if _, dup := seen[kind]; dup {
		return fail(fmt.Sprintf("another template in this store already declares %q", f.Kind))
	}
	if strings.TrimSpace(f.Summary) == "" {
		return fail("the template says no summary, and a list with no line is a list nobody chooses from")
	}
	if strings.TrimSpace(f.Manifest.Purpose) == "" {
		return fail("the template's manifest states no purpose")
	}
	// The archetype is validated exactly as an agent's declaration is, with
	// a scratch name and the store's own kinds — a template that has to be
	// edited before it passes is a template that teaches editing until the
	// error stops.
	scratch := f.Manifest
	scratch.Name = "the-" + f.Kind + "-template"
	if err := scratch.ValidateWith(known, map[agent.Kind]bool{kind: true}); err != nil {
		return fail(err.Error())
	}
	if scratch.Kind != kind {
		return fail(fmt.Sprintf("the file declares kind %q and the manifest says %q", f.Kind, scratch.Kind))
	}
	return agent.Template{Summary: f.Summary, When: f.When, Research: f.Research, Manifest: scratch}, nil
}

// customKinds lists this store's kinds, for validation and display.
func customKinds(root string) map[agent.Kind]bool {
	set, err := loadCustomTemplates(root)
	if err != nil {
		return nil
	}
	kinds := map[agent.Kind]bool{}
	for k := range set {
		kinds[k] = true
	}
	return kinds
}

// cmdAgentTemplate is `quilzo agent template list | save FILE | remove KIND`.
func cmdAgentTemplate(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		set, err := loadCustomTemplates(root)
		if err != nil {
			return err
		}
		if len(set) == 0 {
			fmt.Printf("  no templates of this store's own. `quilzo agent template save FILE` declares one —\n")
			fmt.Printf("  a kind, a summary, a starting manifest — and `quilzo agent new NAME --kind KIND` knows it\n")
			return nil
		}
		var kinds []string
		for k := range set {
			kinds = append(kinds, string(k))
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			t := set[agent.Kind(k)]
			fmt.Printf("  %s%-12s%s %s\n", bold, k, reset, t.Summary)
			if t.When != "" {
				fmt.Printf("      %s%s%s\n", dim, indented(t.When, 66, "      "), reset)
			}
			fmt.Printf("      %scapabilities%s %s   %sautonomy%s %s\n", dim, reset,
				strings.Join(t.Manifest.Capabilities, ", "), dim, reset, t.Manifest.Autonomy)
		}
		fmt.Printf("  %sthis store's own, beside the built-ins in `quilzo agent templates`%s\n", dim, reset)
		return nil
	case "save":
		if len(args) != 2 {
			return errors.New("quilzo agent template save FILE")
		}
		return saveCustomTemplate(root, args[1])
	case "remove":
		if len(args) != 2 {
			return errors.New("quilzo agent template remove KIND")
		}
		return removeCustomTemplate(root, args[1])
	}
	return fmt.Errorf("unknown template command %q; try list, save or remove", args[0])
}

func saveCustomTemplate(root, file string) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var f customTemplateFile
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("%s is not a template: %w", file, err)
	}
	caller := resolveCaller(root, "")
	if err := authorise(root, caller, auth.ActGrant, "/agenttemplates"); err != nil {
		return fmt.Errorf("an archetype is the shape of every agent made from it, which is an administrator's decision: %w", err)
	}
	t, err := f.template(file, knownCapabilities(root), nil)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(templatesDir(root), 0o700); err != nil {
		return err
	}
	out, err := json.MarshalIndent(customTemplateFile{Kind: f.Kind, Summary: f.Summary,
		When: f.When, Research: f.Research, Manifest: t.Manifest}, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicfile.Write(filepath.Join(templatesDir(root), f.Kind+".json"), out, 0o600); err != nil {
		return err
	}
	record(root, caller.auditRecord("agent.template", "/agenttemplates/"+f.Kind, audit.Success,
		map[string]string{"kind": f.Kind,
			"capabilities": strings.Join(t.Manifest.Capabilities, " "),
			"autonomy":     string(t.Manifest.Autonomy)}))
	fmt.Printf("  %s%s%s is a kind: `quilzo agent new NAME --kind %s`%s\n", green, f.Kind, reset, f.Kind, reset)
	return nil
}

func removeCustomTemplate(root, kind string) error {
	if !reCustomKind.MatchString(kind) {
		return fmt.Errorf("%q is not a kind a template could carry", kind)
	}
	caller := resolveCaller(root, "")
	if err := authorise(root, caller, auth.ActGrant, "/agenttemplates"); err != nil {
		return err
	}
	path := filepath.Join(templatesDir(root), kind+".json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("there is no template called %s", kind)
	}
	// A kind is only known while its template exists, so agents of it would
	// stop validating and stop running the moment it went.
	using, err := agentsOfKind(root, kind)
	if err != nil {
		return err
	}
	if len(using) > 0 {
		return fmt.Errorf("agents of kind %s are declared (%s); withdraw them first, or they stop running",
			kind, strings.Join(using, ", "))
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	record(root, caller.auditRecord("agent.template", "/agenttemplates/"+kind, audit.Success,
		map[string]string{"kind": kind, "off": "1"}))
	fmt.Printf("  %sthe template is gone%s\n", green, reset)
	return nil
}

// agentsOfKind names the declared agents of one kind, sorted.
func agentsOfKind(root, kind string) ([]string, error) {
	set, err := loadAgents(root)
	if err != nil {
		return nil, err
	}
	var using []string
	for name, m := range set.Agents {
		if string(m.Kind) == kind {
			using = append(using, name)
		}
	}
	sort.Strings(using)
	return using, nil
}
