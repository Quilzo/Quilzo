package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/out"
	"github.com/rsh1k/scrivet/internal/schema"
	"github.com/rsh1k/scrivet/internal/site"
)

func cmdTypes(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	rest := args[1:]
	switch args[0] {
	case "list":
		return typesList(root)
	case "add":
		return typesAdd(root, rest)
	case "show":
		return typesShow(root, rest)
	case "bind":
		return typesBind(root, rest)
	case "example":
		return cmdTypeExample(args[1:])
	case "check":
		return typesCheck(root)
	default:
		return fmt.Errorf("unknown type command %q; try list, add, show, bind or check",
			args[0])
	}
}

func typesList(root string) error {
	st, err := schema.Load(root)
	if err != nil {
		return err
	}
	names := st.Registry.Names()

	if w.Mode == out.JSON {
		w.JSON(map[string]any{"types": st.Registry.Types, "bound": st.Bound})
		return nil
	}
	if len(names) == 0 {
		w.Human("no content types\n")
		w.Human("  %sa type is a flat list of fields: no regex, no references, "+
			"no nesting%s\n", dim, reset)
		w.Human("  %sdefine one with: scrivet type add article.json%s\n", dim, reset)
		return nil
	}
	for _, name := range names {
		t, _ := st.Registry.Get(name)
		w.Human("%s%s%s  %s%s%s\n", bold, name, reset, dim, short(schema.Hash(t)), reset)
		for _, f := range t.Fields {
			note := ""
			if f.Required {
				note = " required"
			}
			if len(f.Choices) > 0 {
				note += " (" + strings.Join(f.Choices, ", ") + ")"
			}
			if f.AltFor != "" {
				note += " — alt text for " + f.AltFor
			}
			w.Human("  %-18s %-9s%s%s%s\n", f.Name, f.Kind, dim, note, reset)
		}
		var pages []string
		for page, tn := range st.Bound {
			if tn == name {
				pages = append(pages, page)
			}
		}
		sort.Strings(pages)
		if len(pages) > 0 {
			w.Human("  %sused by: %s%s\n", dim, strings.Join(pages, ", "), reset)
		}
	}
	return nil
}

func typesAdd(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: scrivet type add <definition.json>\n" +
			"  scrivet type example > article.json   writes one you can edit")
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}

	var t schema.Type
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	// Unknown keys are refused rather than dropped. A definition carrying
	// "pattern", "$ref" or "oneOf" is somebody expecting JSON Schema, and
	// silently ignoring those keys hands them a type that validates far less
	// than they believe it does.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return fmt.Errorf("%s: %w\n  this is not JSON Schema. There is no pattern, "+
			"$ref, oneOf or nesting, deliberately: those three keywords are the "+
			"whole published attack surface of schema validators", args[0], err)
	}

	st, err := schema.Load(root)
	if err != nil {
		return err
	}
	if err := st.Registry.Add(t); err != nil {
		return err
	}
	if err := st.Save(); err != nil {
		return err
	}
	// A content type is the gate every write passes through, so changing one
	// changes what every author may store from now on.
	record(root, resolveCaller(root, "").auditRecord("type.add", "/",
		audit.Success, map[string]string{"type": t.Name,
			"fields": fmt.Sprintf("%d", len(t.Fields)),
			"hash":   short(schema.Hash(t))}))
	w.Human("added %s%s%s with %d field(s)  %s%s%s\n",
		bold, t.Name, reset, len(t.Fields), dim, short(schema.Hash(t)), reset)
	return nil
}

func typesShow(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: scrivet type show <name>")
	}
	st, err := schema.Load(root)
	if err != nil {
		return err
	}
	t, ok := st.Registry.Get(args[0])
	if !ok {
		return fmt.Errorf("there is no type %q", args[0])
	}
	if w.JSON(t) {
		return nil
	}
	w.Human("%s%s%s\n", bold, t.Name, reset)
	w.Human("  address %s\n", schema.Hash(t))
	w.Human("  %spublished content records this address, so editing the type "+
		"cannot%s\n", dim, reset)
	w.Human("  %sretroactively invalidate what already passed it%s\n", dim, reset)
	for _, f := range t.Fields {
		w.Human("\n  %s%s%s  %s\n", bold, f.Name, reset, f.Kind)
		if f.Required {
			w.Human("    required\n")
		}
		if f.MaxLen > 0 {
			w.Human("    at most %d characters\n", f.MaxLen)
		}
		if f.Min != nil || f.Max != nil {
			w.Human("    range %s..%s\n", num(f.Min), num(f.Max))
		}
		if len(f.Choices) > 0 {
			w.Human("    one of: %s\n", strings.Join(f.Choices, ", "))
		}
		if f.AltFor != "" {
			w.Human("    alt text for %s — WCAG 1.1.1 depends on it being filled in\n",
				f.AltFor)
		}
		if f.Help != "" {
			w.Human("    %s%s%s\n", dim, f.Help, reset)
		}
	}
	return nil
}

func num(v *float64) string {
	if v == nil {
		return "any"
	}
	return fmt.Sprintf("%g", *v)
}

func typesBind(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("bind", flag.ContinueOnError)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: scrivet type bind <page> <type>")
	}
	page, typeName := pos[0], pos[1]

	st, err := schema.Load(root)
	if err != nil {
		return err
	}
	if err := st.Bind(page, typeName); err != nil {
		return err
	}
	if err := st.Save(); err != nil {
		return err
	}
	w.Human("%s must now satisfy %s\n", page, typeName)

	// Say straight away whether it currently does. A binding whose effect is
	// only felt at the next write is a binding people find out about at the
	// worst moment.
	pages, err := draftPages(root)
	if err != nil {
		return nil
	}
	if body, ok := pages[page]; ok {
		if problems := st.Check(page, body); len(problems) > 0 {
			w.Human("  %sit does not yet:%s\n", yellow, reset)
			for _, p := range problems {
				w.Human("    %s\n", p)
			}
			w.Human("  %sthe next write to this page will be refused until it does%s\n",
				dim, reset)
		}
	}
	return nil
}

func typesCheck(root string) error {
	st, err := schema.Load(root)
	if err != nil {
		return err
	}
	pages, err := draftPages(root)
	if err != nil {
		return err
	}
	failures := st.Gate(pages)

	if w.Mode == out.JSON {
		w.JSON(map[string]any{
			"bound":    len(st.Bound),
			"failures": failures,
			"valid":    len(failures) == 0,
		})
		if len(failures) > 0 {
			return errBlocked{fmt.Errorf("%d page(s) do not satisfy their type",
				len(failures))}
		}
		return nil
	}

	if len(st.Bound) == 0 {
		w.Human("no page is bound to a type\n")
		w.Human("  %sscrivet type bind <page> <type>%s\n", dim, reset)
		return nil
	}
	names := make([]string, 0, len(st.Bound))
	for p := range st.Bound {
		names = append(names, p)
	}
	sort.Strings(names)

	failed := map[string]schema.Failure{}
	for _, f := range failures {
		failed[f.Page] = f
	}
	for _, page := range names {
		f, bad := failed[page]
		if !bad {
			w.Human("  %sok%s     %-18s %s%s%s\n",
				green, reset, page, dim, st.Bound[page], reset)
			continue
		}
		w.Human("  %sfails%s  %-18s %s%s%s\n",
			red, reset, page, dim, st.Bound[page], reset)
		for _, p := range f.Problems {
			w.Human("         %s\n", p)
		}
	}
	if len(failures) > 0 {
		return errBlocked{fmt.Errorf("%d page(s) do not satisfy their type",
			len(failures))}
	}
	return nil
}

func draftPages(root string) (map[string]any, error) {
	s, err := open(root)
	if err != nil {
		return nil, err
	}
	ref := s.GetRef(site.RefDraft)
	if ref == "" {
		ref = s.GetRef(site.RefLive)
	}
	if ref == "" {
		return map[string]any{}, nil
	}
	return site.PagesAt(s, ref)
}

// gateWrite is the check every write path in this binary goes through.
//
// One function, called from `add` and from the MCP write operation, because a
// validation rule that lives in one command is a rule about that command. The
// same object is used by the admin server through a function field, so the web
// UI cannot drift from the CLI either.
func gateWrite(root string, pages map[string]any) (*schema.Store, error) {
	st, err := schema.Load(root)
	if err != nil {
		return nil, err
	}
	failures := st.Gate(pages)
	if len(failures) == 0 {
		st.RecordAll(pages, time.Now())
		return st, nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d page(s) do not satisfy their content type:", len(failures))
	for _, f := range failures {
		fmt.Fprintf(&b, "\n  %s", f)
	}
	return nil, errBlocked{fmt.Errorf("%s", b.String())}
}

// cmdTypeExample prints a definition that works.
//
// Added because a content type could not be discovered from the tool. The
// obvious guess is JSON Schema's vocabulary — "type" for a field's type, "max"
// for a bound — and both are wrong here: the keys are "kind" and "max_len".
// The error said what this is not ("this is not JSON Schema") and never said
// what it is, so the only route to a working definition was reading the Go
// struct tags.
//
// An extensibility feature nobody can use is not an extensibility feature.
func cmdTypeExample(args []string) error {
	name := "article"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name = args[0]
	}
	t := schema.Type{
		Name:        name,
		Description: "A single piece of writing.",
		Fields: []schema.Field{
			{Name: "title", Kind: schema.Text, Required: true, MaxLen: 80,
				Label: "Headline", Help: "Shown in search results and tabs."},
			{Name: "slug", Kind: schema.Slug, Required: true},
			{Name: "published", Kind: schema.Date},
			{Name: "body", Kind: schema.LongText, Required: true, MinLen: 1},
			{Name: "section", Kind: schema.Choice,
				Choices: []string{"news", "opinion", "review"}},
			{Name: "tags", Kind: schema.List, MaxLen: 8},
			{Name: "hero", Kind: schema.URL},
			{Name: "hero_alt", Kind: schema.Text, AltFor: "hero",
				Help: "What the image conveys, for a reader who cannot see it."},
			{Name: "featured", Kind: schema.Boolean},
			{Name: "reading_minutes", Kind: schema.Number},
		},
	}
	if err := schema.Compile(t); err != nil {
		// If this ever fires, the example in the tool has drifted from what
		// the tool accepts, which is worse than having no example.
		return fmt.Errorf("the built-in example no longer compiles: %w", err)
	}
	body, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	// The definition goes to stdout on its own so that `scrivet type example >
	// article.json` produces a file that `scrivet type add` accepts. The
	// guidance goes to stderr for the same reason.
	fmt.Println(string(body))
	fmt.Fprintf(os.Stderr, "\n%severy kind: %s%s\n", dim,
		strings.Join(schema.Kinds(), ", "), reset)
	fmt.Fprintf(os.Stderr, "%sno pattern, $ref, oneOf or nesting, deliberately%s\n",
		dim, reset)
	fmt.Fprintf(os.Stderr, "%sscrivet type example > %s.json && scrivet type "+
		"add %s.json%s\n", dim, name, name, reset)
	return nil
}
