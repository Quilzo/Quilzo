package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/ext"
)

func extPath(root string) string { return filepath.Join(root, "extensions.json") }

type extFile struct {
	Extensions []ext.Manifest `json:"extensions"`
}

func loadExts(root string) (*extFile, error) {
	var f extFile
	body, err := os.ReadFile(extPath(root))
	if os.IsNotExist(err) {
		return &f, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", extPath(root), err)
	}
	// Validated at load. An unusable manifest discovered at publish time is
	// discovered in the middle of somebody's work.
	for _, m := range f.Extensions {
		if err := m.Validate(); err != nil {
			return nil, err
		}
	}
	return &f, nil
}

func saveExts(root string, f *extFile) error {
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(extPath(root), append(body, '\n'), 0o600)
}

// extLimits reads the runner's bounds from configuration.
func extLimits(c *config.Config) ext.Limits {
	return ext.Limits{
		Timeout:    c.Dur("ext.timeout"),
		MaxOutput:  c.Int("ext.max_output_bytes"),
		RequirePin: c.Bool("ext.require_pinned"),
	}
}

// runExtensions calls every extension registered for a hook.
//
// Returns a refusal if any extension refuses, and the transformed fields if
// any transformed. An extension that fails is recorded and skipped: it is not
// permitted to take a publish down by crashing, because the alternative is
// that installing a flaky extension makes the CMS flaky.
func runExtensions(root string, hook ext.Hook, page string,
	fields map[string]any) (map[string]any, error) {

	cfg, err := loadConfig(root)
	if err != nil || !cfg.Bool("ext.enabled") {
		return fields, nil
	}
	list, err := loadExts(root)
	if err != nil {
		return fields, err
	}

	runner := &ext.Runner{Limits: extLimits(cfg)}
	out := fields
	for _, m := range list.Extensions {
		if !runsOn(m, hook) {
			continue
		}
		res := runner.Run(context.Background(), m,
			ext.Request{Hook: hook, Page: page, Fields: out})

		if res.Err != nil {
			// Recorded as denied, because an extension that was meant to
			// validate and did not run is a check that did not happen — which
			// the log should not show as a success.
			record(root, audit.Record{
				Action: "ext.failed", Resource: "/" + page,
				Outcome: audit.Denied, Principal: m.Name,
				Kind: audit.KindService, Verified: true,
				Detail: map[string]string{"error": res.Err.Error(),
					"hook": string(hook)},
			})
			// And the write is refused, for the same reason the accessibility
			// gate refuses when it cannot run: a check that could not run must
			// not exit like a check that passed.
			//
			// Found by swapping an extension's binary on disk. The pin
			// correctly refused to run it — and the page was stored anyway, so
			// replacing a validation extension with anything unrunnable was a
			// way to switch the validation off silently.
			//
			// Advisory hooks continue, and so does anything the operator
			// marked optional. That flag exists because "a flaky extension
			// makes the CMS flaky" is a real objection, and it is a decision
			// to make per extension with eyes open rather than a default that
			// quietly weakens every one of them.
			if !m.Optional && hook != ext.OnPublish {
				return out, errBlocked{fmt.Errorf(
					"%s could not run, so %s was not checked: %v\n"+
						"  Fix it, mark it optional if it is advisory, or "+
						"remove it:\n    quilzo ext remove %s",
					m.Name, page, res.Err, m.Name)}
			}
			fmt.Fprintf(os.Stderr, "  %s%s did not run: %v%s\n",
				yellow, m.Name, res.Err, reset)
			continue
		}
		if len(res.Dropped) > 0 {
			fmt.Fprintf(os.Stderr, "  %s%s returned undeclared field(s): %s%s\n",
				yellow, m.Name, strings.Join(res.Dropped, ", "), reset)
		}
		if res.Response.Refuse {
			record(root, audit.Record{
				Action: "ext.refused", Resource: "/" + page,
				Outcome: audit.Denied, Principal: m.Name,
				Kind: audit.KindService, Verified: true,
				Detail: map[string]string{"reason": res.Response.Reason},
			})
			return out, errBlocked{fmt.Errorf("%s refused %s: %s",
				m.Name, page, res.Response.Reason)}
		}
		if len(res.Response.Fields) > 0 && hook == ext.OnTransform {
			// Copied rather than mutated, so an extension cannot change the
			// map another extension already saw.
			next := map[string]any{}
			for k, v := range out {
				next[k] = v
			}
			for k, v := range res.Response.Fields {
				next[k] = v
			}
			out = next
		}
	}
	return out, nil
}

func runsOn(m ext.Manifest, hook ext.Hook) bool {
	for _, h := range m.Hooks {
		if h == hook {
			return true
		}
	}
	return false
}

func cmdExt(root string, args []string) error {
	if len(args) == 0 {
		return extList(root)
	}
	switch args[0] {
	case "list":
		return extList(root)
	case "add":
		return extAdd(root, args[1:])
	case "remove":
		return extRemove(root, args[1:])
	case "pin":
		return extPin(root, args[1:])
	case "test":
		return extTest(root, args[1:])
	default:
		return fmt.Errorf("unknown ext command %q; try list, add, remove, "+
			"pin or test", args[0])
	}
}

func extList(root string) error {
	f, err := loadExts(root)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{
		"enabled": cfg.Bool("ext.enabled"), "extensions": f.Extensions,
	}) {
		return nil
	}
	if len(f.Extensions) == 0 {
		w.Human("no extensions\n")
		w.Human("  %san extension is a program that sees the fields it "+
			"declares and nothing else%s\n", dim, reset)
		w.Human("  %squilzo ext add NAME --command /path/to/it --on validate "+
			"--fields title,body%s\n", dim, reset)
		return nil
	}
	if !cfg.Bool("ext.enabled") {
		w.Human("  %s%d registered, and ext.enabled is false so none of them "+
			"run%s\n", yellow, len(f.Extensions), reset)
	}
	for _, m := range f.Extensions {
		hooks := make([]string, 0, len(m.Hooks))
		for _, h := range m.Hooks {
			hooks = append(hooks, string(h))
		}
		w.Human("%s%-18s%s %s\n", bold, m.Name, reset, m.Description)
		w.Human("  %son %s · sees %s%s\n", dim, strings.Join(hooks, ", "),
			fieldList(m.Fields), reset)
		w.Human("  %s%s%s\n", dim, strings.Join(m.Command, " "), reset)
		if m.SHA256 == "" {
			w.Human("  %sunpinned: the binary on disk can be swapped without "+
				"anybody being told%s\n", yellow, reset)
		} else {
			w.Human("  %spinned %s%s\n", dim, m.SHA256[:12], reset)
		}
	}
	return nil
}

func fieldList(f []string) string {
	if len(f) == 0 {
		return "no fields"
	}
	return strings.Join(f, ", ")
}

func extAdd(root string, args []string) error {
	var name, command, desc string
	var hooks, fields []string
	var optional bool
	rest := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--command":
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		case "--on":
			if i+1 < len(args) {
				hooks = append(hooks, splitList(args[i+1])...)
				i++
			}
		case "--fields":
			if i+1 < len(args) {
				fields = append(fields, splitList(args[i+1])...)
				i++
			}
		case "--optional":
			optional = true
		case "--description":
			if i+1 < len(args) {
				desc = args[i+1]
				i++
			}
		default:
			rest = append(rest, args[i])
		}
	}
	if len(rest) != 1 || command == "" {
		return fmt.Errorf("usage: quilzo ext add <name> --command /abs/path " +
			"--on validate[,transform,publish] [--fields title,body]")
	}
	name = rest[0]

	m := ext.Manifest{Name: name, Description: desc, Command: []string{command},
		Fields: fields, Optional: optional}
	for _, h := range hooks {
		m.Hooks = append(m.Hooks, ext.Hook(h))
	}
	if err := m.Validate(); err != nil {
		return err
	}
	// Pinned at registration, because that is the moment somebody has decided
	// to trust this binary. Pinning later would pin whatever is there then.
	sum, err := ext.Pin(command)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", command, err)
	}
	m.SHA256 = sum

	f, err := loadExts(root)
	if err != nil {
		return err
	}
	for _, existing := range f.Extensions {
		if existing.Name == name {
			return fmt.Errorf("%s is already registered; remove it first", name)
		}
	}
	f.Extensions = append(f.Extensions, m)
	if err := saveExts(root, f); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("ext.add", "/",
		audit.Success, map[string]string{
			"extension": name, "command": command,
			"hooks": strings.Join(hooks, ","), "hash": sum[:12]}))

	w.Human("registered %s%s%s\n", bold, name, reset)
	w.Human("  %spinned %s%s\n", dim, sum[:12], reset)
	if len(fields) == 0 {
		w.Human("  %sit declared no fields, so it will be sent none%s\n",
			yellow, reset)
	}
	if optional {
		w.Human("  %soptional: writes continue when it cannot run%s\n",
			dim, reset)
	} else {
		w.Human("  %srequired: a write is refused when it cannot run%s\n",
			dim, reset)
	}
	cfg, _ := loadConfig(root)
	if cfg != nil && !cfg.Bool("ext.enabled") {
		w.Human("  %sextensions are off; quilzo config set ext.enabled true%s\n",
			dim, reset)
	}
	return nil
}

func extRemove(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo ext remove <name>")
	}
	f, err := loadExts(root)
	if err != nil {
		return err
	}
	kept := f.Extensions[:0]
	found := false
	for _, m := range f.Extensions {
		if m.Name == args[0] {
			found = true
			continue
		}
		kept = append(kept, m)
	}
	if !found {
		return fmt.Errorf("there is no extension called %q", args[0])
	}
	f.Extensions = kept
	if err := saveExts(root, f); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("ext.remove", "/",
		audit.Success, map[string]string{"extension": args[0]}))
	w.Human("removed %s\n", args[0])
	return nil
}

func extPin(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo ext pin <name>")
	}
	f, err := loadExts(root)
	if err != nil {
		return err
	}
	for i := range f.Extensions {
		if f.Extensions[i].Name != args[0] {
			continue
		}
		sum, err := ext.Pin(f.Extensions[i].Command[0])
		if err != nil {
			return err
		}
		was := f.Extensions[i].SHA256
		f.Extensions[i].SHA256 = sum
		if err := saveExts(root, f); err != nil {
			return err
		}
		record(root, resolveCaller(root, "").auditRecord("ext.pin", "/",
			audit.Success, map[string]string{
				"extension": args[0], "was": short(was), "now": sum[:12]}))
		w.Human("%s is pinned to %s\n", args[0], sum[:12])
		if was != "" && was != sum {
			w.Human("  %sit was %s — the binary has changed since it was "+
				"registered%s\n", yellow, short(was), reset)
		}
		return nil
	}
	return fmt.Errorf("there is no extension called %q", args[0])
}

// extTest runs one extension against a made-up page, so an operator can see
// what it does before it runs inside a publish.
func extTest(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo ext test <name>")
	}
	f, err := loadExts(root)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	for _, m := range f.Extensions {
		if m.Name != args[0] {
			continue
		}
		fields := map[string]any{}
		for _, name := range m.Fields {
			fields[name] = "example value for " + name
		}
		runner := &ext.Runner{Limits: extLimits(cfg)}
		res := runner.Run(context.Background(), m, ext.Request{
			Hook: m.Hooks[0], Page: "example", Fields: fields})

		if w.JSON(res) {
			return nil
		}
		w.Human("%s on %s, %s\n", m.Name, m.Hooks[0], res.Took.Round(1e6))
		if res.Err != nil {
			return res.Err
		}
		switch {
		case res.Response.Refuse:
			w.Human("  refused: %s\n", res.Response.Reason)
		case len(res.Response.Fields) > 0:
			for k, v := range res.Response.Fields {
				w.Human("  %s → %v\n", k, v)
			}
		default:
			w.Human("  %sno objection%s\n", dim, reset)
		}
		return nil
	}
	return fmt.Errorf("there is no extension called %q", args[0])
}
