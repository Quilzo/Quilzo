// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentport"
	"github.com/quilzo/quilzo/internal/out"
)

// Agents brought in from other platforms, and taken out to them. See
// internal/agentport for what each format carries.

// importedAgent is one agent of an import, as the command reports it.
type importedAgent struct {
	agentport.Agent
	// Invalid is why it would not be declared as it stands.
	Invalid string `json:"invalid,omitempty"`
	// Exists says an agent of that name is declared already.
	Exists bool `json:"exists,omitempty"`
	// Written are the files written for it, and Declared that it was.
	Written  []string `json:"written,omitempty"`
	Declared bool     `json:"declared,omitempty"`
}

// checkImported checks what an import made as a declaration here would be.
func checkImported(root string, imp *agentport.Imported) []importedAgent {
	known, custom := knownCapabilities(root), customKinds(root)
	set, _ := loadAgents(root)
	var out []importedAgent
	for _, a := range imp.Agents {
		ia := importedAgent{Agent: a}
		m := a.Manifest
		if err := m.ValidateWith(known, custom); err != nil {
			ia.Invalid = err.Error()
		}
		if set != nil {
			_, ia.Exists = set.Agents[m.Name]
		}
		out = append(out, ia)
	}
	return out
}

// agentImport is `quilzo agent import FILE [--from F] [--name N] [-o DIR] [--save]`.
func agentImport(root string, args []string) error {
	usage := errors.New("quilzo agent import FILE [--from FORMAT] [--name NAME] [-o DIR] [--save]")
	pos, rest := leadingArgs(args, 1)
	fs := flag.NewFlagSet("agent import", flag.ContinueOnError)
	from := fs.String("from", "", "the file's format, when it is not recognised (quilzo agent formats)")
	name := fs.String("name", "", "what to call the file's only agent here")
	outDir := fs.String("o", "", "write each declaration, and any document it came with, to this directory")
	save := fs.Bool("save", false, "declare each agent that checks, as quilzo agent declare would")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	pos = append(pos, fs.Args()...)
	if len(pos) != 1 {
		return usage
	}
	fi, err := os.Stat(pos[0])
	if err != nil {
		return err
	}
	if fi.Size() > agentport.MaxFile {
		return fmt.Errorf("%s is over %d MiB", pos[0], agentport.MaxFile>>20)
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	imp, err := agentport.Read(data, *from, *name)
	if err != nil {
		return err
	}
	agents := checkImported(root, imp)
	caller := resolveCaller(root, flagToken)
	if *outDir != "" {
		for i := range agents {
			if err := writeImported(*outDir, &agents[i]); err != nil {
				return err
			}
		}
	}
	ms := make([]agent.Manifest, len(agents))
	for i, a := range agents {
		ms[i] = a.Manifest
	}
	for _, i := range agentport.Order(ms) {
		a := &agents[i]
		if *save && a.Invalid == "" && !a.Exists {
			if err := declareAgent(root, a.Manifest, true, false, caller); err != nil {
				a.Invalid = err.Error()
				continue
			}
			a.Declared = true
		}
	}
	if w.JSON(map[string]any{"format": imp.Format, "agents": agents, "notes": imp.Notes}) {
		return nil
	}
	f, _ := agentport.FormatNamed(imp.Format)
	w.Human("%s%s%s: %s\n", bold, pos[0], reset, f.Title)
	for _, n := range imp.Notes {
		w.Human("  %s\n", noteLine(n))
	}
	for _, a := range agents {
		m := a.Manifest
		w.Human("\n%s%s%s  %s agent, %s  %s(%s)%s\n  %s\n", bold, m.Name, reset, m.Kind, m.Autonomy, dim, a.Source, reset, m.Purpose)
		for _, kind := range []string{agentport.Kept, agentport.Changed, agentport.Left, agentport.Decide} {
			for _, n := range a.Notes {
				if n.Kind == kind {
					w.Human("  %s\n", noteLine(n))
				}
			}
		}
		switch {
		case a.Declared:
			w.Human("  %sdeclared%s: quilzo agent could %s OPERATION says what a run of it could do\n", green, reset, m.Name)
		case a.Invalid != "":
			w.Human("  %swould not be declared: %s%s\n", red, a.Invalid, reset)
		case a.Exists && len(agents) == 1:
			w.Human("  %san agent called %s is declared already: import it --name NEW, or amend that one "+
				"with quilzo agent declare FILE%s\n", yellow, m.Name, reset)
		case a.Exists:
			w.Human("  %san agent called %s is declared already, and is left as it is: amend it "+
				"with quilzo agent declare FILE%s\n", yellow, m.Name, reset)
		}
		for _, f := range a.Written {
			w.Human("  %swrote %s%s\n", dim, f, reset)
		}
	}
	if !*save {
		w.Human("\n%snothing is declared yet: read the above, then add --save, or write it out with -o DIR, "+
			"change what you would, and quilzo agent declare DIR/NAME.json%s\n", dim, reset)
	}
	return nil
}

func noteLine(n agentport.Note) string {
	switch n.Kind {
	case agentport.Kept:
		return green + "kept     " + reset + n.Text
	case agentport.Changed:
		return "changed  " + n.Text
	case agentport.Left:
		return dim + "left out " + reset + n.Text
	}
	return yellow + "decide   " + reset + n.Text
}

// writeImported writes an imported agent's declaration and the documents
// it came with, refusing to write over a file.
func writeImported(dir string, a *importedAgent) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	e, err := agentport.Write(a.Manifest, "quilzo")
	if err != nil {
		return err
	}
	files := map[string][]byte{}
	for n, b := range e.Files {
		files[n] = b
	}
	for n, b := range a.Files {
		files[n] = b
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		path := filepath.Join(dir, filepath.Base(n))
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("%s exists already; write the import somewhere else", path)
			}
			return err
		}
		_, werr := f.Write(files[n])
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return werr
		}
		a.Written = append(a.Written, path)
	}
	return nil
}

// agentExport is `quilzo agent export NAME [--to FORMAT] [-o PATH]`.
func agentExport(root string, args []string) error {
	pos, rest := leadingArgs(args, 1)
	fs := flag.NewFlagSet("agent export", flag.ContinueOnError)
	to := fs.String("to", "quilzo", "the format to write (quilzo agent formats)")
	dest := fs.String("o", "", "write it to this file, or into this directory; without it, it is printed")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	pos = append(pos, fs.Args()...)
	if len(pos) != 1 {
		return errors.New("quilzo agent export NAME [--to FORMAT] [-o PATH]")
	}
	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	m, ok := set.Agents[pos[0]]
	if !ok {
		return fmt.Errorf("no agent is called %s", pos[0])
	}
	e, err := agentport.Write(m, *to)
	if err != nil {
		return err
	}
	if *dest == "" && len(e.Files) != 1 && w.Mode != out.JSON {
		return fmt.Errorf("%s writes %d files; give a directory with -o", *to, len(e.Files))
	}
	var written []string
	if *dest != "" {
		dir, single := *dest, ""
		if fi, err := os.Stat(*dest); err != nil || !fi.IsDir() {
			if len(e.Files) != 1 {
				return fmt.Errorf("%s writes %d files; give a directory", *to, len(e.Files))
			}
			dir, single = filepath.Dir(*dest), filepath.Base(*dest)
		}
		for n, b := range e.Files {
			if single != "" {
				n = single
			}
			p := filepath.Join(dir, n)
			if err := os.WriteFile(p, b, 0o644); err != nil {
				return err
			}
			written = append(written, p)
		}
	}
	if w.JSON(map[string]any{"format": *to, "files": stringFiles(e.Files), "written": written, "notes": e.Notes}) {
		return nil
	}
	if *dest == "" {
		for _, b := range e.Files {
			w.Out.Write(b)
		}
	}
	// What was not carried goes beside the file, never into it, so the
	// printed file can be redirected as it is.
	for _, p := range written {
		fmt.Fprintf(w.Err, "wrote %s\n", p)
	}
	for _, n := range e.Notes {
		fmt.Fprintf(w.Err, "  %s\n", noteLine(n))
	}
	return nil
}

func stringFiles(files map[string][]byte) map[string]string {
	out := make(map[string]string, len(files))
	for n, b := range files {
		out[n] = string(b)
	}
	return out
}

// agentFormats is `quilzo agent formats`.
func agentFormats() error {
	if w.JSON(agentport.Formats) {
		return nil
	}
	for _, f := range agentport.Formats {
		ways := []string{}
		if f.Import {
			ways = append(ways, "import")
		}
		if f.Export {
			ways = append(ways, "export")
		}
		w.Human("%s%-17s%s %s  %s(%s)%s\n  %s\n", bold, f.Name, reset, f.Title, dim, strings.Join(ways, ", "), reset, f.What)
	}
	w.Human("\n%squilzo agent import FILE recognises the format; --from names it when it cannot%s\n", dim, reset)
	return nil
}
