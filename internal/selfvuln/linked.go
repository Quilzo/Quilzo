// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package selfvuln

import (
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"errors"
	"fmt"
	"strings"
)

// What is linked into a binary: every function the compiler kept, read from
// the binary's own line table (pclntab), which survives stripping (-s -w)
// because the runtime needs it for stack traces.
//
// This is the question a vulnerability in the standard library turns on.
// An advisory names the functions that are wrong; the linker drops every
// function nothing can call; so a function absent from the binary cannot
// be reached, by this program or by anything an attacker sends it. It is
// the same reading govulncheck's binary mode does, with the standard
// library only.

// Linked is the functions in a binary, by package: "net/http" ->
// {"Server.Serve", "ListenAndServe"}.
type Linked map[string]map[string]bool

// ErrUnreadable is a binary whose line table this cannot read: a format
// other than ELF or Mach-O, or one built without it. Nothing is then known
// about what is linked, which is not the same as nothing being linked.
var ErrUnreadable = errors.New("the functions linked into this binary cannot be read")

// ReadLinked reads the functions linked into the executable at path.
func ReadLinked(path string) (Linked, error) {
	data, text, err := pclntab(path)
	if err != nil {
		return nil, err
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(data, text))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	out := Linked{}
	for _, fn := range tab.Funcs {
		pkg, sym := split(fn.Name)
		if pkg == "" {
			continue
		}
		if out[pkg] == nil {
			out[pkg] = map[string]bool{}
		}
		out[pkg][sym] = true
	}
	if len(out) == 0 {
		return nil, ErrUnreadable
	}
	return out, nil
}

func pclntab(path string) ([]byte, uint64, error) {
	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		pc, text := f.Section(".gopclntab"), f.Section(".text")
		if pc == nil || text == nil {
			return nil, 0, ErrUnreadable
		}
		data, err := pc.Data()
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %v", ErrUnreadable, err)
		}
		return data, text.Addr, nil
	}
	if f, err := macho.Open(path); err == nil {
		defer f.Close()
		pc, text := f.Section("__gopclntab"), f.Section("__text")
		if pc == nil || text == nil {
			return nil, 0, ErrUnreadable
		}
		data, err := pc.Data()
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %v", ErrUnreadable, err)
		}
		return data, text.Addr, nil
	}
	return nil, 0, ErrUnreadable
}

// split turns a linker name into a package and the symbol as the Go
// vulnerability database writes it: "net/http.(*Server).Serve" is
// net/http and "Server.Serve"; "crypto/x509.ParseCertificate" is
// crypto/x509 and "ParseCertificate". Closures and generic instances are
// named for the function they belong to.
func split(name string) (pkg, sym string) {
	// The compiler's own: type equality, hashing, interface tables.
	if strings.HasPrefix(name, "type:") || strings.HasPrefix(name, "go:") || strings.Contains(name, " ") {
		return "", ""
	}
	name = dropBrackets(name) // a generic instance's type arguments
	// The package is everything up to the first dot after the last slash.
	slash := strings.LastIndexByte(name, '/')
	dot := strings.IndexByte(name[slash+1:], '.')
	if dot < 0 {
		return "", ""
	}
	pkg, sym = name[:slash+1+dot], name[slash+1+dot+1:]
	sym = strings.NewReplacer("(*", "", ")", "").Replace(sym)
	// func1, func2... are closures inside a function; gowrap, deferwrap
	// and the like are the compiler's.
	parts := strings.Split(sym, ".")
	for len(parts) > 1 {
		last := parts[len(parts)-1]
		if strings.HasPrefix(last, "func") || strings.HasSuffix(last, "wrap1") || strings.HasPrefix(last, "gowrap") || strings.HasPrefix(last, "deferwrap") {
			parts = parts[:len(parts)-1]
			continue
		}
		break
	}
	return pkg, strings.Join(parts, ".")
}

// Has reports whether any of the symbols is linked from pkg; with no
// symbols, whether anything of pkg is.
func (l Linked) Has(pkg string, symbols []string) (bool, []string) {
	fns, ok := l[pkg]
	if !ok {
		return false, nil
	}
	if len(symbols) == 0 {
		return len(fns) > 0, nil
	}
	var found []string
	for _, s := range symbols {
		if fns[s] {
			found = append(found, s)
		}
	}
	return len(found) > 0, found
}

// dropBrackets removes every [...] group, nested ones with it.
func dropBrackets(s string) string {
	if !strings.Contains(s, "[") {
		return s
	}
	var b strings.Builder
	depth := 0
	for _, c := range s {
		switch {
		case c == '[':
			depth++
		case c == ']' && depth > 0:
			depth--
		case depth == 0:
			b.WriteRune(c)
		}
	}
	return b.String()
}
