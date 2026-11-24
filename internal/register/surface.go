// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"fmt"
	"regexp"
	"sort"
	"sync"
)

// What each security module offers, and where.
//
// Every capability is reached four ways: from the command line, from the
// admin, by an agent over MCP and by a program over the HTTP API. A module
// registers each of the four from its own file, through the registration of
// the surface it is adding to (cmd/quilzo's registerCLI, the admin's
// registerScreens, the API's registerRoutes), and each of those writes here
// what it registered, under the module's name. Nothing else writes here.
//
// That is what lets one test hold every module to all four surfaces without
// a list of modules anybody keeps: the command line's tests link the admin
// and the API, so by the time they run every surface has said what it
// offers, and a module that offers a command and no screen is a failure
// with the module's name on it. A module that should not have a surface
// says so with Without and a reason, which is shown beside the test's
// verdict and read in review.

// Surface is one of the four ways a capability is reached.
type Surface string

const (
	SurfaceCLI   Surface = "cli"
	SurfaceAdmin Surface = "admin"
	SurfaceMCP   Surface = "mcp"
	SurfaceAPI   Surface = "api"
)

// Surfaces is the four, in the order a person is told them.
var Surfaces = []Surface{SurfaceCLI, SurfaceAdmin, SurfaceMCP, SurfaceAPI}

// Module is what one module offers: on each surface, the names of what it
// registered there (commands, addresses, operations), and the surfaces it
// does without, each with why.
type Module struct {
	Name    string               `json:"name"`
	Offers  map[Surface][]string `json:"offers"`
	Without map[Surface]string   `json:"without,omitempty"`
}

// Missing is the surfaces the module neither offers nor says why it does
// without.
func (m Module) Missing() []Surface {
	var out []Surface
	for _, s := range Surfaces {
		if len(m.Offers[s]) == 0 && m.Without[s] == "" {
			out = append(out, s)
		}
	}
	return out
}

var (
	ledgerMu sync.Mutex
	ledger   = map[string]*Module{}
	// reModuleName is a module's name: what its command is called, and
	// what its screens and routes are filed under.
	reModuleName = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
)

func moduleNamed(name string) *Module {
	if !reModuleName.MatchString(name) {
		panic(fmt.Sprintf("register: %q is not a module's name", name))
	}
	m := ledger[name]
	if m == nil {
		m = &Module{Name: name, Offers: map[Surface][]string{}, Without: map[Surface]string{}}
		ledger[name] = m
	}
	return m
}

func knownSurface(on Surface) {
	for _, s := range Surfaces {
		if s == on {
			return
		}
	}
	panic(fmt.Sprintf("register: %q is not a surface", on))
}

// Offer records that a module registered something on a surface. It is
// called by a surface's own registration, at start, and never by a module
// directly: what is written here is what that surface will serve.
func Offer(module string, on Surface, names ...string) {
	knownSurface(on)
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	m := moduleNamed(module)
	m.Offers[on] = append(m.Offers[on], names...)
	sort.Strings(m.Offers[on])
}

// Without records that a module deliberately has no such surface, and why.
// The reason is a sentence a reviewer reads; an empty one is a mistake in
// the program.
func Without(module string, on Surface, why string) {
	knownSurface(on)
	if why == "" {
		panic(fmt.Sprintf("register: the module %s does without %s and does not say why", module, on))
	}
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	moduleNamed(module).Without[on] = why
}

// Modules is every module any surface registered, in the order of their
// names, each a copy.
func Modules() []Module {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	out := make([]Module, 0, len(ledger))
	for _, m := range ledger {
		c := Module{Name: m.Name, Offers: map[Surface][]string{}, Without: map[Surface]string{}}
		for s, names := range m.Offers {
			c.Offers[s] = append([]string(nil), names...)
		}
		for s, why := range m.Without {
			c.Without[s] = why
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
