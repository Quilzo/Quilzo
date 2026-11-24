// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/icons"
)

// A module's screens, registered from the module's own file.
//
// A screen has always been four edits in four files: a route in Handler, a
// row in the navigation, an icon in the icon table and its other names in
// the finder's list. That is right for one program written in order, and it
// is how two people adding two screens in the same week edit the same four
// lists. The security modules are built side by side, so each brings its
// screens with it: a file of handlers that ends with one call to
// registerScreens, in an init, and no line changed anywhere else.
//
// What is registered is held to what the tables are held to, by the same
// tests. A module's routes are read with the ones in server.go by the test
// helper that lists what is served, so each screen is opened, rendered and
// run through the accessibility checks, each must be reachable from the menu
// or from a link, and each entry in the menu needs an icon, a section and a
// page of the manual, exactly as if it had been written into the tables.

// screens is what a module adds to the admin.
type screens struct {
	// module is the module's name. It is the name its commands and its
	// routes in the content API are registered under too, which is how a
	// test finds that one of the three is missing.
	module string
	routes []screenRoute
	nav    []navEntry
}

// screenRoute is one address a module serves.
type screenRoute struct {
	// path is the pattern, as the mux takes it: "/register" for one
	// address, "/register/record/" for everything below one.
	path string
	// handle is the handler, as a method expression: (*Server).handleX.
	handle func(*Server, http.ResponseWriter, *http.Request)
	// notScreen says why the address is not a page somebody opens: a
	// form's target, a download. Empty for a screen.
	notScreen string
}

// navEntry is one entry a module adds to the menu.
type navEntry struct {
	destination
	// icon is the entry's Material Symbol, by its name in internal/icons.
	icon string
	// area is the area of the admin the screen belongs to, when it is not
	// the site's content: see screenAreas.
	area string
	// also is what else somebody looking for the screen would type.
	also []string
}

var (
	// moduleScreens is every module's screens, in the order of their names.
	moduleScreens []screens
	// moduleAlso is the other names of the modules' screens, for the finder.
	moduleAlso = map[string][]string{}

	reModule = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	reRoute  = regexp.MustCompile(`^/[a-z0-9][a-z0-9/._-]*$`)
)

// registerScreens adds a module's screens. It is called from an init in the
// module's own file. A module that is declared wrongly stops the program
// starting, with what is wrong: that is a mistake in the program, found the
// first time anything runs, tests included.
func registerScreens(m screens) {
	if err := checkScreens(m); err != nil {
		panic("admin: the module " + m.module + ": " + err.Error())
	}
	moduleScreens = append(moduleScreens, m)
	sort.SliceStable(moduleScreens, func(i, j int) bool { return moduleScreens[i].module < moduleScreens[j].module })
	for _, n := range m.nav {
		destinations = append(destinations, n.destination)
		iconPath[n.Key] = icons.Path(n.icon, "rounded")
		moduleFilled[n.Key] = icons.Path(n.icon, "rounded-filled")
		if n.area != "" {
			screenAreas[n.Key] = n.area
		}
		if len(n.also) > 0 {
			moduleAlso[n.Key] = n.also
		}
	}
}

// moduleFilled is each module screen's symbol filled, for the screen being
// looked at.
var moduleFilled = map[string]string{}

// checkScreens is what registerScreens refuses, without changing anything.
func checkScreens(m screens) error {
	if !reModule.MatchString(m.module) {
		return fmt.Errorf("%q is not a module's name", m.module)
	}
	for _, have := range moduleScreens {
		if have.module == m.module {
			return fmt.Errorf("it is registered twice")
		}
	}
	if len(m.routes) == 0 {
		return fmt.Errorf("it serves nothing")
	}
	served := map[string]bool{}
	for _, have := range moduleScreens {
		for _, r := range have.routes {
			served[r.path] = true
		}
	}
	mine := map[string]bool{}
	for _, r := range m.routes {
		switch {
		case !reRoute.MatchString(r.path):
			return fmt.Errorf("%q is not an address", r.path)
		case r.handle == nil:
			return fmt.Errorf("%s has no handler", r.path)
		case served[r.path] || mine[r.path]:
			return fmt.Errorf("%s is served twice", r.path)
		}
		mine[r.path] = true
	}
	for _, n := range m.nav {
		switch {
		case n.Key == "" || n.Label == "" || n.Doc == "" || n.Needs == "":
			return fmt.Errorf("the menu entry %q needs a key, a label, a page of the manual and the permission it takes", n.Key)
		case !mine[n.Path]:
			return fmt.Errorf("the menu entry %q goes to %s, which the module does not serve", n.Key, n.Path)
		case !knownGroup(n.Group):
			return fmt.Errorf("the menu entry %q is in the section %q, and the sections are %s", n.Key, n.Group, strings.Join(groups, ", "))
		case icons.Path(n.icon, "rounded") == "":
			return fmt.Errorf("the menu entry %q has the icon %q, which is not one of internal/icons", n.Key, n.icon)
		case n.area != "" && !auth.IsArea(n.area):
			return fmt.Errorf("the menu entry %q belongs to %q, which is not an area", n.Key, n.area)
		}
		for _, d := range destinations {
			if d.Key == n.Key || d.Path == n.Path {
				return fmt.Errorf("the menu already has an entry %q at %s", d.Key, d.Path)
			}
		}
	}
	return nil
}

func knownGroup(name string) bool {
	for _, g := range groups {
		if g == name {
			return true
		}
	}
	return false
}

// mountModules adds every module's routes to the admin's mux.
func (s *Server) mountModules(mux *http.ServeMux) {
	for _, m := range moduleScreens {
		for _, r := range m.routes {
			handle := r.handle
			mux.HandleFunc(r.path, func(w http.ResponseWriter, req *http.Request) { handle(s, w, req) })
		}
	}
}

// ModuleRoutes is the addresses each module serves, by the module's name.
// It is for the tests that hold a module to having every surface: the
// command line's reads it to check that the screen a command claims exists.
func ModuleRoutes() map[string][]string {
	out := map[string][]string{}
	for _, m := range moduleScreens {
		for _, r := range m.routes {
			out[m.module] = append(out[m.module], r.path)
		}
	}
	return out
}
