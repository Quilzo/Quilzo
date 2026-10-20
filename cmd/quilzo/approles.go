// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/feature"
)

// Roles the installed features declare for the people who work in them
// (see internal/auth/approle.go). Each is read from the version of its
// feature that is installed, so there is one place it is defined.

// appRoles is every role the installed features declare, by name.
func appRoles(root string) ([]auth.AppRole, error) {
	installed, err := loadInstalledFeatures(root)
	if err != nil {
		return nil, err
	}
	var out []auth.AppRole
	for _, in := range installed {
		if !ownsKind(in, "role") {
			continue
		}
		p, _, err := loadFeaturePackage(root, in.Name, in.Digest)
		if err != nil {
			return nil, fmt.Errorf("the roles of %s cannot be read: %w", in.Name, err)
		}
		out = append(out, p.AppRoles()...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// appRoleNamed finds an installed feature's role by its full name.
func appRoleNamed(root, name string) (auth.AppRole, error) {
	roles, err := appRoles(root)
	if err != nil {
		return auth.AppRole{}, err
	}
	for _, r := range roles {
		if r.Name == name {
			return r, nil
		}
	}
	app, _, _ := strings.Cut(name, "/")
	var same []string
	for _, r := range roles {
		if strings.HasPrefix(r.Name, app+"/") {
			same = append(same, r.Name)
		}
	}
	if len(same) > 0 {
		return auth.AppRole{}, fmt.Errorf("%s declares no role %s; its roles are %s", app, name, strings.Join(same, ", "))
	}
	return auth.AppRole{}, fmt.Errorf("no installed feature declares the role %s", name)
}

// heldRolesChanged is the roles an install would change that somebody
// holds: changing one changes what they may do.
func heldRolesChanged(root string, p *feature.Package) ([]string, error) {
	installed, err := loadInstalledFeatures(root)
	if err != nil {
		return nil, err
	}
	in := installed[p.Name]
	if in == nil || !ownsKind(in, "role") {
		return nil, nil
	}
	cur, _, err := loadFeaturePackage(root, in.Name, in.Digest)
	if err != nil {
		return nil, fmt.Errorf("the roles of %s cannot be read: %w", in.Name, err)
	}
	pol, err := loadPolicy(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range p.Roles {
		name := p.FullName(r)
		was, ok := cur.Block(feature.Ref{Kind: "role", Name: name}).(feature.Role)
		if !ok || slices.Equal(p.AppRole(r).Bindings, cur.AppRole(was).Bindings) {
			continue
		}
		if len(holders(pol, name)) > 0 {
			out = append(out, name)
		}
	}
	return out, nil
}

// holders is who holds an app role.
func holders(pol *auth.Policy, role string) []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range pol.Snapshot() {
		if b.Via == auth.ViaApp(role) && !seen[b.Principal] {
			seen[b.Principal] = true
			out = append(out, b.Principal)
		}
	}
	sort.Strings(out)
	return out
}

// reassignRoles brings the holders of a feature's roles up to date after
// an install: a changed role grants its holders what it grants now, and a
// role the feature no longer declares is taken from everybody.
func reassignRoles(root string, pkg *feature.Package, act map[feature.Ref]string, removed []string, caller *Caller) error {
	type change struct {
		role, what string
		who        []string
	}
	var changes []change
	if _, err := updatePolicy(root, func(pol *auth.Policy) error {
		changes = nil
		for _, r := range pkg.Roles {
			name := pkg.FullName(r)
			if act[feature.Ref{Kind: "role", Name: name}] != feature.Change {
				continue
			}
			ar := pkg.AppRole(r)
			if who := pol.Reassign(name, &ar); len(who) > 0 {
				changes = append(changes, change{name, "changed", who})
			}
		}
		for _, name := range removed {
			if who := pol.Reassign(name, nil); len(who) > 0 {
				changes = append(changes, change{name, "removed", who})
			}
		}
		if len(changes) == 0 {
			return atomicfile.ErrUnchanged
		}
		return nil
	}); err != nil {
		return err
	}
	for _, c := range changes {
		record(root, caller.auditRecord("auth.app-role-"+c.what, "/", audit.Success, map[string]string{
			"feature": pkg.Name, "role": c.role, "people": fmt.Sprint(len(c.who))}))
	}
	return nil
}
