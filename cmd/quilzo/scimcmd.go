// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/oauthas"
	"github.com/quilzo/quilzo/internal/scim"
	"github.com/quilzo/quilzo/internal/throttle"
)

// Provisioning from an identity provider. See internal/scim.

func scimPath(root string) string      { return filepath.Join(root, "scim.json") }
func scimTokenPath(root string) string { return filepath.Join(root, "scim-token") }

// scimBy marks the grants provisioning made, which are the only ones it
// ever changes.
const scimBy = "scim"

func scimStore(root string) *scim.Store { return &scim.Store{Path: scimPath(root)} }

// newSCIMToken makes the provisioning token, keeps its hash, and returns it
// once. A new one replaces the old: there is one provisioning connection.
func newSCIMToken(root string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := "qzscim_" + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	if err := atomicfile.Write(scimTokenPath(root), []byte(hex.EncodeToString(sum[:])), 0o600); err != nil {
		return "", err
	}
	return token, nil
}

// scimAuthenticate compares a presented token's hash with the kept one.
func scimAuthenticate(root, token string) bool {
	want, err := os.ReadFile(scimTokenPath(root))
	if err != nil || token == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	got := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(strings.TrimSpace(string(want)))) == 1
}

// validMapping reports whether a group may be mapped to this: a role or a job.
func validMapping(to string) error {
	if _, ok := auth.JobNamed(to); ok {
		return nil
	}
	if auth.Role(to).Valid() {
		return nil
	}
	var jobs []string
	for _, j := range auth.Jobs {
		jobs = append(jobs, j.Name)
	}
	return fmt.Errorf("%q is neither a role (reader, author, publisher, admin) nor a job (%s)",
		to, strings.Join(jobs, ", "))
}

// scimSync makes a person's provisioned access match what provisioning
// says. Grants made by hand are never changed; while somebody is suspended
// a deny over everything outranks them, and is lifted when the provider
// reactivates them. Somebody who ends up holding nothing, or suspended,
// keeps no session or token either.
func scimSync(root, name string, grants []string, suspended bool) error {
	p, err := loadPolicy(root)
	if err != nil {
		return err
	}
	ts, err := loadTokens(root)
	if err != nil {
		return err
	}
	// Policy decisions compare names exactly and an identity provider does
	// not, so a suspension covers every spelling this install has of them.
	spellings := []string{name}
	seen := map[string]bool{name: true}
	note := func(who string) {
		if strings.EqualFold(who, name) && !seen[who] {
			seen[who] = true
			spellings = append(spellings, who)
		}
	}
	for _, b := range p.Snapshot() {
		note(b.Principal)
	}
	for _, t := range ts.Snapshot() {
		note(t.Principal)
	}

	var want []auth.Binding
	if suspended {
		for _, who := range spellings {
			want = append(want, auth.Binding{Principal: who, Role: auth.RoleReader, Resource: "/", Deny: true,
				Note: "suspended: the identity provider deactivated or removed them"})
		}
	} else {
		for _, g := range grants {
			if job, ok := auth.JobNamed(g); ok {
				for _, b := range job.Bindings {
					want = append(want, auth.Binding{Principal: name, Role: b.Role, Resource: b.Resource})
				}
			} else if auth.Role(g).Valid() {
				want = append(want, auth.Binding{Principal: name, Role: auth.Role(g), Resource: "/"})
			}
		}
	}
	same := func(a, b auth.Binding) bool {
		return a.Principal == b.Principal && a.Role == b.Role && a.Resource == b.Resource && a.Deny == b.Deny
	}

	// Keep what provisioning made and still wants, so a grant's date is the
	// day it was first made and an unchanged sync writes nothing.
	satisfied := make([]bool, len(want))
	changed := false
	kept := p.Bindings[:0]
	for _, b := range p.Bindings {
		if b.GrantedBy != scimBy || !strings.EqualFold(b.Principal, name) {
			kept = append(kept, b)
			continue
		}
		keep := false
		for i, x := range want {
			if !satisfied[i] && same(b, x) {
				satisfied[i], keep = true, true
				break
			}
		}
		if keep {
			kept = append(kept, b)
		} else {
			changed = true
		}
	}
	p.Bindings = kept
	for i, x := range want {
		if satisfied[i] {
			continue
		}
		// Somebody already granted it by hand, which stands for both.
		dup := false
		for _, b := range p.Bindings {
			if same(b, x) {
				dup = true
			}
		}
		if dup {
			continue
		}
		if x.Note == "" {
			x.Note = "provisioned from the identity provider's groups"
		}
		x.GrantedBy = scimBy
		if err := p.Grant(x); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		if err := saveJSON(policyPath(root), p); err != nil {
			return err
		}
	}

	if !suspended && (p.Anywhere(name, auth.ActView) || holdsArea(p, name)) {
		return nil
	}
	ended := 0
	for _, t := range ts.Snapshot() {
		if seen[t.Principal] && !t.Revoked {
			if _, err := ts.Revoke(t.ID); err == nil {
				ended++
			}
		}
	}
	if ended > 0 {
		if err := saveJSON(tokensPath(root), ts); err != nil {
			return err
		}
		record(root, audit.Record{Action: "scim.sessions-ended", Resource: "/",
			Outcome: audit.Success, Principal: scimBy, Kind: audit.KindService,
			Verified: true, Detail: map[string]string{"subject": name, "count": fmt.Sprint(ended)}})
	}
	// And the apps they connected: an app acting for somebody who is no
	// longer here is not connected to anybody. Ended after the tokens are
	// saved, because ending a connection revokes its tokens in the same
	// file.
	by := &Caller{Name: scimBy, Kind: audit.KindService, Verified: true}
	appsServer(root, by).EndWhere(func(g oauthas.Grant) bool { return strings.EqualFold(g.Principal, name) },
		scimBy, "the identity provider suspended or removed them")
	// Deleted, not suspended: no longer anybody here, so no agent keeps
	// anything about them.
	exists := false
	_ = scimStore(root).Read(func(st *scim.State) {
		for _, u := range st.Users {
			if strings.EqualFold(u.UserName, name) {
				exists = true
			}
		}
	})
	if !exists {
		for _, who := range spellings {
			if _, err := forgetPerson(root, who, scimBy); err != nil {
				return err
			}
		}
	}
	return nil
}

// holdsArea reports whether somebody holds any grant on an area, which
// Anywhere does not count.
func holdsArea(p *auth.Policy, name string) bool {
	for _, a := range []string{auth.AreaSecurity, auth.AreaCompliance, auth.AreaLog, auth.AreaInbox, auth.AreaBoards} {
		if p.Evaluate(name, auth.ActView, a).Allowed {
			return true
		}
	}
	return false
}

// scimHandler is the endpoint the identity provider talks to.
func scimHandler(root string) *scim.Handler {
	return &scim.Handler{
		Store:        scimStore(root),
		Authenticate: func(token string) bool { return scimAuthenticate(root, token) },
		Sync: func(name string, grants []string, suspended bool) error {
			return scimSync(root, name, grants, suspended)
		},
		Audit: func(action, subject string, ok bool) {
			outcome := audit.Success
			if !ok {
				outcome = audit.Failure
			}
			record(root, audit.Record{Action: action, Resource: "/", Outcome: outcome,
				Principal: scimBy, Kind: audit.KindService, Verified: true,
				Detail: map[string]string{"subject": subject}})
		},
		Limit: throttle.New(throttlePolicy(mustConfig(root))),
	}
}

func scimUsage() error {
	return fmt.Errorf("usage: quilzo scim status | token [--revoke] | map GROUP ROLE|JOB | unmap GROUP")
}

func cmdSCIM(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	caller := resolveCaller(root, "")
	note := func(action, detail string) error {
		return recordE(root, caller.auditRecord(action, "/", audit.Success,
			map[string]string{"group": detail}))
	}
	store := scimStore(root)
	switch args[0] {
	case "status":
		var users, active, groups int
		var mapping map[string]string
		if err := store.Read(func(st *scim.State) {
			users, groups, mapping = len(st.Users), len(st.Groups), st.Mapping
			for _, u := range st.Users {
				if u.Active {
					active++
				}
			}
		}); err != nil {
			return err
		}
		_, terr := os.Stat(scimTokenPath(root))
		if w.JSON(map[string]any{"token": terr == nil, "users": users, "active": active,
			"groups": groups, "mapping": mapping}) {
			return nil
		}
		if terr != nil {
			w.Human("  no provisioning token; quilzo scim token makes one\n")
		} else {
			w.Human("  provisioning is set up at /scim/v2 on the admin\n")
		}
		w.Human("  %d people (%d active), %d groups\n", users, active, groups)
		names := make([]string, 0, len(mapping))
		for g := range mapping {
			names = append(names, g)
		}
		sort.Strings(names)
		for _, g := range names {
			w.Human("  %s%s%s  is  %s\n", bold, onOneLine(g), reset, mapping[g])
		}
		if len(names) == 0 {
			w.Human("  %sno group is mapped, so provisioning grants nothing%s\n", dim, reset)
		}
		return nil
	case "token":
		if len(args) > 1 && args[1] == "--revoke" {
			if err := os.Remove(scimTokenPath(root)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			w.Human("the provisioning token is revoked; the identity provider can change nothing\n")
			return note("scim.token-revoked", "")
		}
		token, err := newSCIMToken(root)
		if err != nil {
			return err
		}
		w.Human("%s\n", token)
		w.Human("  %sgive this to the identity provider as its bearer token, with the URL\n"+
			"  https://YOUR-ADMIN/scim/v2. Shown once; it replaces any earlier one%s\n", dim, reset)
		return note("scim.token-made", "")
	case "map":
		if len(args) != 3 {
			return scimUsage()
		}
		if err := validMapping(args[2]); err != nil {
			return err
		}
		if err := store.Update(func(st *scim.State) error { st.Mapping[args[1]] = args[2]; return nil }); err != nil {
			return err
		}
		scimHandler(root).SyncAll()
		w.Human("members of %q are now %s here\n", args[1], args[2])
		return note("scim.mapped", args[1]+" → "+args[2])
	case "unmap":
		if len(args) != 2 {
			return scimUsage()
		}
		if err := store.Update(func(st *scim.State) error { delete(st.Mapping, args[1]); return nil }); err != nil {
			return err
		}
		scimHandler(root).SyncAll()
		w.Human("%q no longer grants anything here\n", args[1])
		return note("scim.unmapped", args[1])
	}
	return scimUsage()
}

// scimHooks is the admin's Provisioning screen.
func scimHooks(root string) *admin.SCIMAdmin {
	store := scimStore(root)
	note := func(action, by, detail string) error {
		return recordE(root, audit.Record{Action: action, Resource: "/", Outcome: audit.Success,
			Principal: by, Kind: audit.KindHuman, Detail: map[string]string{"group": detail}})
	}
	return &admin.SCIMAdmin{
		Handler: scimHandler(root),
		Status: func() (bool, *scim.State, error) {
			_, terr := os.Stat(scimTokenPath(root))
			var copyOf *scim.State
			err := store.Read(func(st *scim.State) { c := *st; copyOf = &c })
			return terr == nil, copyOf, err
		},
		Map: func(group, to, by string) error {
			if err := validMapping(to); err != nil {
				return err
			}
			if err := store.Update(func(st *scim.State) error { st.Mapping[group] = to; return nil }); err != nil {
				return err
			}
			scimHandler(root).SyncAll()
			return note("scim.mapped", by, group+" → "+to)
		},
		Unmap: func(group, by string) error {
			if err := store.Update(func(st *scim.State) error { delete(st.Mapping, group); return nil }); err != nil {
				return err
			}
			scimHandler(root).SyncAll()
			return note("scim.unmapped", by, group)
		},
		NewToken: func(by string) (string, error) {
			t, err := newSCIMToken(root)
			if err != nil {
				return "", err
			}
			return t, note("scim.token-made", by, "")
		},
		RevokeToken: func(by string) error {
			if err := os.Remove(scimTokenPath(root)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return note("scim.token-revoked", by, "")
		},
	}
}
