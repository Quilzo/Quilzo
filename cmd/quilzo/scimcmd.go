// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
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

// The provisioning token works for a limited time. Whoever holds it can
// create people and, through a mapped group, make them administrators, so
// a copy must stop working; it is replaced before it ends, with warning
// (the posture rule scim.token-expiring), because an ended token also
// stops the identity provider taking access away.
const (
	scimTokenDays    = 180
	scimTokenMaxDays = 365
	// scimTokenGrace is what a token made before tokens ended is given
	// from when it is first read, so nobody's provisioning stops unwarned.
	scimTokenGrace = 30 * 24 * time.Hour
)

// scimToken is what is kept of the provisioning token: its hash, when it
// was made and ends, and who made it and how it was approved, which the
// approval of a mapping that makes administrators shows (liveSCIMTokens).
type scimToken struct {
	Hash    string    `json:"hash"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	scim.TokenMade
}

// newSCIMToken makes the provisioning token, lasting days, keeps its hash,
// and returns it once. A new one replaces the old: there is one
// provisioning connection.
func newSCIMToken(root string, days int) (string, scimToken, error) {
	return newSCIMTokenMade(root, days, scim.TokenMade{})
}

// newSCIMTokenMade is newSCIMToken, keeping who made it and how.
func newSCIMTokenMade(root string, days int, made scim.TokenMade) (string, scimToken, error) {
	if days <= 0 || days > scimTokenMaxDays {
		return "", scimToken{}, fmt.Errorf("a provisioning token lasts from 1 to %d days", scimTokenMaxDays)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", scimToken{}, err
	}
	token := "qzscim_" + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	kept := scimToken{Hash: hex.EncodeToString(sum[:]), Created: now, Expires: now.AddDate(0, 0, days), TokenMade: made}
	if err := saveSCIMToken(root, kept); err != nil {
		return "", scimToken{}, err
	}
	return token, kept, nil
}

func saveSCIMToken(root string, t scimToken) error {
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return atomicfile.Write(scimTokenPath(root), b, 0o600)
}

// liveSCIMTokens are the provisioning tokens that work at now: who made
// each, when, and how it was approved. There is one at most, since a new
// one replaces the old, and none once it has ended or been revoked.
func liveSCIMTokens(root string, now time.Time) ([]scim.LiveToken, error) {
	t, ok, err := readSCIMToken(root, now)
	if err != nil || !ok || !now.Before(t.Expires) {
		return nil, err
	}
	return []scim.LiveToken{{TokenMade: t.TokenMade, Made: t.Created, Ends: t.Expires}}, nil
}

// readSCIMToken is the kept token, and whether there is one. A token kept
// as a bare hash, from before tokens ended, is given an end now and kept
// with it: the later of scimTokenDays after it was made and scimTokenGrace
// from now.
func readSCIMToken(root string, now time.Time) (scimToken, bool, error) {
	path := scimTokenPath(root)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return scimToken{}, false, nil
	}
	if err != nil {
		return scimToken{}, false, err
	}
	var t scimToken
	if text := strings.TrimSpace(string(b)); strings.HasPrefix(text, "{") {
		if err := json.Unmarshal(b, &t); err != nil || t.Hash == "" || t.Expires.IsZero() {
			return scimToken{}, false, fmt.Errorf("%s cannot be read; make a new token: quilzo scim token", path)
		}
		return t, true, nil
	} else {
		fi, serr := os.Stat(path)
		if serr != nil {
			return scimToken{}, false, serr
		}
		t = scimToken{Hash: text, Created: fi.ModTime().UTC(), Expires: fi.ModTime().UTC().AddDate(0, 0, scimTokenDays)}
		if grace := now.UTC().Add(scimTokenGrace); t.Expires.Before(grace) {
			t.Expires = grace
		}
		if err := saveSCIMToken(root, t); err != nil {
			return scimToken{}, false, err
		}
	}
	return t, true, nil
}

// scimAuthenticate compares a presented token's hash with the kept one,
// and refuses one that has ended.
func scimAuthenticate(root, token string) bool {
	now := time.Now()
	want, ok, err := readSCIMToken(root, now)
	if err != nil || !ok || token == "" || !now.Before(want.Expires) {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	got := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(want.Hash)) == 1
}

// validMapping reports whether a group may be mapped to this: a role, a
// permission, a job, or a role an installed feature declares.
func validMapping(root, to string) error {
	if _, ok := auth.JobNamed(to); ok {
		return nil
	}
	if _, ok := auth.PermissionNamed(to); ok {
		return nil
	}
	if auth.Role(to).Valid() {
		return nil
	}
	if auth.IsAppRoleName(to) {
		_, err := appRoleNamed(root, to)
		return err
	}
	var jobs []string
	for _, j := range auth.Jobs {
		jobs = append(jobs, j.Name)
	}
	return fmt.Errorf("%q is not a role (reader, author, publisher, admin), a permission, a job (%s) "+
		"or a role an installed feature declares (APP/ROLE)", to, strings.Join(jobs, ", "))
}

// scimMap makes a group mean something here, and brings everybody in it up
// to date. Mapping to an administrator's role or job waits for a second
// administrator first (dual.MapsToAdministrator), which is its callers'.
func scimMap(root, group, to string) error {
	if err := validMapping(root, to); err != nil {
		return err
	}
	if err := scimStore(root).Update(func(st *scim.State) error { st.Mapping[group] = to; return nil }); err != nil {
		return err
	}
	scimHandler(root).SyncAll()
	return nil
}

// scimUnmap makes a group mean nothing here, and takes back what it gave
// everybody in it. The command, the Provisioning screen and an access
// review that revokes a mapping all come through here.
func scimUnmap(root, group string) error {
	if err := scimStore(root).Update(func(st *scim.State) error { delete(st.Mapping, group); return nil }); err != nil {
		return err
	}
	scimHandler(root).SyncAll()
	return nil
}

// scimMappingWhat is a mapping that waits, in words, for the person
// deciding it.
func scimMappingWhat(group, to string) string {
	return fmt.Sprintf("map the identity provider's group %q to %s, making its members administrators", group, to)
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

	// What their groups give them. A suspension is sent none, since
	// scim.State.Grants is nothing while somebody is inactive, so their
	// groups are read here: what they give is what somebody keeps when
	// suspending them would leave nobody able to grant (below).
	var given, want []auth.Binding
	meant := slices.Clone(grants)
	if suspended {
		_ = scimStore(root).Read(func(st *scim.State) {
			if u, ok := st.UserNamed(name); ok {
				for _, g := range st.GroupsOf(u.ID) {
					if m := st.Mapping[g]; m != "" && !slices.Contains(meant, m) {
						meant = append(meant, m)
					}
				}
			}
		})
	}
	// Read only when a group means one, so a feature whose package cannot
	// be read stops nobody else's provisioning.
	var roles []auth.AppRole
	if slices.ContainsFunc(grants, auth.IsAppRoleName) && !suspended {
		if roles, err = appRoles(root); err != nil {
			return err
		}
	}
	for _, g := range meant {
		if job, ok := auth.JobNamed(g); ok {
			for _, b := range job.Bindings {
				given = append(given, auth.Binding{Principal: name, Role: b.Role, Resource: b.Resource})
			}
		} else if auth.Role(g).Valid() {
			given = append(given, auth.Binding{Principal: name, Role: auth.Role(g), Resource: "/"})
		} else if perm, ok := auth.PermissionNamed(g); ok {
			given = append(given, auth.Binding{Principal: name, Permission: perm.Action, Resource: "/"})
		} else if i := slices.IndexFunc(roles, func(r auth.AppRole) bool { return r.Name == g }); i >= 0 {
			for _, b := range roles[i].Bindings {
				given = append(given, auth.Binding{Principal: name, Role: b.Role, Permission: b.Permission,
					Resource: b.Resource, Via: auth.ViaApp(g)})
			}
		}
	}
	if suspended {
		for _, who := range spellings {
			want = append(want, auth.Binding{Principal: who, Role: auth.RoleReader, Resource: "/", Deny: true,
				Note: "suspended: the identity provider deactivated or removed them"})
		}
	} else {
		want = given
	}
	same := func(a, b auth.Binding) bool {
		return a.Principal == b.Principal && a.Role == b.Role && a.Permission == b.Permission &&
			a.Resource == b.Resource && a.Deny == b.Deny && a.Via == b.Via
	}

	// Keep what provisioning made and still wants, so a grant's date is the
	// day it was first made and an unchanged sync writes nothing. Worked out
	// on the policy as stored now, under its lock: an identity provider sends
	// requests in parallel, and the admin and the command line write the same
	// file, so a revocation decided from an earlier copy could be undone.
	// What provisioning gave and took is recorded one by one below: the role
	// is what a rule about somebody being made an administrator reads, and
	// a group mapped to admin is a way to make one.
	//
	// A suspension leaves the last person who can grant access on the whole
	// site as they are, by the rule the Shared Signals receiver keeps
	// (suspendOnSignal, lastGranter): no deny, and nothing provisioning gave
	// them taken back, since an administrator's role from a mapped group
	// ending would shut everybody out as surely as the deny. The identity
	// provider deactivating every administrator, or whoever held the
	// provisioning token doing it, denied each in turn, and nobody was left
	// who could grant access to anybody. Decided under the same lock, so two
	// administrators deactivated at once cannot each see the other still
	// able to grant; any spelling of them counts, since the deny covers them
	// all.
	//
	// Nobody at all able to grant is the same moment seen from the other
	// side. The identity provider renaming the last administrator as it
	// deactivated them, in one request or one after the other, took what
	// provisioning gave them from the old name, as a rename does, and then
	// denied the new one, which held nothing yet: nobody was left who could
	// grant access, and nobody was told. So a suspension that finds nobody
	// who can grant, of somebody what their groups give would make able to,
	// gives them that and no deny, and their access moves with the name. An
	// app's role is not read for a suspension, and does not count here.
	var granted, revoked []auth.Binding
	last := false
	p, err = updatePolicy(root, func(p *auth.Policy) error {
		granted, revoked, last = nil, nil, false
		want := want
		if suspended && slices.ContainsFunc(p.Principals(), func(who string) bool {
			return strings.EqualFold(who, name) && lastGranter(p, who)
		}) {
			last = true
			return atomicfile.ErrUnchanged
		}
		if suspended && len(given) > 0 && nobodyAdministers(p) &&
			(&auth.Policy{Bindings: append(p.Snapshot(), given...)}).Evaluate(name, auth.ActGrant, "/").Allowed {
			last, want = true, given
		}
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
				revoked = append(revoked, b)
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
			granted = append(granted, x)
		}
		if !changed {
			return atomicfile.ErrUnchanged
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, set := range []struct {
		action string
		list   []auth.Binding
	}{{"scim.granted", granted}, {"scim.revoked", revoked}} {
		for _, b := range set.list {
			role := string(b.Role)
			if b.Permission != "" {
				role = string(b.Permission)
			}
			record(root, audit.Record{Action: set.action, Resource: b.Resource, Outcome: audit.Success,
				Principal: scimBy, Kind: audit.KindService, Verified: true,
				Detail: map[string]string{"subject": name, "role": role, "deny": fmt.Sprintf("%t", b.Deny)}})
		}
	}

	if !suspended && (p.Anywhere(name, auth.ActView) || holdsArea(p, name)) {
		return nil
	}
	ended := 0
	for _, t := range ts.Snapshot() {
		// The last who can grant keeps their own long-lived token, as the
		// receiver leaves it: with the provider no longer signing them in,
		// it may be the one way in left to anybody.
		if seen[t.Principal] && !t.Revoked && (!last || t.IsSession()) {
			if _, err := ts.Revoke(t.ID); err == nil {
				ended++
			}
		}
	}
	if ended > 0 {
		if err := saveTokens(root, ts); err != nil {
			return err
		}
		record(root, audit.Record{Action: "scim.sessions-ended", Resource: "/",
			Outcome: audit.Success, Principal: scimBy, Kind: audit.KindService,
			Verified: true, Detail: map[string]string{"subject": name, "count": fmt.Sprint(ended)}})
	}
	exists := false
	_ = scimStore(root).Read(func(st *scim.State) {
		for _, u := range st.Users {
			if strings.EqualFold(u.UserName, name) {
				exists = true
			}
		}
	})
	if last {
		// Not suspended, and recorded as a suspension that failed, so
		// whoever reads the log sees it was asked for. A person decides the
		// rest; their apps and what agents remember of them stay until
		// then. A deletion is told of once: it suspends them first, while
		// they are still provisioned, and that is what tells.
		record(root, audit.Record{Action: "scim.suspended", Resource: "/", Outcome: audit.Failure,
			Principal: scimBy, Kind: audit.KindService, Verified: true,
			Detail: map[string]string{"subject": name, "count": fmt.Sprint(ended)}})
		if exists {
			scimTell(root, name, fmt.Sprintf("The identity provider deactivated or removed %s. %s is the only "+
				"person who can grant access here, so they were not suspended and keep what provisioning gave "+
				"them, and %s of theirs ended. Check with them; if it is right, make somebody else an "+
				"administrator, then suspend them by hand.", name, name, plural2(ended, "the one session", "sessions")))
		}
		return nil
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
	if !exists {
		for _, who := range spellings {
			if _, err := forgetPerson(root, who, scimBy); err != nil {
				return err
			}
		}
	}
	return nil
}

// scimTell mails the security contact in the background, so no request
// from the identity provider waits on a mail server, and records whether
// it reached them.
func scimTell(root, subject, summary string) {
	inBackground(func() {
		did, err := tellSecurity(root, summary)
		detail := map[string]string{"did": did, "subject": subject}
		outcome := audit.Success
		if err != nil {
			detail["error"], outcome = onOneLine(err.Error()), audit.Failure
		}
		record(root, audit.Record{Action: "scim.told", Resource: "/", Outcome: outcome,
			Principal: scimBy, Kind: audit.KindService, Verified: true, Detail: detail})
	})
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
		now := time.Now()
		tok, set, terr := readSCIMToken(root, now)
		if terr != nil {
			return terr
		}
		out := map[string]any{"token": set, "users": users, "active": active,
			"groups": groups, "mapping": mapping}
		if set {
			out["token_expires"] = tok.Expires.Format(time.RFC3339)
		}
		if w.JSON(out) {
			return nil
		}
		switch {
		case !set:
			w.Human("  no provisioning token; quilzo scim token makes one\n")
		case !now.Before(tok.Expires):
			w.Human("  %sthe provisioning token ended on %s, so the identity provider can change nothing, "+
				"not even take access away: quilzo scim token makes a new one%s\n",
				red, tok.Expires.Format("2 January 2006"), reset)
		default:
			w.Human("  provisioning is set up at /scim/v2 on the admin; its token ends on %s\n",
				tok.Expires.Format("2 January 2006"))
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
		fs := flag.NewFlagSet("scim token", flag.ContinueOnError)
		days := fs.Int("days", scimTokenDays, fmt.Sprintf("how many days it works, at most %d", scimTokenMaxDays))
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *days <= 0 || *days > scimTokenMaxDays {
			return fmt.Errorf("a provisioning token lasts from 1 to %d days", scimTokenMaxDays)
		}
		// While a group makes administrators, whoever holds this token
		// makes anybody one by putting them in it, so making it waits for a
		// second administrator and goes to whoever asked (quilzo pending
		// redeem), as an administrator's token does. It did not, and either
		// of two administrators alone made mallory an administrator through
		// the identity provider's door.
		makes, err := scimMakesAdministrators(root)
		if err != nil {
			return err
		}
		made := scim.TokenMade{By: caller.Name, Approval: scim.Unasked}
		if makes {
			apply, err := proposeSecond(root, caller, dual.SCIMToken,
				"a new provisioning token, which makes administrators through a mapped group",
				dual.SCIMTokenChange{Days: *days}, "")
			if err != nil || !apply {
				return err
			}
			made.Approval = scim.Alone
		}
		return giveSCIMToken(root, *days, caller, made)
	case "map":
		if len(args) != 3 {
			return scimUsage()
		}
		if err := validMapping(root, args[2]); err != nil {
			return err
		}
		if dual.MapsToAdministrator(args[2]) {
			apply, err := proposeSecond(root, caller, dual.Mapping, scimMappingWhat(args[1], args[2]),
				dual.MappingChange{Group: args[1], To: args[2]}, "")
			if err != nil || !apply {
				return err
			}
		}
		if err := scimMap(root, args[1], args[2]); err != nil {
			return err
		}
		w.Human("members of %q are now %s here\n", args[1], args[2])
		if dual.MapsToAdministrator(args[2]) {
			mappedTokens(root, time.Now())
		}
		return note("scim.mapped", args[1]+" → "+args[2])
	case "unmap":
		if len(args) != 2 {
			return scimUsage()
		}
		if err := scimUnmap(root, args[1]); err != nil {
			return err
		}
		w.Human("%q no longer grants anything here\n", args[1])
		return note("scim.unmapped", args[1])
	}
	return scimUsage()
}

// mappedTokens tells the only administrator, who has just mapped a group
// to make administrators and so approved it alone, which provisioning
// tokens now make them: what `quilzo pending show` lists for a second
// administrator before approving. Nothing waited here, so nothing was
// shown, and a token another administrator made before any group made
// administrators went on working as a way to make them.
func mappedTokens(root string, now time.Time) {
	live, err := liveSCIMTokens(root, now)
	switch {
	case err != nil:
		w.Human("  %sthis lets the provisioning token make administrators, and it could not be read: %v%s\n",
			yellow, err, reset)
	case len(live) == 0:
		w.Human("  no provisioning token works now; one made from now on asks a second administrator, when there is one\n")
	default:
		w.Human("  %sthis lets the provisioning token make administrators:%s\n", yellow, reset)
		for _, t := range live {
			w.Human("    %s\n", t.Words())
		}
		w.Human("  %sif that is not who should hold it, revoke it: quilzo scim token --revoke%s\n", dim, reset)
	}
}

// scimMakesAdministrators reports whether a group the identity provider
// sends makes its members administrators of anything, or will once a
// mapping waiting for a second administrator is approved.
//
// The waiting mapping counts: its approver reads the live tokens with the
// request, and a token made after that, while no group made
// administrators yet, was made on one administrator's word and was not
// among them. Once the mapping was approved it made administrators.
func scimMakesAdministrators(root string) (bool, error) {
	makes := false
	err := scimStore(root).Read(func(st *scim.State) {
		for _, to := range st.Mapping {
			makes = makes || dual.MapsToAdministrator(to)
		}
	})
	if err != nil || makes {
		return makes, err
	}
	now := time.Now()
	pend, err := dualStore(root).Pending(now)
	for _, r := range pend {
		makes = makes || (r.Kind == dual.Mapping && r.Open(now))
	}
	return makes, err
}

// giveSCIMToken makes the provisioning token, records it (never the
// secret), and prints it once.
func giveSCIMToken(root string, days int, caller *Caller, made scim.TokenMade) error {
	token, kept, err := newSCIMTokenMade(root, days, made)
	if err != nil {
		return err
	}
	w.Human("%s\n", token)
	w.Human("  %sgive this to the identity provider as its bearer token, with the URL\n"+
		"  https://YOUR-ADMIN/scim/v2. Shown once; it replaces any earlier one, and ends on %s:\n"+
		"  make a new one before then, or provisioning stops, taking access away included%s\n",
		dim, kept.Expires.Format("2 January 2006"), reset)
	return recordE(root, caller.auditRecord("scim.token-made", "/", audit.Success,
		map[string]string{"group": ""}))
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
			if err := scimMap(root, group, to); err != nil {
				return err
			}
			return note("scim.mapped", by, group+" → "+to)
		},
		Unmap: func(group, by string) error {
			if err := scimUnmap(root, group); err != nil {
				return err
			}
			return note("scim.unmapped", by, group)
		},
		NewToken: func(made scim.TokenMade) (string, error) {
			t, _, err := newSCIMTokenMade(root, scimTokenDays, made)
			if err != nil {
				return "", err
			}
			return t, note("scim.token-made", made.By, "")
		},
		LiveTokens: func() ([]scim.LiveToken, error) { return liveSCIMTokens(root, time.Now()) },
		TokenEnds: func() (time.Time, bool, error) {
			t, ok, err := readSCIMToken(root, time.Now())
			return t.Expires, ok, err
		},
		RevokeToken: func(by string) error {
			if err := os.Remove(scimTokenPath(root)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return note("scim.token-revoked", by, "")
		},
	}
}
