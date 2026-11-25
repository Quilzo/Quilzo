// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/plaintext"
)

// Okta: every user by their login, their status, the factors they have
// enrolled and whether one cannot be phished, who is an administrator and
// a super administrator, and the sign-on policies.
//
// An Okta API token is not scoped: it acts with whatever administrator
// roles the person who made it holds. So the token's own roles are read
// first, and a run whose token holds any but Read-Only Administrator
// reads nothing else.

func init() {
	define(&Recipe{
		Name: "okta",
		Privilege: []string{
			"An API token made by an administrator who holds the Read-Only Administrator role and no other.",
			"The token's own roles are read before anything else, and a token that holds any other role is " +
				"refused before it reads a user.",
		},
		Fresh:  24 * time.Hour,
		checks: "grant",
		check:  oktaGrant,
		pull:   pullOkta,
	})
}

// oktaReadOnly is the one role an Okta token a recipe reads with may hold.
const oktaReadOnly = "READ_ONLY_ADMIN"

// oktaGrant refuses a token whose maker holds more than Read-Only
// Administrator.
func oktaGrant(records []map[string]string) error {
	if len(records) == 0 {
		return fmt.Errorf("%w: the token's maker holds no administrator role, so what it may read is unknown",
			errRefusedGrant)
	}
	var extra []string
	for _, r := range records {
		if r["type"] != oktaReadOnly {
			extra = append(extra, plaintext.Clip(r["type"], 64, "…"))
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("%w: the token's maker holds %s, and reading needs %s alone. Make the token as an "+
			"administrator who holds Read-Only Administrator only", errRefusedGrant, strings.Join(extra, ", "), oktaReadOnly)
	}
	return nil
}

// oktaResistant are the factors that cannot be phished: a passkey or a
// security key, and Okta FastPass.
var oktaResistant = map[string]bool{"webauthn": true, "signed_nonce": true}

func pullOkta(r *Run, to evidence.PullTo) error {
	users, err := r.Endpoint("users")
	if err != nil {
		return err
	}
	factors, err := r.Endpoint("factors")
	if err != nil {
		return err
	}
	admins, err := r.Endpoint("administrators")
	if err != nil {
		return err
	}
	roles, err := r.Endpoint("administrator-roles")
	if err != nil {
		return err
	}
	isAdmin := map[string]bool{}
	for _, a := range admins.Records {
		isAdmin[a.Fields["id"]] = true
	}
	super := map[string]bool{}
	for _, role := range roles.Records {
		if role.Fields["type"] == "SUPER_ADMIN" && role.Fields["status"] == "ACTIVE" {
			super[role.Fields["parent"]] = true
		}
	}
	read := map[string]bool{}
	for _, p := range factors.Parents {
		read[p] = true
	}
	active := map[string][]string{}
	for _, f := range factors.Records {
		if f.Fields["status"] == "ACTIVE" {
			active[f.Fields["parent"]] = append(active[f.Fields["parent"]], strings.ToLower(f.Fields["type"]))
		}
	}
	for _, u := range users.Records {
		uid := u.Fields["id"]
		id, err := to.Subject(u.Fields["login"], "account", u.Place)
		if err != nil {
			return err
		}
		f := &facts{to: to, about: id, place: u.Place}
		f.text("account.status", u.Fields["status"])
		f.bool("account.active", u.Fields["status"] == "ACTIVE")
		f.bool("account.admin", isAdmin[uid])
		f.bool("role.super-admin", super[uid])
		if read[uid] {
			kinds := active[uid]
			sort.Strings(kinds)
			resistant := false
			for _, k := range kinds {
				resistant = resistant || oktaResistant[k]
			}
			f.bool("mfa.enrolled", len(kinds) > 0)
			f.bool("mfa.phishing-resistant", resistant)
			f.text("mfa.methods", strings.Join(dedupe(kinds), ","))
		}
		if f.err != nil {
			return f.err
		}
	}
	policies, err := r.Endpoint("session-policies")
	if err != nil {
		return err
	}
	for _, p := range policies.Records {
		id, err := to.Asset("other", "okta-policy/"+p.Fields["id"], named(p.Fields["name"]), p.Place)
		if err != nil {
			return err
		}
		f := &facts{to: to, about: id, place: p.Place}
		f.text("policy.status", p.Fields["status"])
		if n, ok := number(p.Fields["priority"]); ok {
			f.number("policy.priority", n)
		}
		if f.err != nil {
			return f.err
		}
	}
	return nil
}

func dedupe(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
