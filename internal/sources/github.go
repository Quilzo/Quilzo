// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/evidence"
)

// GitHub, through a GitHub App installed on the organisation: whether the
// organisation requires two-factor authentication and who has none, who
// owns it, whether each repository's default branch is protected, by
// classic protection or by rulesets, and what Actions may do.
//
// A member is their login, named "github:" and the login in the subject
// map, so that a login is never taken for an account of the same name in
// another tool.

func init() {
	define(&Recipe{
		Name: "github",
		Privilege: []string{
			"A GitHub App of its own, installed on the organisation, with these permissions at the Read-only level " +
				"and no others: organisation Members, organisation Administration, repository Administration and " +
				"repository Metadata.",
			"The installation token is asked for exactly these, and one that comes back holding any other, or any " +
				"at the write level, is refused before it is used.",
		},
		Gaps: map[string]string{
			"without-2fa": "GitHub lists the members without two-factor authentication to organisation owners only.",
		},
		Fresh: 24 * time.Hour,
		pull:  pullGitHub,
	})
}

func pullGitHub(r *Run, to evidence.PullTo) error {
	org := r.Param("org")
	orgRead, err := r.Endpoint("org")
	if err != nil {
		return err
	}
	orgID, err := to.Asset("other", "github-org/"+org, "GitHub organisation "+org, "/params")
	if err != nil {
		return err
	}
	for _, o := range orgRead.Records {
		f := &facts{to: to, about: orgID, place: o.Place}
		f.yes("org.2fa-required", o.Fields["two_factor"])
		f.text("org.default-permission", o.Fields["default_permission"])
		f.yes("org.members-can-create-public", o.Fields["public_repositories"])
		if f.err != nil {
			return f.err
		}
	}

	members, err := r.Endpoint("members")
	if err != nil {
		return err
	}
	without, err := r.Endpoint("without-2fa")
	if err != nil {
		return err
	}
	owners, err := r.Endpoint("owners")
	if err != nil {
		return err
	}
	no2fa, owner := logins(without), logins(owners)
	readWithout := without.Refused == 0 || len(without.Records) > 0
	if !readWithout {
		if err := gap(to, orgID, "without-2fa", recipes["github"].Gaps["without-2fa"], without.Refused); err != nil {
			return err
		}
	}
	for _, m := range members.Records {
		login := m.Fields["login"]
		id, err := to.Subject("github:"+strings.ToLower(login), "account", m.Place)
		if err != nil {
			return err
		}
		f := &facts{to: to, about: id, place: m.Place}
		f.bool("org.member", true)
		f.bool("org.owner", owner[strings.ToLower(login)])
		if readWithout {
			f.bool("2fa.enabled", !no2fa[strings.ToLower(login)])
		}
		if f.err != nil {
			return f.err
		}
	}

	repos, err := r.Endpoint("repositories")
	if err != nil {
		return err
	}
	branch, err := r.Endpoint("branch")
	if err != nil {
		return err
	}
	rules, err := r.Endpoint("rules")
	if err != nil {
		return err
	}
	actions, err := r.Endpoint("repository-actions")
	if err != nil {
		return err
	}
	protected := map[string]bool{}
	branchRead := map[string]bool{}
	for _, b := range branch.Records {
		branchRead[b.Fields["parent"]] = true
		if v, ok := yes(b.Fields["protected"]); ok && v {
			protected[b.Fields["parent"]] = true
		}
	}
	type ruleset struct{ pr, forcePush, deletion, checks bool }
	sets := map[string]*ruleset{}
	approvals := map[string]float64{}
	for _, p := range rules.Parents {
		sets[p] = &ruleset{}
	}
	for _, rule := range rules.Records {
		s := sets[rule.Fields["parent"]]
		if s == nil {
			continue
		}
		switch rule.Fields["rule"] {
		case "pull_request":
			s.pr = true
			if n, ok := number(rule.Fields["approvals"]); ok && n > approvals[rule.Fields["parent"]] {
				approvals[rule.Fields["parent"]] = n
			}
		case "non_fast_forward":
			s.forcePush = true
		case "deletion":
			s.deletion = true
		case "required_status_checks":
			s.checks = true
		}
	}
	allowed := map[string]map[string]string{}
	for _, a := range actions.Records {
		allowed[a.Fields["parent"]] = a.Fields
	}
	for _, repo := range repos.Records {
		name := repo.Fields["name"]
		full := repo.Fields["full_name"]
		if full == "" {
			full = org + "/" + name
		}
		id, err := to.Asset("repository", strings.ToLower(full), full, repo.Place)
		if err != nil {
			return err
		}
		f := &facts{to: to, about: id, place: repo.Place}
		f.yes("repo.private", repo.Fields["private"])
		f.yes("repo.archived", repo.Fields["archived"])
		f.text("repo.default-branch", repo.Fields["default_branch"])
		if branchRead[name] {
			f.bool("branch.protected", protected[name])
		}
		if s := sets[name]; s != nil {
			f.bool("ruleset.pull-request", s.pr)
			f.number("ruleset.approvals", approvals[name])
			f.bool("ruleset.no-force-push", s.forcePush)
			f.bool("ruleset.no-deletion", s.deletion)
			f.bool("ruleset.status-checks", s.checks)
		}
		if branchRead[name] && sets[name] != nil {
			ruled := sets[name].pr || sets[name].forcePush || sets[name].deletion || sets[name].checks
			switch {
			case protected[name] && ruled:
				f.text("branch.protection", "classic and rulesets")
			case protected[name]:
				f.text("branch.protection", "classic")
			case ruled:
				f.text("branch.protection", "rulesets")
			default:
				f.text("branch.protection", "none")
			}
		}
		if a := allowed[name]; a != nil {
			f.yes("actions.enabled", a["enabled"])
			f.text("actions.allowed", a["allowed"])
		}
		if f.err != nil {
			return f.err
		}
	}

	for _, ep := range []string{"actions", "workflow-token"} {
		read, err := r.Endpoint(ep)
		if err != nil {
			return err
		}
		for _, a := range read.Records {
			f := &facts{to: to, about: orgID, place: a.Place}
			if ep == "actions" {
				f.text("actions.enabled-repositories", a.Fields["repositories"])
				f.text("actions.allowed", a.Fields["allowed"])
			} else {
				f.text("actions.token-permissions", a.Fields["permissions"])
				f.yes("actions.can-approve-reviews", a.Fields["approves"])
			}
			if f.err != nil {
				return f.err
			}
		}
	}
	return nil
}

func logins(r Read) map[string]bool {
	out := map[string]bool{}
	for _, rec := range r.Records {
		out[strings.ToLower(rec.Fields["login"])] = true
	}
	return out
}
