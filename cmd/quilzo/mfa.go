// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Two factors for every person (SP 800-63B-4 AAL2): from when.
//
// An installation running before two factors became the rule is given a
// grace, so nobody already signing in with a token is locked out the day
// they upgrade: the first time this version starts, it writes down the end
// of the grace, and from then on that date is the one every part of the
// program reads. During it, a token alone still reaches the admin, with a
// notice on every page and a posture finding naming who has no passkey;
// after it, a token is a first factor only.

// mfaGrace is how long an installation has to give everyone a passkey.
const mfaGrace = 14 * 24 * time.Hour

type mfaState struct {
	// EnforcedFrom is when two factors became compulsory here.
	EnforcedFrom time.Time `json:"enforced_from"`
}

func mfaPath(root string) string { return filepath.Join(root, "mfa.json") }

// mfaFrom is when two factors are compulsory from, written down the first
// time it is asked for. A state file that cannot be read or written is
// answered with now: the grace is a courtesy, and losing it never opens
// anything.
func mfaFrom(root string, now time.Time) time.Time {
	var from time.Time
	err := atomicfile.Update(mfaPath(root), func(st *mfaState) error {
		if !st.EnforcedFrom.IsZero() {
			from = st.EnforcedFrom
			return atomicfile.ErrUnchanged
		}
		st.EnforcedFrom = now.UTC().Add(mfaGrace)
		from = st.EnforcedFrom
		return nil
	})
	if err != nil {
		return now
	}
	return from
}

// mfaFromIfSet is the date without writing one, for the commands that
// report it.
func mfaFromIfSet(root string) (time.Time, bool) {
	var st mfaState
	if err := loadJSON(mfaPath(root), &st); err != nil {
		return time.Time{}, false
	}
	return st.EnforcedFrom, !st.EnforcedFrom.IsZero()
}

// withoutSecondFactor are the people with access here who have no way to
// sign in with two factors: no passkey, and no single sign-on that covers
// their address and can say it used two (a SAML provider with no way set
// up to say so cannot). Agents are not people and are left out, as is
// anybody whose only bindings deny.
func withoutSecondFactor(root string) []string {
	pol, err := loadPolicy(root)
	if err != nil || pol == nil {
		return nil
	}
	pk := &admin.Passkeys{}
	_ = loadJSON(passkeysPath(root), pk)
	keyed := map[string]bool{}
	for _, c := range pk.Credentials {
		keyed[strings.ToLower(c.Principal)] = true
	}
	samls, _ := loadSAML(root)
	oidc, _ := loadOIDC(root)
	covered := func(name string) bool {
		for i := range samls {
			if samls[i].Owns(name) && samls[i].SaysMFA() {
				return true
			}
		}
		if oidc == nil || !strings.Contains(name, "@") {
			return false
		}
		if len(oidc.Domains) == 0 {
			return true
		}
		_, domain, _ := strings.Cut(strings.ToLower(name), "@")
		for _, d := range oidc.Domains {
			if strings.EqualFold(d, domain) {
				return true
			}
		}
		return false
	}
	grants := map[string]bool{}
	for _, b := range pol.Bindings {
		if !b.Deny {
			grants[b.Principal] = true
		}
	}
	var out []string
	for name := range grants {
		if strings.HasPrefix(name, agent.PrincipalPrefix) || keyed[strings.ToLower(name)] || covered(name) {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
