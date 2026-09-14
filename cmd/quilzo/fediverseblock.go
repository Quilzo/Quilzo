// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/activitypub"
	"github.com/quilzo/quilzo/internal/audit"
)

// Refusing an instance.
//
// # What there was
//
// Nothing. handleFollow accepted any actor whose signature checked out, up to
// a hundred thousand followers, and the only way to be rid of one was to stop
// the server and edit followers.json by hand — after which it could follow
// again immediately. An operator being harassed from one instance had no
// answer at all, which is not a position anybody chose; it is a feature nobody
// wrote.
//
// # A host, not an actor
//
// Both are accepted and a host is what an operator reaches for, because
// abuse arrives from an instance rather than from a name they can enumerate.
// A blocked host covers every actor on it, now and later, which is the
// property that makes a block worth applying.
//
// # Silence, not a refusal
//
// The inbox answers 202 and does nothing. Telling a sender they are blocked is
// an invitation to come back from somewhere else, and the record of the
// refusal belongs on this side of it — which is what the audit entry is for.

// blockPath is where the list lives. Beside the follower list, because they
// are the same kind of thing: who this site is in a relationship with.
func blockPath(root string) string {
	return filepath.Join(root, "fediverse", "blocked.json")
}

// Blocklist is the hosts and actors this site will not hear from.
type Blocklist struct {
	// Hosts is matched against the actor's host, case-folded.
	Hosts []string `json:"hosts,omitempty"`
	// Actors is matched whole, for the case where one account misbehaves and
	// the instance it is on is otherwise fine.
	Actors []string `json:"actors,omitempty"`
}

// Blocks reports whether an actor URL is refused.
func (b *Blocklist) Blocks(actor string) bool {
	if b == nil {
		return false
	}
	for _, a := range b.Actors {
		if strings.EqualFold(a, actor) {
			return true
		}
	}
	u, err := url.Parse(actor)
	if err != nil {
		// An actor id that will not parse is not one this site issued a
		// follow to. Not blocked here; the signature check refuses it.
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range b.Hosts {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}

func loadBlocklist(root string) (*Blocklist, error) {
	b := &Blocklist{}
	if err := loadJSON(blockPath(root), b); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return b, nil
}

// fediverseBlock refuses a host or an actor, and drops it if it was following.
func fediverseBlock(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(
			"usage: quilzo fediverse block HOST-OR-ACTOR\n" +
				"  a host — example.social — covers every account on it")
	}
	target := strings.TrimSpace(args[0])
	list, err := loadBlocklist(root)
	if err != nil {
		return err
	}

	actor := strings.Contains(target, "://") || strings.Contains(target, "@")
	if actor {
		if list.Blocks(target) {
			return fmt.Errorf("%s is already refused", target)
		}
		list.Actors = append(list.Actors, target)
		sort.Strings(list.Actors)
	} else {
		host := strings.ToLower(target)
		for _, h := range list.Hosts {
			if strings.EqualFold(h, host) {
				return fmt.Errorf("%s is already refused", host)
			}
		}
		list.Hosts = append(list.Hosts, host)
		sort.Strings(list.Hosts)
	}
	if err := os.MkdirAll(filepath.Dir(blockPath(root)), 0o700); err != nil {
		return err
	}
	if err := saveJSON(blockPath(root), list); err != nil {
		return err
	}

	// And remove whoever is already following from there. A block that leaves
	// the existing relationship in place blocks nothing worth blocking: the
	// posts keep going out, which is the half that reaches them.
	dropped := dropBlockedFollowers(root, list)

	record(root, resolveCaller(root, flagToken).auditRecord("fediverse.block",
		"/", audit.Success, map[string]string{
			"target": target, "dropped": fmt.Sprint(dropped),
		}))
	w.Human("%s is refused\n", target)
	if dropped > 0 {
		w.Human("  %s%d follower(s) from there removed%s\n", dim, dropped, reset)
	}
	w.Human("  %sthe inbox answers as usual and does nothing, so nobody is "+
		"told they were blocked%s\n", dim, reset)
	return nil
}

// fediverseUnblock takes one back off the list.
func fediverseUnblock(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: quilzo fediverse unblock HOST-OR-ACTOR")
	}
	target := strings.TrimSpace(args[0])
	list, err := loadBlocklist(root)
	if err != nil {
		return err
	}
	before := len(list.Hosts) + len(list.Actors)
	list.Hosts = without(list.Hosts, target)
	list.Actors = without(list.Actors, target)
	if len(list.Hosts)+len(list.Actors) == before {
		return fmt.Errorf("%s is not on the list; `quilzo fediverse blocked` "+
			"shows what is", target)
	}
	if err := saveJSON(blockPath(root), list); err != nil {
		return err
	}
	record(root, resolveCaller(root, flagToken).auditRecord("fediverse.unblock",
		"/", audit.Success, map[string]string{"target": target}))
	w.Human("%s is no longer refused\n", target)
	w.Human("  %sthey are not following again by themselves; a block removes "+
		"the follow and unblocking does not put it back%s\n", dim, reset)
	return nil
}

// fediverseBlocked lists what is refused.
func fediverseBlocked(root string) error {
	list, err := loadBlocklist(root)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"hosts": list.Hosts, "actors": list.Actors}) {
		return nil
	}
	if len(list.Hosts)+len(list.Actors) == 0 {
		w.Human("nothing is refused\n")
		w.Human("  %squilzo fediverse block example.social%s\n", dim, reset)
		return nil
	}
	for _, h := range list.Hosts {
		w.Human("  %-40s %severy account on it%s\n", h, dim, reset)
	}
	for _, a := range list.Actors {
		w.Human("  %-40s %sone account%s\n", a, dim, reset)
	}
	return nil
}

func without(all []string, drop string) []string {
	var out []string
	for _, v := range all {
		if !strings.EqualFold(v, drop) {
			out = append(out, v)
		}
	}
	return out
}

// dropBlockedFollowers removes every follower the list now refuses.
func dropBlockedFollowers(root string, list *Blocklist) int {
	followers := activitypub.NewFollowers()
	if err := loadJSON(fediverseFollowersPath(root), followers); err != nil {
		return 0
	}
	dropped := 0
	for _, f := range followers.All() {
		if list.Blocks(f.Actor) && followers.Remove(f.Actor) {
			dropped++
		}
	}
	if dropped > 0 {
		_ = saveJSON(fediverseFollowersPath(root), followers)
	}
	return dropped
}
