// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
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
	// One at a time. `fediverse block a.example b.example` refused the first
	// and said nothing of the second, which went on being served.
	fs := flag.NewFlagSet("fediverse block", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "refuse it, and drop its follows; at a terminal, without this, only say what would go")
	var pos []string
	if err := parseFlags(fs, args, &pos, 1); err != nil {
		return err
	}
	if len(pos) == 0 {
		return errMisused{fmt.Errorf(
			"usage: quilzo fediverse block HOST-OR-ACTOR [--yes]\n" +
				"  a host — example.social — covers every account on it")}
	}
	target, actor, err := blockTarget(pos[0])
	if err != nil {
		return err
	}
	list, err := loadBlocklist(root)
	if err != nil {
		return err
	}

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
	// Unblocking lets them in again; the follows it drops are gone.
	if erasureHeld(*yes, fmt.Sprintf("this would refuse %s and drop whoever follows the site from there",
		onOneLine(target))) {
		return nil
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
	// What is refused and who stopped following, under --json; it answered
	// nothing, exit 0.
	if w.JSON(map[string]any{"blocked": target, "followers_removed": dropped}) {
		return nil
	}
	w.Human("%s is refused\n", target)
	if dropped > 0 {
		w.Human("  %s%d follower(s) from there removed%s\n", dim, dropped, reset)
	}
	w.Human("  %sthe inbox answers as usual and does nothing, so nobody is "+
		"told they were blocked%s\n", dim, reset)
	return nil
}

// blockTarget is what `fediverse block` was given, as the list keeps it: a
// host, in lower case, or one account's actor id, the https address an
// inbox is sent a Follow from and Blocks compares whole. Anything else is
// refused as the command line's mistake, exit 2, and nothing is written.
//
// The list took any word as one or the other. `fediverse block ""` listed
// an empty host, `fediverse block "not a host at all"` a host nothing can
// have, and `@spam@bad.example` an account no actor id is ever equal to:
// `fediverse blocked` showed each as refused, it refused nobody, and the
// operator who typed it believed the account or the instance was blocked.
// Unblocking takes any word still, so what an earlier version listed can
// be taken off.
func blockTarget(typed string) (target string, actor bool, err error) {
	target = strings.TrimSpace(typed)
	hint := "a host, example.social, for every account on it, or one account's " +
		"actor id, https://example.social/users/NAME, which its profile links to"
	switch {
	case target == "":
		return "", false, errMisused{fmt.Errorf("usage: quilzo fediverse block HOST-OR-ACTOR: %s", hint)}
	case strings.Contains(target, "://"):
		u, perr := url.Parse(target)
		if perr != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
			strings.ContainsAny(target, " \t\r\n") {
			return "", false, errMisused{fmt.Errorf("%q is not an actor id, which is an https address "+
				"with no name or password in it; block %s", onOneLine(target), hint)}
		}
		return target, true, nil
	case strings.Contains(target, "@"):
		return "", false, errMisused{fmt.Errorf("%q is an account's handle, which no actor id is ever "+
			"equal to, so blocking it would block nobody; block %s", onOneLine(target), hint)}
	}
	host := strings.ToLower(target)
	if _, ipErr := netip.ParseAddr(host); ipErr != nil && !isHostName(host) {
		return "", false, errMisused{fmt.Errorf("%q is not a host; block %s", onOneLine(target), hint)}
	}
	return host, false, nil
}

// isHostName reports whether s is a DNS name an actor's address can have:
// labels of letters, digits and hyphens, none starting or ending with one,
// joined by dots. An internationalised name is written in its xn-- form,
// as an address carries it.
func isHostName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// fediverseUnblock takes one back off the list.
func fediverseUnblock(root string, args []string) error {
	args, err := positionals(args, 1)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return errMisused{fmt.Errorf("usage: quilzo fediverse unblock HOST-OR-ACTOR")}
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
		return errNotFound{fmt.Errorf("%s is not on the list; `quilzo fediverse blocked` "+
			"shows what is", target)}
	}
	if err := saveJSON(blockPath(root), list); err != nil {
		return err
	}
	record(root, resolveCaller(root, flagToken).auditRecord("fediverse.unblock",
		"/", audit.Success, map[string]string{"target": target}))
	if w.JSON(map[string]any{"unblocked": target}) {
		return nil
	}
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
