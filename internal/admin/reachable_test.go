// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Every screen can be reached without typing its address.
//
// Five routes under /security answered and nothing linked to any of them:
// /security/scan, /security/policy, /security/inventory, /security/integrity
// and /security/agents. /security/integrity is also where the Verify button
// redirects, so pressing Verify landed somebody on a screen they had no way to
// find and no way back from.
//
// A screen nobody can reach is worse than a screen that does not exist. It was
// written, it is being maintained, and it is answering nobody — and the two
// tests that walk every route open all five happily, because opening a route
// is not the same question as finding it.
//
// Reachable here means one of two things: it is in the navigation, or some
// template links to it. That is deliberately loose. The point is not to
// dictate where a link goes, only that one exists.
func TestEveryScreenIsReachableFromSomewhere(t *testing.T) {
	served := servedRoutes(t)

	// In the navigation.
	reachable := map[string]bool{}
	for _, d := range destinations {
		reachable[d.Path] = true
	}
	// Or linked from a template.
	dir, err := os.Getwd()
	if err != nil {
		t.Skip("no working directory")
	}
	files, err := filepath.Glob(filepath.Join(dir, "assets", "*.html"))
	if err != nil || len(files) == 0 {
		t.Skip("no templates found")
	}
	for _, f := range files {
		b, rerr := os.ReadFile(f)
		if rerr != nil {
			continue
		}
		for _, path := range localPaths(string(b)) {
			reachable[path] = true
		}
	}

	// The WebAuthn ceremony endpoints, which a script callsrather than a link
	// or a form reaching. They are the only such endpoints in the program:
	// passkeys.html and passkeysignin.html are the two pages whose policy
	// permits a script, by nonce, and these are what that script talks to.
	//
	// Written down rather than matched by prefix, so a sixth passkey route
	// added later is reported rather than excused by a pattern.
	byScript := map[string]string{
		"/passkeys/challenge":       "passkeys.html asks for a registration challenge",
		"/passkeys/register":        "passkeys.html posts what the authenticator made",
		"/signin/passkey/challenge": "passkeysignin.html asks for a sign-in challenge",
		"/signin/passkey/verify":    "passkeysignin.html posts the assertion",
	}
	for path := range byScript {
		if !served[path] {
			t.Errorf("%q is excused as a script endpoint and is not a route; "+
				"the exemption is stale", path)
		}
	}

	// Routes that are not screens: write-only endpoints, subtrees needing a
	// name, and the API. Written down rather than skipped quietly.
	var unreachable []string
	for route := range served {
		if strings.HasSuffix(route, "/") && route != "/" {
			continue
		}
		if _, excused := notAScreen[route]; excused {
			continue
		}
		if reachable[route] {
			continue
		}
		if _, script := byScript[route]; script {
			continue
		}
		unreachable = append(unreachable, route)
	}
	sort.Strings(unreachable)
	for _, route := range unreachable {
		t.Errorf("%s answers and nothing links to it, so the only way there "+
			"is to type the address. Put it in the navigation or link it from "+
			"a screen that does", route)
	}
}

// localPaths collects the local paths a template links to or posts to.
//
// Both href and action, because a write endpoint is reached by submitting a
// form rather than by following a link, and one that no form posts to is as
// unreachable as a screen nothing links to.
//
// Anything carrying a template action is skipped rather than guessed at: a
// path built from a variable is one this cannot resolve, and reporting it
// would be inventing a link.
func localPaths(src string) []string {
	var out []string
	for _, attr := range []string{`href="`, `action="`} {
		for _, seg := range strings.Split(src, attr)[1:] {
			end := strings.IndexByte(seg, '"')
			if end < 0 {
				continue
			}
			path := seg[:end]
			if !strings.HasPrefix(path, "/") || strings.Contains(path, "{{") {
				continue
			}
			if i := strings.IndexAny(path, "?#"); i >= 0 {
				path = path[:i]
			}
			out = append(out, path)
		}
	}
	return out
}
