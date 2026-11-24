// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package profile is the security profile: the features a security install
// has no use for, switched off while the program runs, and the signed
// record of which ones are off.
//
// # Why off, and not removed
//
// Quilzo grew as a content platform, and a security programme's record has
// no use for much of what that left behind: taking payments, posting to the
// fediverse, working a person's desktop or a web browser for an agent,
// testing page variants on visitors. Each is code an attacker can reach, and
// NIST SP 800-53 CM-7 (least functionality) asks that what is not needed is
// not running. Deleting the code would answer that, and would also break
// every installation that does use it, which the project does not do: a
// feature is switched off by a recorded decision, never deleted.
//
// So a profile is a baseline, applied by `quilzo init --profile security`
// or `quilzo profile apply security`, and every feature in the catalogue is
// off under it. An administrator can switch any one back on, and that takes
// a written reason, which is kept with who made the change and when. The
// standard profile, which a store has when nobody applied one, has
// everything on, exactly as before this package existed.
//
// # Where it is enforced
//
// At every surface a feature is reached from, by name rather than by a
// check inside each feature: the command line refuses a switched-off
// command before it runs, the admin and the public site answer a
// switched-off address with 404 (Gate), the agent interface does not offer
// its operations, and an agent run is refused the browser. The catalogue
// lists those names, and the tests that walk the router and the command
// table hold the catalogue to what the program serves, so a feature cannot
// keep a door the catalogue does not know about.
//
// # The manifest
//
// The state is written as a feature manifest, signed with the store's head
// keys (internal/audit's statements, under their own context), and attached
// to CM-7 in Quilzo's own OSCAL component (Annotate). It is evidence an
// auditor can check offline: which features were off, since when, which were
// switched back on, by whom and why, and that nobody edited the list after
// it was signed. It is attached only while it says what the gates enforce
// (Manifest.Says): the gates read the state, and a state changed outside the
// record leaves a manifest that verifies and is no longer true.
package profile
