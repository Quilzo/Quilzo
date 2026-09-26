// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/engagement"
)

// Giving an auditor exactly what the engagement covers, in a form they can
// check without asking us for anything.
//
// `audit issue` writes one file. It carries the evidence in scope, the audit
// entries that recorded each piece being gathered, an inclusion proof for
// every entry, and one head signed with Ed25519 and ML-DSA-65. `audit check`
// verifies it against a published key, and is meant to be run by the auditor
// on their own machine — it touches no store, no log and no network.
//
// The published complaint about the compliance platforms is the awkward
// three-way conversation between the company, the platform and the auditor.
// This is a file.

func engagementsPath(root string) string {
	return filepath.Join(assuranceDir(root), "engagements.jsonl")
}

func cmdEngagement(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return engagementList(root)
	case "open":
		return engagementOpen(root, args[1:])
	case "issue":
		return engagementIssue(root, args[1:])
	case "check":
		return engagementCheck(root, args[1:])
	default:
		return fmt.Errorf("unknown engagement command %q; try list, open, "+
			"issue or check", args[0])
	}
}

func loadEngagements(root string) ([]engagement.Engagement, error) {
	var out []engagement.Engagement
	err := loadJSONL(engagementsPath(root), func(b []byte) error {
		var e engagement.Engagement
		if uerr := json.Unmarshal(b, &e); uerr != nil {
			return uerr
		}
		out = append(out, e)
		return nil
	})
	return out, err
}

func engagementList(root string) error {
	all, err := loadEngagements(root)
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	if w.JSON(all) {
		return nil
	}
	if len(all) == 0 {
		w.Human("no engagements in %s\n", engagementsPath(root))
		return nil
	}
	for _, e := range all {
		colour := green
		if !e.Open(at) {
			colour = dim
		}
		w.Human("%s%s%s  %s%s / %s%s\n", bold, e.ID, reset,
			dim, e.Firm, e.Auditor, reset)
		w.Human("  %s%s%s\n", colour, e.Why(at), reset)
	}
	return nil
}

func engagementOpen(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	firm := fs.String("firm", "", "the firm engaged")
	auditor := fs.String("auditor", "", "the person who will look")
	scope := fs.String("scope", "", "the entity this covers")
	from := fs.String("from", "", "start of the period examined")
	to := fs.String("to", "", "end of it")
	until := fs.String("until", "", "when the access ends, as 2026-12-31")
	frameworks := fs.String("frameworks", "", "comma-separated")
	because := fs.String("because", "", "what the audit is, in one line")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf(
			"usage: quilzo engagement open ID --firm ... --auditor ... " +
				"--scope ... --until 2026-12-31 --because \"...\"")
	}
	period, err := window(*from, *to)
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	e := engagement.Engagement{
		ID: pos[0], Firm: strings.TrimSpace(*firm),
		Auditor: strings.TrimSpace(*auditor),
		Scope:   strings.TrimSpace(*scope), Period: period,
		Opened: at, By: resolveCaller(root, flagToken).Name,
		Kind:    resolveCaller(root, flagToken).Kind,
		Because: strings.TrimSpace(*because),
	}
	for _, f := range strings.Split(*frameworks, ",") {
		if strings.TrimSpace(f) != "" {
			e.Frameworks = append(e.Frameworks, strings.TrimSpace(f))
		}
	}
	if strings.TrimSpace(*until) == "" {
		return fmt.Errorf(
			"--until is required. An engagement that never ends is the " +
				"access nobody revokes, which is the complaint about every " +
				"one of these products")
	}
	parsed, perr := time.Parse("2006-01-02", strings.TrimSpace(*until))
	if perr != nil {
		return fmt.Errorf("--until is a date like 2026-12-31: %w", perr)
	}
	e.Until = parsed.UTC()
	if err := e.Validate(); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	// Granting an outside firm access to this organisation's evidence is a
	// commercial decision: the same authority as publishing.
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	if err := appendJSONL(engagementsPath(root), e); err != nil {
		return err
	}
	record(root, e.Record())

	if w.JSON(e) {
		return nil
	}
	w.Human("%s%s%s opened for %s / %s\n", bold, e.ID, reset, e.Firm,
		e.Auditor)
	w.Human("  %s%s%s\n", dim, e.Why(at), reset)
	w.Human("  %squilzo engagement issue %s writes the package%s\n",
		dim, e.ID, reset)
	return nil
}

func appendJSONL(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func engagementIssue(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	out := fs.String("o", "", "where to write it; standard output otherwise")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo engagement issue ID [-o FILE]")
	}
	all, err := loadEngagements(root)
	if err != nil {
		return err
	}
	var e engagement.Engagement
	var found bool
	for _, candidate := range all {
		if candidate.ID == pos[0] {
			e, found = candidate, true
		}
	}
	if !found {
		return fmt.Errorf("there is no engagement %q", pos[0])
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}

	controls, err := loadControls(root)
	if err != nil {
		return err
	}
	evidence, err := loadEvidence(root)
	if err != nil {
		return err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	signer, err := headSigner(root)
	if err != nil {
		return err
	}
	// Scope comes from the group where one is configured, and is everything
	// where one is not: a deployment with no subsidiaries should not have to
	// declare a tree to hand an auditor a package.
	inScope, err := scopeFor(root, e.Scope)
	if err != nil {
		return err
	}

	at := time.Now().UTC()
	p, err := engagement.Build(e, controls, evidence, events, inScope,
		signer, at)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	// Recorded before it is written, so a package that exists is one the
	// log knows was issued.
	record(root, engagement.Access{
		Engagement: e.ID, At: at, Head: p.Head.Root, Items: p.Count(),
		By: caller.Name,
	}.Record())

	if *out == "" {
		fmt.Println(string(body))
		return nil
	}
	if err := os.WriteFile(*out, body, 0o600); err != nil {
		return err
	}
	if w.JSON(map[string]any{
		"path": *out, "items": p.Count(), "head": p.Head.Root,
	}) {
		return nil
	}
	w.Human("%s%s%s\n", bold, *out, reset)
	w.Human("  %s%d piece(s) of evidence for %d control(s), one signed "+
		"head%s\n", dim, p.Count(), len(p.Controls), reset)
	if len(p.Unevidenced) > 0 {
		w.Human("  %s%d control(s) in scope have nothing in the period, "+
			"named in the package rather than left out: %s%s\n",
			yellow, len(p.Unevidenced), strings.Join(p.Unevidenced, ", "),
			reset)
	}
	w.Human("  %sthe auditor checks it with quilzo engagement check and "+
		"the published key; it touches nothing here%s\n", dim, reset)
	return nil
}

// scopeFor answers whether an entity is inside an engagement's scope.
func scopeFor(root, scope string) (engagement.InScope, error) {
	t, err := loadTree(root)
	if err != nil {
		return nil, err
	}
	if t.Len() == 0 {
		// No group configured. Everything is in scope, which is the right
		// answer for a single company and avoids making a tree a
		// precondition for handing over a package.
		return func(string) bool { return true }, nil
	}
	if _, ok := t.Get(scope); !ok {
		return nil, fmt.Errorf(
			"the engagement covers %q and there is no such entity", scope)
	}
	// The subtree and the ancestors. Scoping to the subtree alone looks
	// tighter and silently drops the group-wide controls the subsidiary
	// depends on; see internal/entity.Covers.
	return func(entity string) bool {
		return entity == "" || t.Covers(scope, entity)
	}, nil
}

// engagementCheck verifies a package, and is the command an auditor runs.
func engagementCheck(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	keys := fs.String("keys", "",
		"the published verifying keys; this store's own otherwise")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo engagement check FILE [--keys FILE]")
	}
	body, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	var p engagement.Package
	if err := json.Unmarshal(body, &p); err != nil {
		return fmt.Errorf("%s is not an engagement package: %w", pos[0], err)
	}
	v, from, err := verifierFor(root, *keys)
	if err != nil {
		return err
	}
	if err := p.Verify(v); err != nil {
		return err
	}
	if w.JSON(map[string]any{
		"engagement": p.Engagement.ID, "items": p.Count(),
		"head": p.Head.Root, "verified": true, "keys": from,
	}) {
		return nil
	}
	w.Human("%s%s verifies%s\n", green, pos[0], reset)
	w.Human("  %s%d piece(s) of evidence, every one with an inclusion "+
		"proof against a head signed by %s%s\n", dim, p.Count(), from, reset)
	w.Human("  %s%s over %s, issued %s%s\n", dim, p.Engagement.Scope,
		p.Engagement.Period, p.Issued.Format("2006-01-02"), reset)
	w.Human("\n%s\n", p.Note)
	return nil
}

// publishedVerifier reads the keys an auditor was given.
//
// From a file rather than from this store, because checking a package
// against keys this machine holds is checking a claim against itself. The
// auditor was handed the public keys separately, and that separation is the
// whole argument.
func publishedVerifier(path string) (*audit.HeadVerifier, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the public keys at %s: %w",
			path, err)
	}
	var pub publishedKeys
	if err := json.Unmarshal(body, &pub); err != nil {
		return nil, fmt.Errorf("%s is not a published key file: %w", path,
			err)
	}
	ed, err := base64.StdEncoding.DecodeString(pub.Ed25519)
	if err != nil {
		return nil, fmt.Errorf("the published Ed25519 key is not base64: %w",
			err)
	}
	ml, err := base64.StdEncoding.DecodeString(pub.MLDSA)
	if err != nil {
		return nil, fmt.Errorf("the published ML-DSA key is not base64: %w",
			err)
	}
	return audit.NewHeadVerifier(ed, ml)
}

// verifierFor loads the public keys a package is checked against.
func verifierFor(root, path string) (*audit.HeadVerifier, string, error) {
	if strings.TrimSpace(path) != "" {
		v, err := publishedVerifier(path)
		if err != nil {
			return nil, "", err
		}
		return v, path, nil
	}
	s, err := headSigner(root)
	if err != nil {
		return nil, "", err
	}
	// This store's own keys. Useful for checking a package before sending
	// it and meaningless as an independent check, so it says which it is.
	return s.Verifier(), "this store's own key", nil
}
