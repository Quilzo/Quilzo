// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/feature"
)

// Proposals: packages an agent drafted, waiting for a person to read them.
//
// An agent may draft a package and may not install one. What it drafts
// waits here, on the Make and Approvals screens and in `quilzo feature
// proposals`, until a person reads it and installs it as their own decision,
// under the same card and the same approvals as a package they brought
// themselves. Nothing about who approves changes: the agent counts as
// nobody.

const (
	// proposalTTL is how long a proposal waits to be read.
	proposalTTL = 14 * 24 * time.Hour
	// maxProposals bounds what agents can leave waiting, so a loop that
	// proposes on every turn fills nobody's screen.
	maxProposals = 20
)

type proposal struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Title   string `json:"title"`
	// What says what it is: a site built from a description, a site brought
	// from an address, or a feature an agent wrote.
	What string `json:"what"`
	// By is the agent; For is the person it was acting for.
	By     string    `json:"by"`
	For    string    `json:"for"`
	At     time.Time `json:"at"`
	Digest string    `json:"digest"`
	Notes  []string  `json:"notes,omitempty"`
}

func proposalsDir(root string) string { return filepath.Join(featuresDir(root), "proposed") }

// proposalPath is where a proposal's package is kept: a file a person can
// read and install from the command line.
func proposalPath(root, id string) string { return filepath.Join(proposalsDir(root), id+".json") }

func proposalMetaPath(root, id string) string {
	return filepath.Join(proposalsDir(root), id+".proposal.json")
}

// proposingAgent is who an agent's act is recorded as: the app or agent itself,
// for the person it acts for.
func proposingAgent(caller *Caller) (agentName string, ai *Caller) {
	c := *caller
	c.Kind = audit.KindAI
	if c.Model == "" {
		c.Model = "mcp-client"
	}
	return c.Model, &c
}

// proposeFeature keeps a package an agent drafted for a person to read.
// Proposing the same package again answers with the proposal already
// waiting.
func proposeFeature(root string, body []byte, what string, notes []string, caller *Caller) (proposal, *feature.Package, error) {
	var out proposal
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return out, nil, fmt.Errorf("proposing a feature is drafting one: %w", err)
	}
	pkg, body, err := readFeatureBytes(root, body, "")
	if err != nil {
		return out, nil, err
	}
	digest, err := pkg.Digest()
	if err != nil {
		return out, nil, err
	}
	waiting, err := proposals(root)
	if err != nil {
		return out, nil, err
	}
	// The same package again is the proposal already waiting; a newer
	// version of one proposed for the same person replaces it, so a person
	// reads the latest and not a pile of drafts.
	kept := 0
	for _, w := range waiting {
		switch {
		case w.Digest == digest:
			return w, pkg, nil
		case w.Name == pkg.Name && strings.EqualFold(w.For, caller.Name):
			clearProposal(root, w.ID)
		default:
			kept++
		}
	}
	if kept >= maxProposals {
		return out, nil, fmt.Errorf("%d proposals are already waiting to be read; a person reads or sets some aside first",
			kept)
	}
	id := make([]byte, 6)
	if _, err := rand.Read(id); err != nil {
		return out, nil, err
	}
	by, ai := proposingAgent(caller)
	out = proposal{ID: hex.EncodeToString(id), Name: pkg.Name, Version: pkg.Version, Title: pkg.Title, What: what,
		By: by, For: caller.Name, At: time.Now().UTC(), Digest: digest, Notes: notes}
	if err := os.MkdirAll(proposalsDir(root), 0o700); err != nil {
		return out, nil, err
	}
	if err := atomicfile.Write(proposalPath(root, out.ID), body, 0o600); err != nil {
		return out, nil, err
	}
	if err := saveJSON(proposalMetaPath(root, out.ID), out); err != nil {
		return out, nil, err
	}
	if err := recordE(root, ai.auditRecord("feature.proposed", "/", audit.Success, map[string]string{
		"feature": pkg.Name, "version": pkg.Version, "digest": digest[:16], "proposal": out.ID, "what": what})); err != nil {
		return out, nil, err
	}
	return out, pkg, nil
}

// proposals are what is waiting, newest first. One that lapsed, or whose
// package is now installed, is cleared away.
func proposals(root string) ([]proposal, error) {
	ents, err := os.ReadDir(proposalsDir(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	installed, err := loadInstalledFeatures(root)
	if err != nil {
		return nil, err
	}
	var out []proposal
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".proposal.json")
		if !ok || !reFeatureID.MatchString(id) {
			continue
		}
		var pr proposal
		if loadJSON(proposalMetaPath(root, id), &pr) != nil || pr.ID != id {
			continue
		}
		in := installed[pr.Name]
		if time.Since(pr.At) > proposalTTL || (in != nil && in.Digest == pr.Digest) {
			clearProposal(root, id)
			continue
		}
		out = append(out, pr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out, nil
}

func clearProposal(root, id string) {
	_ = os.Remove(proposalPath(root, id))
	_ = os.Remove(proposalMetaPath(root, id))
}

// proposalBody is a waiting proposal's package.
func proposalBody(root, id string) ([]byte, proposal, error) {
	var pr proposal
	if !reFeatureID.MatchString(id) {
		return nil, pr, fmt.Errorf("%q is not a proposal", id)
	}
	if err := loadJSON(proposalMetaPath(root, id), &pr); err != nil || time.Since(pr.At) > proposalTTL {
		return nil, pr, fmt.Errorf("no proposal %s is waiting", id)
	}
	body, err := os.ReadFile(proposalPath(root, id))
	if err != nil {
		return nil, pr, fmt.Errorf("no proposal %s is waiting", id)
	}
	return body, pr, nil
}

// dismissProposal sets a proposal aside unread: a person's decision, made
// by whoever may install features.
func dismissProposal(root, id string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActInstall, "/"); err != nil {
		return fmt.Errorf("a proposal is set aside by whoever may install features: %w", err)
	}
	if caller.Kind == audit.KindAI {
		return errors.New("a proposal is set aside by a person")
	}
	_, pr, err := proposalBody(root, id)
	if err != nil {
		return err
	}
	clearProposal(root, id)
	return recordE(root, caller.auditRecord("feature.proposal_dismissed", "/", audit.Success, map[string]string{
		"feature": pr.Name, "version": pr.Version, "proposal": id}))
}

// featureProposalsCmd is `quilzo feature proposals [--dismiss ID]`.
func featureProposalsCmd(root string, args []string) error {
	fs := flag.NewFlagSet("feature proposals", flag.ContinueOnError)
	dismiss := fs.String("dismiss", "", "set a proposal aside unread")
	if err := fs.Parse(args); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if *dismiss != "" {
		if err := dismissProposal(root, *dismiss, caller); err != nil {
			return err
		}
		w.Human("set proposal %s aside\n", *dismiss)
		return nil
	}
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	list, err := proposals(root)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"proposals": list}) {
		return nil
	}
	if len(list) == 0 {
		w.Human("no agent has proposed anything\n")
		return nil
	}
	for _, pr := range list {
		w.Human("%s  %s %s, %s, by %s for %s, %s\n", pr.ID, pr.Title, pr.Version, pr.What, pr.By, pr.For,
			pr.At.Local().Format("2 Jan 15:04"))
		for _, n := range pr.Notes {
			w.Human("    %s%s%s\n", dim, n, reset)
		}
		w.Human("    read it: %s\n    install it: quilzo feature install %s\n", proposalPath(root, pr.ID),
			proposalPath(root, pr.ID))
	}
	return nil
}
