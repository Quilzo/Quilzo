// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/attest"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
)

// The attestations the public instance shows (internal/attest): set as a
// draft by an administrator, published by two (autonomy level 4: one
// proposes, another approves), and sent one way, signed (outpostcmd.go).
//
// The draft is a small typed file the admin publishes. A later theme feeds
// it from the register: whatever produces it writes attest.File, format 1,
// and every surface here checks it with attest.Validate before it is kept
// or sent.

// dualPublishExternal is a publication to the public instance, waiting for
// a second administrator (internal/dual keeps the request, this file
// applies it).
const dualPublishExternal = "publish-external"

func attestationsPath(root string) string { return filepath.Join(root, "attestations.json") }

// publishChange is what a publication request carries: the draft it is for,
// by digest, so an approval sends what was proposed and nothing changed
// since.
type publishChange struct {
	Digest string `json:"digest"`
	Target string `json:"target"`
}

func parseAttestations(body []byte, now time.Time) (*attest.File, error) {
	f, err := attest.Parse(body, now)
	if err != nil {
		return nil, errMisused{err}
	}
	return f, nil
}

// loadDraft is the draft, nil when none has been set.
func loadDraft(root string, now time.Time) (*attest.File, error) {
	body, err := os.ReadFile(attestationsPath(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseAttestations(body, now)
}

// setDraft keeps a file of attestations as the draft, as c, after checking
// it; recorded with its digest.
func setDraft(root string, c *Caller, body []byte, surface string) (*attest.File, error) {
	if err := authorise(root, c, auth.ActGrant, "/"); err != nil {
		return nil, err
	}
	f, err := parseAttestations(body, time.Now())
	if err != nil {
		return nil, err
	}
	enc, err := f.Encode()
	if err != nil {
		return nil, err
	}
	if err := recordE(root, c.auditRecord("attest.draft", "/security/public", audit.Success, map[string]string{
		"digest": f.Digest(), "attestations": fmt.Sprint(len(f.Attestations)),
		"policies": fmt.Sprint(len(f.Policies)), "surface": surface})); err != nil {
		return nil, err
	}
	return f, atomicfile.Write(attestationsPath(root), enc, 0o600)
}

// proposePublication asks for the draft to be published, as c, with a
// reason. It is sent at once only when c is the only administrator, and the
// record says so; otherwise it waits for a second (quilzo pending approve).
func proposePublication(root string, c *Caller, reason string) (sent bool, err error) {
	s, err := publishOrPropose(root, c, reason)
	return s != nil, err
}

// publishOrPropose is proposePublication with what was sent, when it was
// sent at once: nil when the publication waits for a second administrator.
func publishOrPropose(root string, c *Caller, reason string) (*publicSent, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, errMisused{errors.New("a reason is required: publishing to the public instance is " +
			"speaking for the organisation, and the record keeps why")}
	}
	if err := authorise(root, c, auth.ActGrant, "/"); err != nil {
		return nil, err
	}
	draft, err := loadDraft(root, time.Now())
	if err != nil {
		return nil, err
	}
	if draft == nil {
		return nil, errNotFound{errors.New("there are no attestations to publish: quilzo attest set FILE " +
			"keeps a file of them as the draft")}
	}
	to, err := loadTarget(root)
	if err != nil {
		return nil, err
	}
	if to == "" {
		return nil, errBlocked{errors.New("there is nowhere to publish to: quilzo public target " +
			"https://PUBLIC-HOST says where the public instance is")}
	}
	what := fmt.Sprintf("publish %s's attestations (%s, %s) to the public instance at %s", draft.Organisation,
		count(len(draft.Attestations), "attestation"), count(len(draft.Policies), "policy"), to)
	now, err := proposeSecond(root, c, dualPublishExternal, what, publishChange{Digest: draft.Digest(), Target: to}, reason)
	if err != nil || !now {
		return nil, err
	}
	sent, err := publishProjection(root, attestationsPath(root), publication{approvers: []string{c.Name},
		alone: true, reason: reason, by: c})
	if err != nil {
		return nil, err
	}
	return &sent, nil
}

// applyPublishExternal is an approved publication, sent: the draft, as long
// as it is the one that was proposed.
func applyPublishExternal(root string, r dual.Request, by string) error {
	var ch publishChange
	if err := json.Unmarshal(r.Payload, &ch); err != nil {
		return err
	}
	draft, err := loadDraft(root, time.Now())
	if err != nil {
		return err
	}
	if draft == nil || draft.Digest() != ch.Digest {
		return errBlocked{fmt.Errorf("the attestations changed after request %s was made, so approving it would "+
			"send something nobody proposed: propose the draft as it is now", r.ID)}
	}
	if to, err := loadTarget(root); err != nil || to != ch.Target {
		return errBlocked{fmt.Errorf("the public instance's address changed after request %s was made", r.ID)}
	}
	c := resolveCaller(root, "")
	_, err = publishProjection(root, attestationsPath(root), publication{approvers: []string{r.By, by},
		alone: r.Alone, request: r.ID, reason: r.Why, by: c})
	return err
}

// cmdAttest is `quilzo attest [show] | set FILE | publish --reason WHY`.
func cmdAttest(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"show"}
	}
	if isPublicInstance(root) {
		return errPublicInstance(root, "shows the attestations it was sent and keeps no draft")
	}
	switch args[0] {
	case "show":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return attestShow(root)
	case "set":
		if len(args) != 2 {
			return errMisused{errors.New("usage: quilzo attest set FILE")}
		}
		body, err := readInput(args[1], attest.MaxBytes+1)
		if err != nil {
			return err
		}
		f, err := setDraft(root, resolveCaller(root, ""), body, "cli")
		if err != nil {
			return err
		}
		if w.JSON(map[string]string{"digest": f.Digest()}) {
			return nil
		}
		w.Human("%sthe draft is %s%s: %s, %s\n", bold, f.Digest(), reset,
			count(len(f.Attestations), "attestation"), count(len(f.Policies), "policy"))
		w.Human("  %stwo administrators publish it: quilzo attest publish --reason WHY%s\n", dim, reset)
		return nil
	case "publish":
		fs := flag.NewFlagSet("attest publish", flag.ContinueOnError)
		reason := fs.String("reason", "", "why it is published, kept in the record")
		if err := parseFlags(fs, args[1:], nil, 0); err != nil {
			return err
		}
		sent, err := publishOrPropose(root, resolveCaller(root, ""), *reason)
		if err != nil {
			return err
		}
		// Sent at once, by the only administrator: under --json what was
		// sent, as `quilzo public send` answers it. It was said only in
		// prose, so the line that waits for a second administrator answered
		// its request and the one that published answered nothing.
		if sent != nil && !w.JSON(sent) {
			w.Human("%spublished%s to the public instance\n", bold, reset)
		}
		return nil
	}
	return errMisused{fmt.Errorf("unknown attest command %q; try show, set or publish", args[0])}
}

// publicView is the public instance as the internal one sees it, for every
// surface.
type publicView struct {
	Target  string       `json:"target,omitempty"`
	KeyID   string       `json:"key_id,omitempty"`
	Keys    string       `json:"keys_file,omitempty"`
	Draft   *attest.File `json:"draft,omitempty"`
	Digest  string       `json:"draft_digest,omitempty"`
	Problem string       `json:"draft_problem,omitempty"`
	Sent    *publicSent  `json:"sent,omitempty"`
	Waiting string       `json:"waiting,omitempty"`
}

func viewPublic(root string) (publicView, error) {
	var v publicView
	to, err := loadTarget(root)
	if err != nil {
		return v, err
	}
	v.Target = to
	if signer, err := headSigner(root); err == nil {
		v.KeyID, v.Keys = signer.Verifier().KeyID(), headKeysPath(root)
	}
	if draft, err := loadDraft(root, time.Now()); err != nil {
		v.Problem = err.Error()
	} else if draft != nil {
		v.Draft, v.Digest = draft, draft.Digest()
	}
	if fileExists(publicSentPath(root)) {
		var sent publicSent
		if err := loadJSON(publicSentPath(root), &sent); err != nil {
			return v, err
		}
		v.Sent = &sent
	}
	if pend, err := dualStore(root).Pending(time.Now()); err == nil {
		for _, r := range pend {
			if r.Kind == dualPublishExternal && r.State == dual.Waiting {
				v.Waiting = r.ID
			}
		}
	}
	return v, nil
}

func attestShow(root string) error {
	if err := authorise(root, resolveCaller(root, ""), auth.ActView, "/"); err != nil {
		return err
	}
	v, err := viewPublic(root)
	if err != nil {
		return err
	}
	if w.JSON(v) {
		return nil
	}
	switch {
	case v.Problem != "":
		w.Human("%sthe draft is not publishable%s\n  %s\n", bold, reset, v.Problem)
	case v.Draft == nil:
		w.Human("no draft: quilzo attest set FILE keeps a file of attestations as one\n")
	default:
		w.Human("%sthe draft%s %s, for %s\n", bold, reset, v.Digest, v.Draft.Organisation)
		for _, a := range v.Draft.Attestations {
			w.Human("  %-12s %s, %s to %s, issued by %s\n", a.Kind, a.Title, a.PeriodStart, a.PeriodEnd, a.Issuer)
		}
		for _, p := range v.Draft.Policies {
			w.Human("  policy       %s, version %s, approved %s\n", p.Title, p.Version, p.Approved)
		}
	}
	if v.Sent != nil {
		same := ""
		if v.Sent.Digest == v.Digest {
			same = ", the draft as it is"
		}
		w.Human("\n  published %s to %s, approved by %s%s\n", v.Sent.At.Format("2 January 2006"), v.Sent.To,
			v.Sent.ApprovedBy, same)
	}
	if v.Waiting != "" {
		w.Human("  %sa publication waits for a second administrator: quilzo pending approve %s%s\n", yellow, v.Waiting, reset)
	}
	return nil
}
