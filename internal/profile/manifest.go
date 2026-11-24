// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/oscal"
)

// ManifestContext is what a feature manifest is signed under, so that a
// signature over one can never be shown as a signature over a head, a
// transfer or anything else the same keys sign.
const ManifestContext = "quilzo/feature-manifest/v1"

// Manifest is the record of which features this installation runs: CM-7
// evidence, in a form an auditor can read and check.
type Manifest struct {
	// Format is this layout's version, so a reader in five years knows
	// what it is holding.
	Format int `json:"format"`
	// Control is the control it is evidence for, as OSCAL spells it.
	Control  string    `json:"control"`
	Software string    `json:"software"`
	Version  string    `json:"version"`
	Profile  string    `json:"profile"`
	Made     time.Time `json:"made"`
	// Since, By and Reason are when the profile was applied, by whom, and
	// why when it replaced another.
	Since  time.Time `json:"since,omitzero"`
	By     string    `json:"by,omitempty"`
	Reason string    `json:"reason,omitempty"`
	// Features is every feature the profile can switch, and how it stands.
	Features []Entry `json:"features"`
}

// Entry is one feature in the manifest.
type Entry struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	// State is "off" or "on".
	State      string   `json:"state"`
	Why        string   `json:"why"`
	Commands   []string `json:"commands,omitempty"`
	Admin      []string `json:"admin,omitempty"`
	Site       []string `json:"site,omitempty"`
	Operations []string `json:"operations,omitempty"`
	Also       string   `json:"also,omitempty"`
	// Change is the recorded change that set its state, when one did
	// rather than the profile.
	Change *Change `json:"change,omitempty"`
}

// Build is the manifest of a state, made now.
func Build(st *State, version string, now time.Time) Manifest {
	m := Manifest{Format: 1, Control: "cm-7", Software: "Quilzo", Version: version,
		Profile: st.Name(), Made: now.UTC(), Since: st.Since, By: st.By, Reason: st.Reason}
	for _, f := range Catalogue() {
		e := Entry{Name: f.Name, Title: f.Title, State: "on", Why: f.Why, Commands: f.Commands,
			Admin: f.Admin, Site: f.Site, Operations: f.Operations, Also: f.Also}
		if !st.On(f.Name) {
			e.State = "off"
		}
		if ch, ok := st.Last(f.Name); ok {
			e.Change = &ch
		}
		m.Features = append(m.Features, e)
	}
	return m
}

// Off is the features the manifest has off, by name.
func (m Manifest) Off() []Entry {
	var out []Entry
	for _, e := range m.Features {
		if e.State == "off" {
			out = append(out, e)
		}
	}
	return out
}

// Signed is a manifest as it was signed: the exact bytes, their digest and
// the signature over them.
//
// The bytes are kept rather than the struct, because a signature is over
// bytes and a reader that re-encoded the manifest to check it would be
// checking an encoding it made, not the one that was signed.
type Signed struct {
	Manifest  json.RawMessage `json:"manifest"`
	Digest    string          `json:"digest"`
	Signature audit.Statement `json:"signature"`
}

// Signer is what signs a manifest: the store's head keys, held here or by
// the log writer.
type Signer interface {
	SignStatement(context string, msg []byte) (audit.Statement, error)
}

// Sign encodes and signs a manifest.
func Sign(m Manifest, by Signer) (Signed, error) {
	body, err := json.Marshal(m)
	if err != nil {
		return Signed{}, err
	}
	st, err := by.SignStatement(ManifestContext, body)
	if err != nil {
		return Signed{}, fmt.Errorf("the feature manifest could not be signed: %w", err)
	}
	return Signed{Manifest: body, Digest: digestOf(body), Signature: st}, nil
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Verify checks a signed manifest against the keys that should have signed
// it and returns what it says.
func (sm Signed) Verify(v *audit.HeadVerifier) (Manifest, error) {
	if len(sm.Manifest) == 0 {
		return Manifest{}, errors.New("there is no manifest to check")
	}
	// Compacted first. The manifest was signed as encoding/json writes it,
	// with no space between its tokens, and a file written with indentation
	// for a person to read carries the same tokens laid out: whitespace
	// between tokens is the one thing compacting changes, so a pretty
	// printer cannot break the signature and an edit to a value still does.
	var body bytes.Buffer
	if err := json.Compact(&body, sm.Manifest); err != nil {
		return Manifest{}, fmt.Errorf("the manifest does not parse: %w", err)
	}
	if got := digestOf(body.Bytes()); got != sm.Digest {
		return Manifest{}, fmt.Errorf("the manifest's digest is %s and it says %s: it was changed after it was made",
			got, sm.Digest)
	}
	if err := v.VerifyStatement(ManifestContext, body.Bytes(), sm.Signature); err != nil {
		return Manifest{}, fmt.Errorf("the feature manifest's signature does not verify: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(body.Bytes(), &m); err != nil {
		return Manifest{}, fmt.Errorf("the manifest does not parse: %w", err)
	}
	if m.Format != 1 {
		return Manifest{}, fmt.Errorf("the manifest is format %d and this reads format 1", m.Format)
	}
	return m, nil
}

// Annotate attaches a signed manifest to CM-7 in Quilzo's own OSCAL
// component, as properties a tool can read and remarks a person can: the
// manifest's digest, the key that signed it, the profile and each feature
// that is off. It reports whether the component had a CM-7 to attach it to.
func Annotate(cd *oscal.ComponentDefinition, sm Signed, m Manifest) bool {
	found := false
	for ci := range cd.ComponentDefinition.Components {
		comp := &cd.ComponentDefinition.Components[ci]
		for ii := range comp.ControlImplementations {
			impl := &comp.ControlImplementations[ii]
			for ri := range impl.ImplementedRequirements {
				ir := &impl.ImplementedRequirements[ri]
				if ir.ControlID != "cm-7" {
					continue
				}
				found = true
				ir.Props = slices.DeleteFunc(ir.Props, func(p oscal.Prop) bool {
					return p.NS == oscal.Namespace && (strings.HasPrefix(p.Name, "feature-") || p.Name == "profile")
				})
				ir.Props = append(ir.Props,
					oscal.Prop{Name: "profile", NS: oscal.Namespace, Value: m.Profile},
					oscal.Prop{Name: "feature-manifest", NS: oscal.Namespace, Value: sm.Digest},
					oscal.Prop{Name: "feature-manifest-key", NS: oscal.Namespace, Value: sm.Signature.KeyID})
				var titles []string
				for _, e := range m.Off() {
					ir.Props = append(ir.Props, oscal.Prop{Name: "feature-off", NS: oscal.Namespace, Value: e.Name})
					titles = append(titles, e.Title)
				}
				said := fmt.Sprintf("The %s profile is in force", m.Profile)
				if len(titles) > 0 {
					said += " and switches off: " + strings.Join(titles, ", ")
				} else {
					said += " and switches nothing off"
				}
				said += fmt.Sprintf(". The signed feature manifest %s (key %s) records each switched-off "+
					"feature and every one switched back on, with who did it and why.", sm.Digest, sm.Signature.KeyID)
				ir.Remarks = strings.TrimSpace(ir.Remarks + "\n\n" + said)
			}
		}
	}
	return found
}
