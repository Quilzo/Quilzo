// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/oscal"
	"github.com/quilzo/quilzo/internal/profile"
)

// The security profile, on this store (internal/profile): the command that
// shows and changes it, and the gates every surface puts in front of what
// it switches off.

func profilePath(root string) string { return filepath.Join(root, "profile.json") }

// manifestPath is the signed feature manifest, rewritten at every change:
// the evidence `quilzo compliance component` attaches to CM-7.
func manifestPath(root string) string { return filepath.Join(root, "feature-manifest.json") }

// profileWatches holds one watcher per store, so the gate on every request
// costs a stat and not a parse.
var profileWatches sync.Map

// profileState is the store's profile as its file says now.
func profileState(root string) *profile.State {
	key := auditKey(root)
	got, ok := profileWatches.Load(key)
	if !ok {
		got, _ = profileWatches.LoadOrStore(key, profile.Watch(profilePath(root)))
	}
	return got.(func() *profile.State)()
}

// switchedOff is what a refusal says: what is off, why, and the line that
// switches it back on, because a refusal a person cannot act on is one they
// route around.
func switchedOff(f profile.Feature) error {
	return fmt.Errorf("%s is switched off by this installation's security profile: %s.\n"+
		"  Nothing is removed. An administrator switches it back on, with a reason the record keeps:\n"+
		"    quilzo profile enable %s --reason \"why it is needed\"", f.Title, f.Why, f.Name)
}

// profileRefuses is the command line's gate, asked before any command runs.
func profileRefuses(root, cmd string) error {
	if f, off := profileState(root).RefusesCommand(cmd); off {
		return errBlocked{switchedOff(f)}
	}
	return nil
}

// profileRefusesOperation is the agent interface's gate, asked before every
// operation as its authorisation is.
func profileRefusesOperation(root, op string) error {
	if f, off := profileState(root).RefusesOperation(op); off {
		return errBlocked{switchedOff(f)}
	}
	return nil
}

// featureRefused is the gate for a feature that is a behaviour rather than
// an address: an agent run asking for a browser.
func featureRefused(root, name string) error {
	if profileState(root).On(name) {
		return nil
	}
	f, _ := profile.Lookup(name)
	return errBlocked{switchedOff(f)}
}

// profileGate is what the admin and the site put in front of their routers.
func profileGate(root string, on profile.Surface, h http.Handler) http.Handler {
	return profile.Gate(h, on, func() *profile.State { return profileState(root) })
}

// changeProfile makes one change to the store's profile as c, who must
// administer the store.
func changeProfile(root string, c *Caller, action string, detail map[string]string,
	change func(*profile.State, time.Time) error) (profile.Signed, error) {
	if err := authorise(root, c, auth.ActGrant, "/"); err != nil {
		return profile.Signed{}, err
	}
	return writeProfile(root, c, action, detail, change)
}

// writeProfile makes the change, signs the manifest of the result and
// records both, in that order: the record names the manifest by its digest,
// and nothing is written to the store when the record cannot be.
func writeProfile(root string, c *Caller, action string, detail map[string]string,
	change func(*profile.State, time.Time) error) (profile.Signed, error) {
	if err := auditReady(root); err != nil {
		return profile.Signed{}, err
	}
	unlock, err := atomicfile.Lock(profilePath(root) + ".lock")
	if err != nil {
		return profile.Signed{}, err
	}
	defer unlock()
	st, err := profile.Load(profilePath(root))
	if err != nil {
		return profile.Signed{}, err
	}
	now := time.Now()
	if err := change(st, now); err != nil {
		return profile.Signed{}, errMisused{err}
	}
	signer, err := headSigner(root)
	if err != nil {
		return profile.Signed{}, err
	}
	sm, err := profile.Sign(profile.Build(st, version, now), signer)
	if err != nil {
		return profile.Signed{}, err
	}
	if detail == nil {
		detail = map[string]string{}
	}
	detail["profile"], detail["manifest"] = st.Name(), sm.Digest
	if err := recordE(root, c.auditRecord(action, "/security/profile", audit.Success, detail)); err != nil {
		return profile.Signed{}, err
	}
	if err := profile.Save(profilePath(root), st); err != nil {
		return profile.Signed{}, err
	}
	return sm, saveManifest(root, sm)
}

func saveManifest(root string, sm profile.Signed) error {
	body, err := json.MarshalIndent(sm, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(manifestPath(root), append(body, '\n'), 0o600)
}

// storedManifest is the store's signed manifest, checked against the
// store's own keys. Absent is not an error: a store nobody applied a profile
// to has none.
func storedManifest(root string) (*profile.Signed, *profile.Manifest, error) {
	body, err := os.ReadFile(manifestPath(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var sm profile.Signed
	if err := json.Unmarshal(body, &sm); err != nil {
		return nil, nil, fmt.Errorf("the feature manifest does not parse: %w", err)
	}
	signer, err := headSigner(root)
	if err != nil {
		return nil, nil, err
	}
	m, err := sm.Verify(signer.Verifier())
	if err != nil {
		return &sm, nil, err
	}
	return &sm, &m, nil
}

// manifestSaysWhatRuns is the error that says a manifest which verifies no
// longer says what the gates enforce (profile.Manifest.Says), nil while it
// does.
func manifestSaysWhatRuns(m profile.Manifest, st *profile.State) error {
	if err := m.Says(st); err != nil {
		return fmt.Errorf("the signed feature manifest no longer says what runs: %w. %s was changed outside "+
			"quilzo profile; quilzo profile apply %s --reason WHY signs one that does", err,
			filepath.Base(profilePath("")), st.Name())
	}
	return nil
}

// profileEvidence attaches the store's manifest to CM-7, when there is one,
// it verifies and it says what runs. One that does not is not evidence, and
// is left off with a note rather than attached.
func profileEvidence(root string, cd *oscal.ComponentDefinition) error {
	sm, m, err := storedManifest(root)
	if err == nil && sm != nil {
		var st *profile.State
		if st, err = profile.Load(profilePath(root)); err == nil {
			err = manifestSaysWhatRuns(*m, st)
		}
	}
	if err != nil {
		return fmt.Errorf("the feature manifest is not attached to CM-7: %w", err)
	}
	if sm == nil {
		return nil
	}
	profile.Annotate(cd, *sm, *m)
	return nil
}

// applyProfileAtInit applies the profile `quilzo init --profile` names, to
// a store nobody has used yet. A store already in use is an
// administrator's to change, with a reason.
func applyProfileAtInit(root, name string, created bool) error {
	if name == "" || name == profile.Standard && !fileExists(profilePath(root)) {
		return nil
	}
	st, err := profile.Load(profilePath(root))
	if err != nil {
		return err
	}
	if st.Name() == name && st.Profile != "" {
		w.Human("  %sthe %s profile is in force already%s\n", dim, name, reset)
		return nil
	}
	if !created && !nobodyHasBeenHere(root) {
		return errBlocked{fmt.Errorf("this store is in use, so its profile is an administrator's to change: "+
			"quilzo profile apply %s --reason WHY", name)}
	}
	byInit := &Caller{Name: "quilzo init", Kind: audit.KindService, Verified: true}
	reason := ""
	if st.Profile != "" {
		reason = "quilzo init --profile " + name
	}
	if _, err := writeProfile(root, byInit, "profile.applied", map[string]string{"by": "init"},
		func(st *profile.State, now time.Time) error { return st.Apply(name, reason, byInit.Name, now) }); err != nil {
		return err
	}
	if name == profile.Security {
		w.Human("  %sthe security profile: %d features with no security use are switched off, and the "+
			"signed manifest is CM-7 evidence (quilzo profile)%s\n", dim, len(profile.Catalogue()), reset)
	}
	return nil
}

// cmdProfile is `quilzo profile [show] | apply PROFILE | enable FEATURE |
// disable FEATURE | manifest | verify FILE`.
func cmdProfile(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"show"}
	}
	switch args[0] {
	case "show":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return profileShow(root)
	case "apply", "enable", "disable":
		return profileChange(root, args[0], args[1:])
	case "manifest":
		return profileManifest(root, args[1:])
	case "verify":
		return profileVerify(root, args[1:])
	}
	return errMisused{fmt.Errorf("unknown profile command %q; try show, apply, enable, disable, manifest or verify", args[0])}
}

func profileChange(root, op string, args []string) error {
	fs := flag.NewFlagSet("profile "+op, flag.ContinueOnError)
	reason := fs.String("reason", "", "why: kept in the record and in the signed manifest")
	var pos []string
	if err := parseFlags(fs, args, &pos, 1); err != nil {
		return err
	}
	if len(pos) != 1 {
		what := "FEATURE"
		if op == "apply" {
			what = "security|standard"
		}
		return errMisused{fmt.Errorf("usage: quilzo profile %s %s --reason WHY", op, what)}
	}
	c := resolveCaller(root, "")
	name := pos[0]
	var (
		sm  profile.Signed
		err error
	)
	switch op {
	case "apply":
		sm, err = changeProfile(root, c, "profile.applied", map[string]string{"reason": *reason},
			func(st *profile.State, now time.Time) error { return st.Apply(name, *reason, c.Name, now) })
	default:
		on := op == "enable"
		action := "profile.feature.off"
		if on {
			action = "profile.feature.on"
		}
		sm, err = changeProfile(root, c, action, map[string]string{"feature": name, "reason": *reason},
			func(st *profile.State, now time.Time) error {
				_, err := st.Switch(name, on, *reason, c.Name, now)
				return err
			})
	}
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"manifest": sm.Digest, "key": sm.Signature.KeyID}) {
		return nil
	}
	switch op {
	case "apply":
		w.Human("%s%s profile applied%s\n", bold, name, reset)
	case "enable":
		w.Human("%s%s switched back on%s\n", bold, name, reset)
	default:
		w.Human("%s%s switched off%s\n", bold, name, reset)
	}
	w.Human("  %sthe signed feature manifest is now %s%s\n", dim, sm.Digest, reset)
	return nil
}

// profileView is the profile as every surface shows it.
type profileView struct {
	Profile  string        `json:"profile"`
	Since    time.Time     `json:"since,omitzero"`
	By       string        `json:"by,omitempty"`
	Features []featureView `json:"features"`
	Manifest string        `json:"manifest,omitempty"`
	Key      string        `json:"key,omitempty"`
	Problem  string        `json:"problem,omitempty"`
}

type featureView struct {
	profile.Feature
	On     bool            `json:"on"`
	Change *profile.Change `json:"change,omitempty"`
}

func viewProfile(root string) (profileView, error) {
	st, err := profile.Load(profilePath(root))
	if err != nil {
		return profileView{}, err
	}
	v := profileView{Profile: st.Name(), Since: st.Since, By: st.By}
	for _, f := range profile.Catalogue() {
		fv := featureView{Feature: f, On: st.On(f.Name)}
		if ch, ok := st.Last(f.Name); ok {
			fv.Change = &ch
		}
		v.Features = append(v.Features, fv)
	}
	sm, m, merr := storedManifest(root)
	if sm != nil {
		v.Manifest, v.Key = sm.Digest, sm.Signature.KeyID
	}
	if merr == nil && m != nil {
		merr = manifestSaysWhatRuns(*m, st)
	}
	if merr != nil {
		v.Problem = merr.Error()
	}
	return v, nil
}

func profileShow(root string) error {
	if err := authorise(root, resolveCaller(root, ""), auth.ActView, "/"); err != nil {
		return err
	}
	v, err := viewProfile(root)
	if err != nil {
		return err
	}
	if w.JSON(v) {
		return nil
	}
	w.Human("%sthe %s profile%s", bold, v.Profile, reset)
	if !v.Since.IsZero() {
		w.Human(", applied %s by %s", v.Since.Format("2 January 2006"), v.By)
	}
	w.Human("\n")
	for _, f := range v.Features {
		state := "on "
		if !f.On {
			state = "off"
		}
		w.Human("  %s  %-16s %s\n", state, f.Name, f.Title)
		if f.Change != nil {
			w.Human("       %sswitched %s on %s by %s: %s%s\n", dim, onOff(f.Change.On),
				f.Change.At.Format("2 January 2006"), f.Change.By, f.Change.Reason, reset)
		}
	}
	switch {
	case v.Problem != "":
		w.Human("\n  %s%s%s\n", yellow, v.Problem, reset)
	case v.Manifest != "":
		w.Human("\n  %sthe signed feature manifest is %s, key %s%s\n", dim, v.Manifest, v.Key, reset)
	default:
		w.Human("\n  %sno feature manifest yet: one is signed when a profile is applied%s\n", dim, reset)
	}
	w.Human("  %squilzo profile enable NAME --reason WHY switches one back on%s\n", dim, reset)
	return nil
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

func profileManifest(root string, args []string) error {
	fs := flag.NewFlagSet("profile manifest", flag.ContinueOnError)
	out := fs.String("o", "", "write to this file instead of standard output")
	if err := parseFlags(fs, args, nil, 0); err != nil {
		return err
	}
	if err := authorise(root, resolveCaller(root, ""), auth.ActView, "/"); err != nil {
		return err
	}
	sm, _, err := storedManifest(root)
	if err != nil {
		return err
	}
	if sm == nil {
		return errNotFound{errors.New("no feature manifest has been signed: no profile was applied to this " +
			"store. quilzo profile apply security --reason WHY applies one")}
	}
	body, err := json.MarshalIndent(sm, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if !toStdout(*out) {
		return atomicfile.Write(*out, body, 0o644)
	}
	_, err = os.Stdout.Write(body)
	return err
}

// profileVerify checks a manifest somebody was handed against the public
// keys they were handed separately, or this store's own.
func profileVerify(root string, args []string) error {
	fs := flag.NewFlagSet("profile verify", flag.ContinueOnError)
	keys := fs.String("keys", "", "the published head keys to check it against (head.pub.json)")
	var pos []string
	if err := parseFlags(fs, args, &pos, 1); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errMisused{errors.New("usage: quilzo profile verify FILE [--keys head.pub.json]")}
	}
	body, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	var sm profile.Signed
	if err := json.Unmarshal(body, &sm); err != nil {
		return fmt.Errorf("%s is not a signed feature manifest: %w", pos[0], err)
	}
	v, against, err := verifierFor(root, *keys)
	if err != nil {
		return err
	}
	m, err := sm.Verify(v)
	if err != nil {
		return errBlocked{err}
	}
	if w.JSON(map[string]any{"verified": true, "against": against, "manifest": m}) {
		return nil
	}
	w.Human("%sverified%s against %s\n", bold, reset, against)
	w.Human("  the %s profile, made %s; %d of %d features off\n", m.Profile,
		m.Made.Format("2 January 2006 15:04 MST"), len(m.Off()), len(m.Features))
	for _, e := range m.Off() {
		w.Human("    %s\n", e.Title)
	}
	return nil
}

// securityProfileHooks is the Security profile screen's wiring: the same
// view, the same change and the same manifest as the command line.
func securityProfileHooks(root string, signedIn func(admin.Actor) *Caller) *admin.SecurityProfile {
	return &admin.SecurityProfile{
		View: func() (admin.ProfileView, error) {
			v, err := viewProfile(root)
			if err != nil {
				return admin.ProfileView{}, err
			}
			out := admin.ProfileView{Profile: v.Profile, Since: v.Since, By: v.By,
				Manifest: v.Manifest, Key: v.Key, Problem: v.Problem}
			for _, f := range v.Features {
				out.Features = append(out.Features, admin.ProfileFeature{Feature: f.Feature, On: f.On, Change: f.Change})
			}
			return out, nil
		},
		Switch: func(feature string, on bool, reason string, by admin.Actor) error {
			c := signedIn(by)
			action := "profile.feature.off"
			if on {
				action = "profile.feature.on"
			}
			_, err := changeProfile(root, c, action, map[string]string{"feature": feature, "reason": reason,
				"surface": "admin"}, func(st *profile.State, now time.Time) error {
				_, err := st.Switch(feature, on, reason, c.Name, now)
				return err
			})
			return err
		},
		Apply: func(name, reason string, by admin.Actor) error {
			c := signedIn(by)
			_, err := changeProfile(root, c, "profile.applied", map[string]string{"reason": reason, "surface": "admin"},
				func(st *profile.State, now time.Time) error { return st.Apply(name, reason, c.Name, now) })
			return err
		},
		Manifest: func() ([]byte, error) {
			body, err := os.ReadFile(manifestPath(root))
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			return body, err
		},
	}
}

// wireProfile gives the admin the Security profile screen, the menu that
// leaves out what is switched off, the manifest on CM-7, and the Public
// instance screen the profile's public faces are published from.
func wireProfile(srv *admin.Server, root string, signedIn func(admin.Actor) *Caller) {
	srv.SecurityProfile = securityProfileHooks(root, signedIn)
	srv.PublicInstance = publicInstanceHooks(root, signedIn)
	srv.SwitchedOff = func(path string) bool {
		_, off := profileState(root).Refuses(profile.AdminSurface, path)
		return off
	}
	srv.ComponentEvidence = func(cd *oscal.ComponentDefinition) {
		if err := profileEvidence(root, cd); err != nil {
			fmt.Fprintf(os.Stderr, "  %s%v%s\n", noteYellow, err, noteReset)
		}
	}
}
