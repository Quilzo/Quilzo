// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/controls"
)

// clock is a fake clock: each call is a minute after the one before.
type clock struct{ t time.Time }

func (c *clock) now() time.Time {
	c.t = c.t.Add(time.Minute)
	return c.t
}

func newClock() *clock {
	return &clock{t: time.Date(2027, 3, 1, 9, 0, 0, 0, time.UTC)}
}

func signer(t *testing.T, seed byte) *audit.HeadSigner {
	t.Helper()
	ed := bytes.Repeat([]byte{seed}, audit.SeedSize)
	ml := bytes.Repeat([]byte{seed + 1}, audit.SeedSize)
	s, err := audit.NewHeadSigner(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func secured(t *testing.T, c *clock) *State {
	t.Helper()
	st := &State{}
	if err := st.Apply(Security, "the security install", "dana", c.now()); err != nil {
		t.Fatal(err)
	}
	return st
}

// Every feature the profile can switch off says what it is, why a security
// install has no use for it, and where it is reached, so that what the
// profile switches off is a list somebody can read and an auditor can check.
func TestCatalogueIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	cat := Catalogue()
	if len(cat) < 5 {
		t.Fatalf("the catalogue has %d features; the profile switches off payments, social posting, "+
			"the desktop portal, browser hands and similar", len(cat))
	}
	for _, f := range cat {
		if seen[f.Name] {
			t.Errorf("%s is listed twice", f.Name)
		}
		seen[f.Name] = true
		if f.Title == "" || f.Why == "" {
			t.Errorf("%s does not say what it is and why it is off", f.Name)
		}
		if len(f.Commands)+len(f.Admin)+len(f.Site)+len(f.Operations) == 0 {
			t.Errorf("%s names nowhere it is reached, so switching it off switches nothing", f.Name)
		}
	}
	for _, want := range []string{"commerce", "social", "desktop", "browser-hands"} {
		if !seen[want] {
			t.Errorf("the catalogue does not hold %s", want)
		}
	}
}

// Without the profile nothing is off; with it, everything in the catalogue
// is.
func TestTheProfileSwitchesOffTheCatalogueAndNothingElse(t *testing.T) {
	plain := &State{}
	if off := plain.Off(); len(off) != 0 {
		t.Fatalf("a store with no profile has %d features off", len(off))
	}
	st := secured(t, newClock())
	if got, want := len(st.Off()), len(Catalogue()); got != want {
		t.Fatalf("the security profile has %d of %d features off", got, want)
	}
	if f, off := st.RefusesCommand("pay"); !off || f.Name != "commerce" {
		t.Errorf("pay is not refused under the security profile")
	}
	if _, off := st.RefusesCommand("publish"); off {
		t.Errorf("publish is refused, and it is not in the catalogue")
	}
	if _, off := plain.RefusesCommand("pay"); off {
		t.Errorf("pay is refused with no profile")
	}
}

// Switching a feature back on needs a reason, names who and when, and is
// what the manifest then says.
func TestReenableIsRecorded(t *testing.T) {
	c := newClock()
	st := secured(t, c)
	if _, err := st.Switch("commerce", true, "  ", "sam", c.now()); err == nil {
		t.Fatal("commerce was switched back on with no reason")
	}
	if _, err := st.Switch("commerce", true, "the board sells tickets", "", c.now()); err == nil {
		t.Fatal("commerce was switched back on by nobody")
	}
	if _, err := st.Switch("rockets", true, "why not", "sam", c.now()); err == nil {
		t.Fatal("a feature that does not exist was switched on")
	}
	at := c.now()
	ch, err := st.Switch("commerce", true, "the board sells tickets", "sam", at)
	if err != nil {
		t.Fatal(err)
	}
	if !st.On("commerce") || ch.By != "sam" || !ch.At.Equal(at) || ch.Reason != "the board sells tickets" {
		t.Fatalf("the change is not recorded as made: %+v", ch)
	}
	if _, err := st.Switch("commerce", true, "again", "sam", c.now()); err == nil {
		t.Error("commerce was switched on twice, which records a change that changed nothing")
	}
	m := Build(st, "0.1.0", c.now())
	var entry *Entry
	for i := range m.Features {
		if m.Features[i].Name == "commerce" {
			entry = &m.Features[i]
		}
	}
	if entry == nil || entry.State != "on" || entry.Change == nil || entry.Change.Reason != "the board sells tickets" ||
		entry.Change.By != "sam" {
		t.Fatalf("the manifest does not say commerce was switched back on, by whom and why: %+v", entry)
	}
	// And off again, recorded the same way.
	if _, err := st.Switch("commerce", false, "the ticket sale ended", "dana", c.now()); err != nil {
		t.Fatal(err)
	}
	if st.On("commerce") {
		t.Error("commerce is still on")
	}
}

// Applying a profile starts from it again: what was switched back on under
// an earlier application does not survive a new one.
func TestApplyingTheProfileAgainStartsFromIt(t *testing.T) {
	c := newClock()
	st := secured(t, c)
	if _, err := st.Switch("boards", true, "a forum for the board", "sam", c.now()); err != nil {
		t.Fatal(err)
	}
	if err := st.Apply(Security, "back to the profile", "dana", c.now()); err != nil {
		t.Fatal(err)
	}
	if st.On("boards") {
		t.Error("boards stayed on through a fresh application of the profile")
	}
	if err := st.Apply("public", "", "dana", c.now()); err == nil {
		t.Error("the public instance's profile was applied to a store")
	}
	if err := st.Apply(Standard, "", "dana", c.now()); err == nil {
		t.Error("the profile was changed with no reason")
	}
}

// The manifest is signed, verifies with the key that signed it and with no
// other, notices a change of one byte, and is CM-7 evidence in Quilzo's own
// OSCAL component.
func TestManifestSignedAndInOSCAL(t *testing.T) {
	c := newClock()
	st := secured(t, c)
	key := signer(t, 7)
	sm, err := Sign(Build(st, "0.1.0", c.now()), key)
	if err != nil {
		t.Fatal(err)
	}
	m, err := sm.Verify(key.Verifier())
	if err != nil {
		t.Fatalf("the manifest does not verify with its own key: %v", err)
	}
	if m.Profile != Security || m.Control != "cm-7" || len(m.Features) != len(Catalogue()) {
		t.Fatalf("the manifest does not say what it is: %+v", m)
	}
	if _, err := sm.Verify(signer(t, 9).Verifier()); err == nil {
		t.Error("the manifest verified with a key that did not sign it")
	}
	tampered := sm
	tampered.Manifest = json.RawMessage(strings.Replace(string(sm.Manifest), `"state":"off"`, `"state":"on"`, 1))
	if _, err := tampered.Verify(key.Verifier()); err == nil {
		t.Error("a manifest changed after it was signed verified")
	}

	cd, err := controls.ComponentDefinition("0.1.0", nil, c.now())
	if err != nil {
		t.Fatal(err)
	}
	if !Annotate(&cd, sm, m) {
		t.Fatal("the component definition has no CM-7 to annotate")
	}
	found := false
	for _, comp := range cd.ComponentDefinition.Components {
		for _, ci := range comp.ControlImplementations {
			for _, ir := range ci.ImplementedRequirements {
				if ir.ControlID != "cm-7" {
					continue
				}
				found = true
				props := map[string][]string{}
				for _, p := range ir.Props {
					props[p.Name] = append(props[p.Name], p.Value)
				}
				if got := props["feature-manifest"]; len(got) != 1 || got[0] != sm.Digest {
					t.Errorf("CM-7 does not carry the manifest's digest: %v", got)
				}
				if got := props["feature-manifest-key"]; len(got) != 1 || got[0] != key.Verifier().KeyID() {
					t.Errorf("CM-7 does not name the key that signed the manifest: %v", got)
				}
				if got := props["feature-off"]; len(got) != len(Catalogue()) {
					t.Errorf("CM-7 lists %d features off, and the profile has %d off", len(got), len(Catalogue()))
				}
				if !strings.Contains(ir.Remarks, "Payments and commerce") || !strings.Contains(ir.Remarks, sm.Digest) {
					t.Errorf("CM-7's remarks do not say what is off: %s", ir.Remarks)
				}
			}
		}
	}
	if !found {
		t.Fatal("no CM-7 in the component")
	}
}

// The gate refuses the paths of what is off, and the paths beside them that
// merely begin with the same letters it leaves alone.
func TestGateRefusesTheSwitchedOffPathsOnly(t *testing.T) {
	st := secured(t, newClock())
	served := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("served")) })
	admin := Gate(served, AdminSurface, func() *State { return st })
	for path, off := range map[string]bool{
		"/pay": true, "/pay/act": true, "/payroll": false, "/experiments/change": true,
		"/mcp/browser/run-1": true, "/mcp": false, "/security": false, "/": false,
	} {
		rec := httptest.NewRecorder()
		admin.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		switchedOff := rec.Code == http.StatusNotFound && rec.Header().Get(OffHeader) != ""
		if switchedOff != off {
			t.Errorf("%s: switched off %v, want %v (%d %s)", path, switchedOff, off, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	admin.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/pay", nil))
	if body := rec.Body.String(); !strings.Contains(body, "quilzo profile enable commerce") ||
		!strings.Contains(body, "<h1>") || !strings.Contains(body, `lang="en"`) {
		t.Errorf("the refusal does not say how to switch it back on: %s", body)
	}
	// On the public site, a visitor is told the address is not served and
	// nothing about the installation behind it.
	site := Gate(served, SiteSurface, func() *State { return st })
	rec = httptest.NewRecorder()
	site.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ucp/checkout", nil))
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "profile") {
		t.Errorf("the site's refusal says more than not found: %d %s", rec.Code, rec.Body.String())
	}
	// With no profile, everything is served.
	plain := Gate(served, AdminSurface, func() *State { return &State{} })
	rec = httptest.NewRecorder()
	plain.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/pay", nil))
	if rec.Body.String() != "served" {
		t.Errorf("with no profile /pay was not served")
	}
}

// A profile file that cannot be read is everything off, not everything on:
// spoiling the file must not be a way to switch features back on.
func TestAnUnreadableProfileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	get := Watch(path)
	if st := get(); len(st.Off()) != 0 {
		t.Fatalf("a missing profile switched %d features off", len(st.Off()))
	}
	if err := os.WriteFile(path, []byte(`{"profile": "security", "changes": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A later modification time, so the watcher reads it again.
	later := time.Now().Add(time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if st := get(); len(st.Off()) != len(Catalogue()) {
		t.Fatalf("an unreadable profile left %d of %d features off", len(st.Off()), len(Catalogue()))
	}
	if _, err := Load(path); err == nil {
		t.Error("an unreadable profile loaded")
	}
	if err := os.WriteFile(path, []byte(`{"profile": "security", "surprise": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("a profile with a field this version does not know loaded")
	}
}

// Saved and loaded, a state is the same state.
func TestAStateSurvivesSaving(t *testing.T) {
	c := newClock()
	st := secured(t, c)
	if _, err := st.Switch("social", true, "the newsroom posts", "sam", c.now()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := Save(path, st); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.Profile != Security || !back.On("social") || back.On("commerce") {
		t.Fatalf("the state changed on the way through the file: %+v", back)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the profile is written %v", fi.Mode().Perm())
	}
}

// Both refusals pass the accessibility checks the interface enforces on
// content.
func TestTheRefusalsAreAccessible(t *testing.T) {
	st := secured(t, newClock())
	served := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	for on, path := range map[Surface]string{AdminSurface: "/pay", SiteSurface: "/ucp/x"} {
		rec := httptest.NewRecorder()
		Gate(served, on, func() *State { return st }).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		for _, f := range a11y.Check(path, rec.Body.String()).Findings {
			if f.Severity == a11y.Blocking {
				t.Errorf("%s on the %s: %s (%s): %s", path, on, f.Rule, f.Criterion, f.Detail)
			}
		}
	}
}
