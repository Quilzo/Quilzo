package main

import (
	"fmt"
	"path/filepath"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/anchor"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/timestamp"
)

// What the admin server needs that only this package knows.
//
// Every function here exists because internal/admin deliberately does not know
// where this store keeps its files, and should not learn: the moment the web UI
// knows about `<root>/webhooks.json` there are two places that decide the
// layout, and one of them will be wrong after the next change.

// mediaDir is where uploads live.
func mediaDir(root string) string { return filepath.Join(root, "media") }

func openMedia(root string) (*medialib.Library, error) {
	return medialib.Open(mediaDir(root))
}

func formsPath(root string) string     { return filepath.Join(root, "forms.json") }
func submissionDir(root string) string { return filepath.Join(root, "submissions") }

func loadForms(root string) (*form.Set, error) {
	s := &form.Set{}
	return s, loadJSON(formsPath(root), s)
}

func openSubmissions(root string) (*form.Store, error) {
	return form.Open(submissionDir(root))
}

func profilesPath(root string) string { return filepath.Join(root, "profiles.json") }

// loadProfiles reads the self-supplied details.
//
// A missing file is an empty map rather than an error: a store where nobody
// has set a display name is the ordinary state, not a broken one.
func loadProfiles(root string) (map[string]admin.PersonDetails, error) {
	out := map[string]admin.PersonDetails{}
	if err := loadJSON(profilesPath(root), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func loadHooks(root string) (*hookFile, error) {
	f := &hookFile{}
	return f, loadJSON(hooksPath(root), f)
}

// saveDraft writes pages the way every other write surface does.
//
// The first version of this called site.SaveDraft and nothing else, and two
// tests that walk the source refused it — correctly, and this is exactly what
// they exist for. It skipped the type gate, so content arriving through import,
// a starter or the assistant would not have to satisfy the types every other
// route enforces; and it took whatever the draft was at the moment of writing
// as its parent, so two people importing at once would lose one of the two
// imports with no error.
//
// Both were invisible in the feature. Both would have shipped.
func saveDraft(root string, s *store.Store, pages map[string]any,
	message, author, base string) error {

	types, err := gateWrite(root, pages)
	if err != nil {
		return err
	}
	if _, err := site.SaveDraftFrom(s, pages, message, author, base); err != nil {
		return err
	}
	// The validation record goes after the content, so a crash between the two
	// leaves a page with no record rather than a record for a page that was
	// never stored. Unrecorded reads as unvalidated, which is the safe way
	// round.
	return types.Save()
}

// recordAssisted marks pages as model-generated.
//
// Called after the assistant's proposal is accepted, so the pages carry the
// mark before anybody can try to publish them. The publish gate refuses
// unmarked pages, so writing them without this would only move the refusal to
// whoever presses publish — and by then the connection between "a model wrote
// this" and "these pages" is something a person has to remember.
func recordAssisted(root string, s *store.Store, pages []string,
	model, author string) error {

	idx, err := loadProvenance(root)
	if err != nil {
		return err
	}
	c, err := s.GetCommit(s.GetRef(site.RefDraft))
	if err != nil {
		return err
	}
	tree, err := s.GetTree(c.Tree)
	if err != nil {
		return err
	}
	for _, page := range pages {
		hash, there := tree[page]
		if !there {
			return fmt.Errorf("%s is not in the draft that was just written", page)
		}
		if err := idx.Set(page, admin.AssistProvenance(model, author, hash)); err != nil {
			return err
		}
	}
	return saveJSON(provPath(root), idx)
}

// evidenceRows flattens timestamps and anchors into one list.
//
// They answer the same question — can somebody who does not trust us check
// when this was published — and two tables of one row each are harder to read
// than one table of two.
func evidenceRows(root string) ([]admin.Evidence, error) {
	var out []admin.Evidence

	if stamps, err := loadStamps(root); err == nil {
		for _, st := range stamps.Stamps {
			out = append(out, admin.Evidence{
				Kind: "timestamp", Subject: st.Root, Authority: st.Authority,
				// The trustworthy time is inside the token; this is our clock.
				// Both appear because a disagreement between them is itself
				// worth noticing.
				State: "issued", Detail: describeStampAnchor(st.Anchor),
				At: st.RequestedAt,
			})
		}
	}

	file := &anchorFile{}
	if err := loadJSON(anchorPath(root), file); err == nil {
		for _, p := range file.Proofs {
			state := string(p.State)
			if !p.Anchored() {
				// Named rather than shown as a tick. A proof that has been
				// submitted and not yet committed to a block is evidence of an
				// intention, not of a time.
				state = "pending"
			}
			out = append(out, admin.Evidence{
				Kind: "anchor", Subject: p.Digest, Authority: p.Calendar,
				State: state, Detail: anchor.Describe(p), At: p.SubmittedAt,
			})
		}
	}
	return out, nil
}

func describeStampAnchor(a *timestamp.Anchor) string {
	if a == nil {
		return ""
	}
	if !a.Confirmed {
		return a.Method + " submitted, not yet confirmed"
	}
	return a.Method + " " + a.Reference
}

// mustConfig reads configuration, falling back to defaults.
//
// The defaults are the recommended configuration, so a store whose config file
// is missing gets the safe values rather than zero values — which for a rate
// limit would mean no limit at all.
func mustConfig(root string) *config.Config {
	c, err := loadConfig(root)
	if err != nil || c == nil {
		return config.New()
	}
	return c
}
