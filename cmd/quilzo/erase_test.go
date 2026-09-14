// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/out"
)

// An erasure reported through --json actually erases.
//
// It did not. The JSON branch answered `{"matched": n, "removed": true}` and
// returned — before the delete loop, and before the audit record, both of
// which came after it. So `quilzo form erase VALUE --json`, which is how an
// erasure request gets scripted, reported the erasure done, deleted nothing,
// and left no record that it had been asked for.
//
// That is the worst way for this particular feature to fail. The request is
// closed, the obligation is filed as met, and the data is still on disk — and
// the next person to look has a log saying it was handled.
func TestErasingThroughJSONActuallyErases(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}

	set := &form.Set{}
	if err := set.Add(form.Form{
		Name: "wholesale", Label: "Wholesale",
		Notice:        "we reply and then delete",
		RetentionDays: 30,
		Fields: []form.Field{
			{Name: "email", Label: "Email", Kind: form.Email, Required: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(filepath.Join(root, "forms.json"), set); err != nil {
		t.Fatal(err)
	}

	st, err := openSubmissions(root)
	if err != nil {
		t.Fatal(err)
	}
	for i, who := range []string{"ada@example.com", "grace@example.com"} {
		if err := st.Put(form.Submission{
			Form: "wholesale", ID: "0123456789abcdef0123456789abcde" + string(rune('0'+i)),
			At:     time.Now().Unix(),
			Values: map[string]string{"email": who},
		}); err != nil {
			t.Fatal(err)
		}
	}

	// The scripted path, which is the one that lied.
	old := w
	w = out.New(true)
	defer func() { w = old }()

	if err := cmdForms(root, []string{"erase", "ada@example.com"}); err != nil {
		t.Fatal(err)
	}

	left, err := st.Search(set, "ada@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("%d submission(s) matching the erased value are still on "+
			"disk. The command reported the erasure done", len(left))
	}
	// And it erased only what was asked for.
	other, err := st.Search(set, "grace@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 1 {
		t.Errorf("an erasure for one address removed %d of somebody else's",
			1-len(other))
	}
}

// A dry run says so, and removes nothing.
func TestADryRunErasureSaysItRemovedNothing(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	set := &form.Set{}
	if err := set.Add(form.Form{
		Name: "wholesale", Label: "Wholesale", Notice: "kept briefly",
		RetentionDays: 30,
		Fields:        []form.Field{{Name: "email", Label: "Email", Kind: form.Email}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(filepath.Join(root, "forms.json"), set); err != nil {
		t.Fatal(err)
	}
	st, err := openSubmissions(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(form.Submission{
		Form: "wholesale", ID: "0123456789abcdef0123456789abcdef",
		At: time.Now().Unix(), Values: map[string]string{"email": "ada@example.com"},
	}); err != nil {
		t.Fatal(err)
	}

	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	old, oldStdout := w, os.Stdout
	os.Stdout = f
	w = out.New(true)
	err = cmdForms(root, []string{"erase", "ada@example.com", "--dry-run"})
	w, os.Stdout = old, oldStdout
	f.Close()
	if err != nil {
		t.Fatal(err)
	}

	body, rerr := os.ReadFile(f.Name())
	if rerr != nil {
		t.Fatal(rerr)
	}
	var got map[string]any
	if jerr := json.Unmarshal(body, &got); jerr != nil {
		t.Fatalf("the dry run did not answer JSON: %s", body)
	}
	if got["removed"] != float64(0) {
		t.Errorf("a dry run reported removing %v", got["removed"])
	}
	left, serr := st.Search(set, "ada@example.com")
	if serr != nil {
		t.Fatal(serr)
	}
	if len(left) != 1 {
		t.Error("a dry run deleted the submission it was only supposed to count")
	}
}
