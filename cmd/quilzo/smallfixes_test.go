// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/out"
)

// Pruning takes the oldest finished runs and never a run that is waiting
// for a person or being worked on, however old.
func TestPruningKeepsRunsThatAreNotFinished(t *testing.T) {
	dir := t.TempDir()
	runs := []struct{ id, body string }{
		{"run-20260101-00000001", `{"trace":{"Waiting":{"N":2}}}`},
		{"run-20260101-00000002", `{"state":"running","trace":{}}`},
		{"run-20260101-00000003", `{"trace":{"Waiting":null}}`},
		{"run-20260101-00000004", `{"trace":{}}`},
		{"run-20260101-00000005", `{"trace":{}}`},
	}
	at := time.Now().Add(-time.Hour)
	for i, r := range runs {
		p := filepath.Join(dir, r.id+".json")
		if err := os.WriteFile(p, []byte(r.body), 0o600); err != nil {
			t.Fatal(err)
		}
		when := at.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneRunsIn(dir, 3); err != nil {
		t.Fatal(err)
	}
	for _, r := range runs {
		_, err := os.Stat(filepath.Join(dir, r.id+".json"))
		keep := r.id != "run-20260101-00000003" && r.id != "run-20260101-00000004"
		if keep && err != nil {
			t.Errorf("%s was removed: %s", r.id, r.body)
		}
		if !keep && err == nil {
			t.Errorf("%s, finished and among the oldest, was kept", r.id)
		}
	}
}

// --json a11y answers in JSON, with what was and was not checked.
func TestTheAccessibilityCheckAnswersInJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	old := w
	t.Cleanup(func() { w = old })
	w = out.New(false)
	root, tpl := t.TempDir()+"/st", t.TempDir()+"/tpl"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(root, []string{"-publish=false", "-templates", tpl}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w = out.New(true)
	w.Out = &buf
	_ = cmdA11y(root, []string{"--templates", tpl})
	var got struct {
		Pages   int `json:"pages"`
		Reports []struct {
			Page    string   `json:"page"`
			Checked []string `json:"checked"`
		} `json:"reports"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	if got.Pages == 0 || len(got.Reports) != got.Pages || len(got.Reports[0].Checked) == 0 {
		t.Errorf("%+v", got)
	}
}

// Publishing with nothing drafted names the add command as it is typed.
func TestPublishingNothingNamesTheAddCommandRightly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	err := cmdPublish(root, nil)
	if err == nil || !strings.Contains(err.Error(), "quilzo add NAME=FILE.json") {
		t.Errorf("%v", err)
	}
}
