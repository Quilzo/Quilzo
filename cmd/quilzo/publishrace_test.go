// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// saveInTheGap lands a save on the draft after every check a publish makes
// has passed and before live moves, as a colleague's save or an agent's
// write could at any moment. The page it adds declares no provenance, so
// every gate would have refused it had it been asked.
func saveInTheGap(t *testing.T, root string) {
	t.Helper()
	beforeLiveMoves = func() {
		s, err := store.Open(root)
		if err != nil {
			t.Error(err)
			return
		}
		pages, err := site.PagesAt(s, site.RefDraft)
		if err != nil {
			t.Error(err)
			return
		}
		pages["unchecked"] = map[string]any{"title": "Never checked", "body": "nobody looked at this"}
		if _, err := site.SaveDraft(s, pages, "a save in the gap", "lee"); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeLiveMoves = nil })
}

// `quilzo publish` with no commit puts live the draft it checked, and not
// whatever the draft has become by the time live moves.
//
// It ran every gate on the draft and then called site.Publish(s, ""), which
// read the draft again. A save landing in between went live with none of
// the checks, the approvals or the freeze having seen it.
func TestPublishingTheDraftPutsLiveWhatWasChecked(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := newStoreWithDraft(t)
	if err := runCmd(t, root, "provenance", "set", "index",
		"--source", "humanEdits", "--author", "someone"); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	checked := s.GetRef(site.RefDraft)
	saveInTheGap(t, root)
	if err := runPublish(t, root, "--no-a11y-check"); err != nil {
		t.Fatalf("a checked draft was refused: %v", err)
	}
	if live := s.GetRef(site.RefLive); live != checked {
		t.Fatalf("live is %s, not the draft that was checked (%s): a save "+
			"made after the checks went live unchecked", short(live), short(checked))
	}
	if s.GetRef(site.RefDraft) == checked {
		t.Fatal("control: the save in the gap did not land")
	}
}

// The machine interface's publish puts live what it checked too. It read
// the draft for its checks and site.Publish(s, "") read it again, and its
// approvals were asked about the draft as it stood when they were read
// rather than about the commit the other checks had seen.
func TestAnMCPPublishPutsLiveWhatWasChecked(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	root := t.TempDir() + "/st"
	tpl := t.TempDir() + "/tpl"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(root, []string{"-publish=false", "-templates", tpl}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { finishBackground(10 * time.Second) })
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	checked := s.GetRef(site.RefDraft)
	srv := buildMCP(root, s, asAdmin("dana"), tpl)
	call := func() string {
		params, _ := json.Marshal(map[string]any{"name": "quilzo_publish",
			"arguments": map[string]any{"operation": "publish"}})
		b, _ := json.Marshal(srv.Handle(mcp.Request{JSONRPC: "2.0", ID: json.RawMessage("1"),
			Method: "tools/call", Params: params}))
		return string(b)
	}

	saveInTheGap(t, root)
	if got := call(); refused(got) || !strings.Contains(got, "published") {
		t.Fatalf("control: the demonstration did not publish over MCP: %s", got)
	}
	if live := s.GetRef(site.RefLive); live != checked {
		t.Fatalf("live is %s, not the draft that was checked (%s): a save "+
			"made after the checks went live unchecked", short(live), short(checked))
	}
	if s.GetRef(site.RefDraft) == checked {
		t.Fatal("control: the save in the gap did not land")
	}
}
