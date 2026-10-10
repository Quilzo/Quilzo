// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build linux

package browser

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/cdp"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "agentbox-init":
			agentbox.InitMain()
		case "agentbox-shim":
			agentbox.ShimMain(os.Args[2])
			os.Exit(125)
		}
	}
	os.Exit(m.Run())
}

// Chromium in the agent's box, driven from outside it over the pipe: the
// page renders in the box, and the connection is this process's alone.
func TestABrowserInTheBoxIsDrivenFromOutside(t *testing.T) {
	chrome := localChromium(t)
	n := agentbox.Native{Exe: os.Args[0], Init: []string{"agentbox-init"}, Shim: []string{"agentbox-shim"}}
	if a := n.Check(); !a.OK {
		t.Skip("no box here: " + a.Why)
	}
	work := t.TempDir()
	bx := Box{Backend: n, Run: "r1", Agent: "clerk", Workdir: work, Wall: time.Minute}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	b, err := cdp.Launch(ctx, cdp.Options{Path: chrome, Profile: filepath.Join(work, "profile"), Boxed: true,
		Env: []string{"HOME=" + work, "TMPDIR=" + work}, Start: bx.Start(io.Discard)})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p, err := b.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Navigate(ctx, "data:text/html,<h1>Inside the box</h1><button>Go</button>"); err != nil {
		t.Fatal(err)
	}
	nodes, err := p.AXTree(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range nodes {
		found = found || (n.Role.String() == "heading" && n.Name.String() == "Inside the box")
	}
	if !found {
		t.Fatal("the page's heading is not in its tree")
	}
	png, err := p.Screenshot(ctx)
	if err != nil || !bytes.HasPrefix(png, []byte("\x89PNG")) {
		t.Fatalf("screenshot: %v", err)
	}
	// What the box made is in the box's own directory.
	if _, err := os.Stat(filepath.Join(work, "profile")); err != nil {
		t.Errorf("the profile is not in the box's directory: %v", err)
	}
}
