// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build linux

package agentbox

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/sandbox"
)

// Two pipes handed in reach the program as its fds 3 and 4, and nothing
// else in the box: it reads what this side wrote on 3 and answers on 4.
func TestTheProgramIsHandedItsFilesAsThreeAndFour(t *testing.T) {
	n := native(t)
	work := t.TempDir()
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		_, err := n.Run(context.Background(), Spec{Run: "files", Agent: "files", Program: os.Args[0],
			Args: []string{"agentbox-program", "echo-fds"}, Env: []string{"HOME=" + work, "QUILZO_SEEN=yes"},
			Workdir: work, Read: []string{filepath.Dir(os.Args[0])},
			Limits: sandbox.Limits{DataBytes: 1 << 30, Processes: 4096, OpenFiles: 256},
			Wall:   20 * time.Second, Stdout: io.Discard, Stderr: os.Stderr, Files: []*os.File{inR, outW},
			Started: func() { close(started) }})
		done <- err
	}()
	<-started
	inR.Close()
	outW.Close()
	if _, err := io.WriteString(inW, "ping\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(outR).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "pong ping" {
		t.Fatalf("the program answered %q, %v", line, err)
	}
	inW.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The program has gone, so the pipe's far end is closed: nothing in the
	// box kept a copy.
	if _, err := outR.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("after the program ended, reading gave %v rather than the end", err)
	}
}
