// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package cell drives a desktop in a microVM: the fourth tier of the
// computer-use plan, for apps no browser reaches.
//
// # What a cell is
//
// One cell is one microVM — Firecracker or Cloud Hypervisor, whichever
// binary the operator installed — holding an X server, the accessibility
// tree and the apps, restored from a warm snapshot somebody made of it in
// that state. Nothing of the host is mounted into it; its disc and its
// network are files and taps this program's driver asks the microVM to
// attach, and its only door to the host is a vsock this program connects
// to. Restoring takes milliseconds, which is the point: a session does not
// boot a desktop, it steps into one that was already warm.
//
// # What this package is, and is not
//
// It is the host side, complete: the microVM's API over its Unix socket,
// the vsock conversation with the helper inside, and the messages that
// conversation carries. It is not the image: an X server, AT-SPI and the
// apps are the operator's to build into the snapshot, and this program's
// `Check` says whether what it needs of them is here. Nor is it a
// sandbox claim: the isolation is the microVM's, and this package adds
// no boundary of its own — a cell is offered to an agent only under the
// same manifest, breaker and ask-first as every other capability.
package cell

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

// A Backend is one kind of microVM, driven over its own socket. Both of
// the makers' APIs are HTTP over a Unix socket, which is the whole reason
// either can be driven from this program without a dependency: a
// transport that dials a path instead of a port.
type Backend interface {
	// Name is what a setting names: "firecracker" or "cloud-hypervisor".
	Name() string
	// Check says whether this machine can run one: the binary, and the
	// virtual memory it needs.
	Check() (Availability, error)
	// Start brings one up from the configured warm snapshot and returns
	// the socket to drive it with.
	Start(ctx context.Context, c Machine, socket string) error
	// Stop ends one: the maker's own shutdown signal, which the guest's
	// init answers by ending, taking the process with it.
	Stop(ctx context.Context, socket string) error
}

// Availability is what a machine has for cells.
type Availability struct {
	OK  bool
	Why string
}

// A Machine is one cell to bring up: the pieces the microVM attaches, by
// path, and the shape it is given.
type Machine struct {
	// Kernel and Image are the disc the snapshot was made against; both
	// makers want them named, and neither will start from a snapshot whose
	// pieces have moved since it was taken.
	Kernel string
	Image  string
	// Snapshot is the warm snapshot to restore: the microVM's own files,
	// made by this program's Snapshot when the operator warmed the cell.
	Snapshot string
	// Memory is the memory file of that snapshot, where the maker keeps it
	// apart from the description.
	Memory string
	// Vsock is the Unix socket this program will connect to the helper
	// through; the microVM binds its end when it restores.
	Vsock string
	// CPUs and MemoryMB are the shape the snapshot was taken at; a restore
	// that names another shape is refused by the maker, and by this.
	CPUs, MemoryMB int
}

// reName is what a backend may be called in a setting.
var reName = regexp.MustCompile(`^[a-z][a-z-]{1,31}$`)

// New is the backend a setting names, with the binary that serves it.
func New(backend, binary string) (Backend, error) {
	switch backend {
	case "firecracker":
		return &Firecracker{Binary: binary}, nil
	case "cloud-hypervisor":
		return &CloudHypervisor{Binary: binary}, nil
	}
	return nil, fmt.Errorf("%q is not a cell backend this program can drive; use firecracker or cloud-hypervisor", backend)
}

// httpOverUnix is the transport both makers speak: ordinary HTTP, one
// server, on a socket the microVM owns.
func httpOverUnix(socket string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		// A microVM answers in single-digit milliseconds or it is in
		// trouble; the caller's context bounds the rest.
		ResponseHeaderTimeout: 30 * time.Second,
	}, Timeout: 0}
}

// apiCall is one request of the microVM's API, with a JSON body, and an
// error that carries what the maker said when it said no.
func apiCall(ctx context.Context, c *http.Client, method, path string, body any) error {
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	if len(b) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	why, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		if len(why) > 300 {
			why = why[:300]
		}
		return fmt.Errorf("%s %s: %s: %s", method, path, http.StatusText(resp.StatusCode), why)
	}
	return nil
}

// findKVM says whether the virtual memory a cell needs is here.
func findKVM() error {
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return errors.New("no /dev/kvm on this machine, and a cell is a virtual machine: nothing to run one in")
	}
	return nil
}

// findBinary says whether the operator installed the maker's binary.
func findBinary(binary string) error {
	if binary == "" {
		return errors.New("no cell backend is configured (cell.backend)")
	}
	if !filepath.IsAbs(binary) {
		return fmt.Errorf("%q is not an absolute path to the microVM binary", binary)
	}
	if _, err := exec.LookPath(binary); err != nil {
		if _, serr := os.Stat(binary); serr != nil {
			return fmt.Errorf("%s is not installed here", binary)
		}
	}
	return nil
}
