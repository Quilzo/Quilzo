// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build linux

package sandbox

import (
	"fmt"
	"syscall"
	"unsafe"
)

// The rest of an agent program's confinement: what Landlock does not
// cover. A program inside its own user namespace is root there, with every
// capability that namespace has; it gives them all up here, before it
// runs a single instruction of its own, along with the right to gain any
// back through a setuid file.

const (
	prCapBSetDrop      = 24
	prCapAmbient       = 47
	prCapAmbientClear  = 4
	linuxCapVersion3   = 0x20080522
	lastCapability     = 63
	ruleTypeNetPort    = 2
	rlimitNproc        = 6
	rlimitAddressSpace = 9
)

type capHeader struct {
	Version uint32
	Pid     int32
}

type capData struct {
	Effective, Permitted, Inheritable uint32
}

// netPortAttr mirrors struct landlock_net_port_attr: two 64-bit fields,
// no packing to worry about.
type netPortAttr struct {
	AllowedAccess uint64
	Port          uint64
}

// harden drops every capability, sets no_new_privs and applies the
// limits, on the calling thread.
func harden(l Limits, st *Status) error {
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, uintptr(prSetNoNewPrivs), 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("cannot set no_new_privs: %w", errno)
	}
	for _, lim := range []struct {
		which int
		v     uint64
	}{
		{syscall.RLIMIT_CPU, l.CPUSeconds}, {rlimitAddressSpace, l.MemoryBytes},
		{syscall.RLIMIT_FSIZE, l.FileBytes}, {syscall.RLIMIT_NOFILE, l.OpenFiles},
		{rlimitNproc, l.Processes},
	} {
		if lim.v == 0 {
			continue
		}
		if err := syscall.Setrlimit(lim.which, &syscall.Rlimit{Cur: lim.v, Max: lim.v}); err != nil {
			return fmt.Errorf("cannot limit the program (%d): %w", lim.which, err)
		}
	}
	// The bounding set first, which only a holder of CAP_SETPCAP may
	// shrink: inside the program's own user namespace that is us. Outside
	// one there is nothing in the effective set to drop, and no_new_privs
	// already stops a setuid file handing anything back.
	for c := 0; c <= lastCapability; c++ {
		_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prCapBSetDrop, uintptr(c), 0)
		if errno == syscall.EINVAL {
			break // past the last capability this kernel knows
		}
	}
	_, _, _ = syscall.RawSyscall6(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClear, 0, 0, 0, 0)
	hdr := capHeader{Version: linuxCapVersion3}
	var none [2]capData
	if _, _, errno := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&none[0])), 0); errno != 0 {
		return fmt.Errorf("cannot drop capabilities: %w", errno)
	}
	var now [2]capData
	hdr = capHeader{Version: linuxCapVersion3}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&now[0])), 0); errno == 0 {
		st.CapabilitiesDropped = now == none
	}
	return nil
}

// allowPorts adds a TCP connect rule for each port to a ruleset.
func allowPorts(ruleset uintptr, ports []uint16) error {
	for _, p := range ports {
		rule := netPortAttr{AllowedAccess: accessNetConnectTCP, Port: uint64(p)}
		if _, _, errno := syscall.Syscall6(sysAddRule, ruleset, ruleTypeNetPort,
			uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
			return fmt.Errorf("cannot allow port %d: %w", p, errno)
		}
	}
	return nil
}
