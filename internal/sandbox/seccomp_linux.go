// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package sandbox

import (
	"fmt"
	"syscall"
	"unsafe"
)

// The system calls an agent's program is refused.
//
// Landlock decides which files and ports a program reaches; this decides
// which of the kernel's own doors it may knock on at all. The list is what
// a confined program has no business with and what a program trying to
// leave its confinement reaches for first: tracing other processes,
// loading kernel code, mounting, new namespaces, the keyring, io_uring
// (which performs I/O this filter would never see), the raw and packet
// sockets that sit below every network rule, local sockets, Multipath TCP
// (which Landlock's TCP rules do not see) and listening. Everything else is
// allowed, because a program that cannot start is not confined, it is
// broken, and somebody turns the confinement off.
//
// Built by hand from the standard library, as the classic BPF the kernel
// reads, because the libraries that build these are dependencies, and a
// filter is short enough to read in full: an architecture check, one
// comparison per refused call, two calls looked at by their arguments.
//
// An extension, which is not hardened, gets the network part alone
// (netFilter) whenever its TCP is restricted: without it, the Landlock rule
// that denies it every connection is one socket(2) argument away from
// meaning nothing.

// BPF instruction parts and seccomp's return values.
const (
	bpfLD   = 0x00
	bpfW    = 0x00
	bpfABS  = 0x20
	bpfALU  = 0x04
	bpfAND  = 0x50
	bpfJMP  = 0x05
	bpfJEQ  = 0x10
	bpfJGE  = 0x30
	bpfJSET = 0x40
	bpfK    = 0x00
	bpfRET  = 0x06

	retKillProcess = 0x80000000
	retErrno       = 0x00050000
	retAllow       = 0x7fff0000

	prSetSeccomp      = 22
	seccompModeFilter = 2
)

// Where seccomp_data keeps what the filter reads: the call's number, the
// architecture, and the low half of each argument (little-endian on both
// architectures this builds for).
const (
	offNr   = 0
	offArch = 4
)

func offArg(i int) uint32 { return uint32(16 + 8*i) }

// Calls whose numbers are the same on every architecture (the generic
// table from 424 on).
const (
	sysIoUringSetup    = 425
	sysIoUringEnter    = 426
	sysIoUringRegister = 427
	sysOpenTree        = 428
	sysMoveMount       = 429
	sysFsopen          = 430
	sysFsconfig        = 431
	sysFsmount         = 432
	sysFspick          = 433
	sysClone3          = 435
	sysPidfdGetfd      = 438
	sysMountSetattr    = 442
	sysQuotactlFd      = 443
	sysStatmount       = 457
	sysListmount       = 458
	sysOpenTreeAttr    = 467
)

// Address families a program may open a socket in: the internet ones
// (which inside the sandbox's own network reach only what it was handed),
// and netlink, which the C library asks about the interfaces with.
//
// Not local sockets. A socket on the machine's filesystem is a door past
// every other rule here: Landlock does not decide connecting to one, and
// on the other side are a desktop's message bus (which starts a command
// outside every box when asked), an SSH or GPG agent, a container daemon.
// Nothing confined needs one: the services a box is given reach it over
// its own loopback, and socketpair, which only ever connects a process to
// itself, is a separate call and stays allowed.
var allowedFamilies = []uint32{syscall.AF_INET, syscall.AF_INET6, syscall.AF_NETLINK}

// ipprotoMPTCP is Multipath TCP's protocol number, which a stream socket in
// either internet family may ask for. Landlock's TCP rules are written
// against plain TCP sockets, and on the kernels this was tested on (Linux
// 6.18) an MPTCP socket connects and binds wherever it likes inside a
// ruleset that denies both. Go has opened its listeners as MPTCP by default
// since 1.24, so this is not only a door for a program looking for one: an
// ordinary net.Listen walked through it. Refused as a protocol the kernel
// does not support, which is the answer Go and the C libraries fall back to
// plain TCP on, so a program that never asked for MPTCP notices nothing.
const ipprotoMPTCP = 262

// newNamespaces is every namespace flag clone takes: a confined program
// does not make itself a new world to stand in.
const newNamespaces = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET |
	syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS | 0x02000000 // CLONE_NEWCGROUP

type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// sockFprog mirrors struct sock_fprog: a length and a pointer, which Go
// lays out with the pointer at offset 8, as C does.
type sockFprog struct {
	Len    uint16
	Filter *sockFilter
}

func stmt(code uint16, k uint32) sockFilter { return sockFilter{Code: code, K: k} }

func jump(code uint16, k uint32, jt, jf uint8) sockFilter {
	return sockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

func errno(e syscall.Errno) sockFilter { return stmt(bpfRET|bpfK, retErrno|uint32(e)) }

var allow = stmt(bpfRET|bpfK, retAllow)

// prelude checks the architecture and loads the call's number.
func prelude() []sockFilter {
	p := []sockFilter{
		// The architecture first: a call made through another ABI has other
		// numbers, and a filter that matched them as these would be matching
		// the wrong calls.
		stmt(bpfLD|bpfW|bpfABS, offArch),
		jump(bpfJMP|bpfJEQ|bpfK, auditArch, 1, 0),
		stmt(bpfRET|bpfK, retKillProcess),
		stmt(bpfLD|bpfW|bpfABS, offNr),
	}
	return append(p, archPrelude()...)
}

// network is the part of the filter about sockets, with the call's number
// in the accumulator: no listening, and a socket only in the families
// above, never raw and never Multipath TCP. What it does not refuse it
// allows.
//
// Listening, because Landlock decides bind(2) and not the bind listen(2)
// does by itself on a socket that has none: an unbound socket that listens
// is given a port on every address, which the rule denying bind was there
// to prevent.
func network() []sockFilter {
	p := []sockFilter{jump(bpfJMP|bpfJEQ|bpfK, sysListen, 0, 1), errno(syscall.EPERM)}
	fam := len(allowedFamilies)
	p = append(p,
		jump(bpfJMP|bpfJEQ|bpfK, sysSocket, 0, uint8(fam+10)), // past the block
		stmt(bpfLD|bpfW|bpfABS, offArg(0)),
	)
	for i, f := range allowedFamilies {
		// A match jumps over the remaining comparisons and the refusal to
		// the type check.
		p = append(p, jump(bpfJMP|bpfJEQ|bpfK, f, uint8(fam-i), 0))
	}
	return append(p,
		errno(syscall.EAFNOSUPPORT),
		stmt(bpfLD|bpfW|bpfABS, offArg(1)),
		stmt(bpfALU|bpfAND|bpfK, 0xf), // the type, without SOCK_NONBLOCK and SOCK_CLOEXEC
		jump(bpfJMP|bpfJEQ|bpfK, syscall.SOCK_RAW, 0, 1),
		errno(syscall.EPERM),
		stmt(bpfLD|bpfW|bpfABS, offArg(2)),
		jump(bpfJMP|bpfJEQ|bpfK, ipprotoMPTCP, 0, 1),
		errno(syscall.EPROTONOSUPPORT),
		allow,
	)
}

// netFilter is the network part alone, for a sandbox that is not hardened.
func netFilter() []sockFilter {
	return append(append(prelude(), network()...), allow)
}

// filter is the program, for this architecture.
func filter() []sockFilter {
	p := prelude()
	for _, nr := range denied() {
		p = append(p, jump(bpfJMP|bpfJEQ|bpfK, nr, 0, 1), errno(syscall.EPERM))
	}
	// clone3 takes its flags in a structure the filter cannot read, so it
	// is said not to exist, and the C library falls back to clone, whose
	// flags it can.
	p = append(p, jump(bpfJMP|bpfJEQ|bpfK, sysClone3, 0, 1), errno(syscall.ENOSYS))

	// clone: a new thread or process, never a new namespace.
	p = append(p,
		jump(bpfJMP|bpfJEQ|bpfK, sysClone, 0, 4),
		stmt(bpfLD|bpfW|bpfABS, offArg(0)),
		jump(bpfJMP|bpfJSET|bpfK, newNamespaces, 0, 1),
		errno(syscall.EPERM),
		allow,
	)
	p = append(p, network()...)
	return append(p, allow)
}

// applySeccomp loads the filter on the calling thread. no_new_privs must
// already be set; the filter survives execve, so the program the thread
// becomes is filtered from its first instruction.
func applySeccomp() error { return load(filter()) }

// applyNetSeccomp loads the network part alone, the same way.
func applyNetSeccomp() error { return load(netFilter()) }

func load(f []sockFilter) error {
	prog := sockFprog{Len: uint16(len(f)), Filter: &f[0]}
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter,
		uintptr(unsafe.Pointer(&prog)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("cannot load the system call filter: %w", errno)
	}
	return nil
}

// SeccompSupported says this build can filter system calls here.
func SeccompSupported() bool { return true }
