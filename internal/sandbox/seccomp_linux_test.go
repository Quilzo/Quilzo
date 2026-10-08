// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build linux && (amd64 || arm64)

package sandbox

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"testing"
)

// run interprets the filter as the kernel would, for one call: enough of
// classic BPF to read the filter this package writes, and a refusal for
// any instruction it does not know, so a filter that grew one fails here
// rather than passing untested.
func run(t *testing.T, prog []sockFilter, arch uint32, nr uint32, args ...uint64) uint32 {
	t.Helper()
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[0:], nr)
	binary.LittleEndian.PutUint32(data[4:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(data[16+8*i:], a)
	}
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case bpfLD | bpfW | bpfABS:
			acc = binary.LittleEndian.Uint32(data[in.K:])
		case bpfALU | bpfAND | bpfK:
			acc &= in.K
		case bpfJMP | bpfJEQ | bpfK, bpfJMP | bpfJGE | bpfK, bpfJMP | bpfJSET | bpfK:
			var ok bool
			switch in.Code &^ (bpfJMP | bpfK) {
			case bpfJEQ:
				ok = acc == in.K
			case bpfJGE:
				ok = acc >= in.K
			case bpfJSET:
				ok = acc&in.K != 0
			}
			if ok {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
			if pc+1 >= len(prog) {
				t.Fatalf("a jump at %d leaves the program", pc)
			}
		case bpfRET | bpfK:
			return in.K
		default:
			t.Fatalf("instruction %#x at %d is not one this filter writes", in.Code, pc)
		}
	}
	t.Fatal("the program ran off its end")
	return 0
}

func TestTheFilterRefusesWhatAConfinedProgramMustNotDo(t *testing.T) {
	p := filter()
	eperm := retErrno | uint32(syscall.EPERM)
	call := func(nr uint32, args ...uint64) uint32 { return run(t, p, auditArch, nr, args...) }

	for _, nr := range denied() {
		if got := call(nr); got != eperm {
			t.Errorf("call %d: %#x, want refused", nr, got)
		}
	}
	if got := call(sysClone3); got != retErrno|uint32(syscall.ENOSYS) {
		t.Errorf("clone3: %#x, want said not to exist", got)
	}
	// A thread, yes; a namespace, no.
	if got := call(sysClone, syscall.CLONE_VM|syscall.CLONE_THREAD|syscall.CLONE_SIGHAND); got != retAllow {
		t.Errorf("clone for a thread: %#x", got)
	}
	for _, ns := range []uint64{syscall.CLONE_NEWUSER, syscall.CLONE_NEWNET, syscall.CLONE_NEWNS, syscall.CLONE_NEWPID, 0x02000000} {
		if got := call(sysClone, ns|uint64(syscall.SIGCHLD)); got != eperm {
			t.Errorf("clone with %#x: %#x", ns, got)
		}
	}
	// Sockets: the four families, never raw.
	for _, fam := range allowedFamilies {
		if got := call(sysSocket, uint64(fam), syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC); got != retAllow {
			t.Errorf("socket family %d: %#x", fam, got)
		}
	}
	if got := call(sysSocket, syscall.AF_PACKET, syscall.SOCK_RAW); got != retErrno|uint32(syscall.EAFNOSUPPORT) {
		t.Errorf("a packet socket: %#x", got)
	}
	if got := call(sysSocket, syscall.AF_INET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK); got != eperm {
		t.Errorf("a raw socket: %#x", got)
	}
	if got := call(sysSocket, syscall.AF_INET6, syscall.SOCK_DGRAM); got != retAllow {
		t.Errorf("a datagram socket: %#x", got)
	}
	// Everything else is allowed, or a program cannot start.
	for _, nr := range []uint32{0, 1, 2, 39, 57, 59, 60, 231, 444, 445, 446} {
		if !contains(denied(), nr) && nr != sysClone && nr != sysSocket {
			if got := call(nr); got != retAllow {
				t.Errorf("call %d: %#x, want allowed", nr, got)
			}
		}
	}
	// Another architecture's numbers are not these.
	if got := run(t, p, 0x40000003, 1); got != retKillProcess {
		t.Errorf("a call from another architecture: %#x", got)
	}
	if runtime.GOARCH == "amd64" {
		if got := call(0x40000000 | 1); got != retErrno|uint32(syscall.ENOSYS) {
			t.Errorf("an x32 call: %#x", got)
		}
	}
}

func contains(list []uint32, v uint32) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// hardenedResult is what the confined child saw.
type hardenedResult struct {
	Status   Status          `json:"status"`
	Errnos   map[string]int  `json:"errnos"`
	Allowed  map[string]bool `json:"allowed"`
	Files    uint64          `json:"files"`
	Problems []string        `json:"problems"`
}

// The real thing: a child confines itself as an agent's program would and
// tries each door.
func TestAHardenedProcessIsConfined(t *testing.T) {
	if !Supported() {
		t.Skip("no Landlock here")
	}
	open, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	shut, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer shut.Close()
	go func() {
		for {
			c, err := open.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	cmd := exec.Command(os.Args[0], "-test.run=TestHardenedHelper")
	cmd.Env = append(os.Environ(), "QUILZO_SANDBOX_HELPER=1",
		"QUILZO_OPEN="+open.Addr().String(), "QUILZO_SHUT="+shut.Addr().String())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the helper failed: %v\n%s", err, out)
	}
	var r hardenedResult
	if err := json.Unmarshal(out[:jsonEnd(out)], &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, p := range r.Problems {
		t.Error(p)
	}
	if !r.Status.Seccomp || !r.Status.Enforced || !r.Status.CapabilitiesDropped {
		t.Errorf("status %+v", r.Status)
	}
	want := map[string]syscall.Errno{"unshare": syscall.EPERM, "ptrace": syscall.EPERM, "keyctl": syscall.EPERM,
		"mount": syscall.EPERM, "io_uring": syscall.EPERM, "clone3": syscall.ENOSYS,
		"packet socket": syscall.EAFNOSUPPORT, "raw socket": syscall.EPERM, "connect elsewhere": syscall.EACCES}
	for name, e := range want {
		if got := syscall.Errno(r.Errnos[name]); got != e {
			t.Errorf("%s: %v, want %v", name, got, e)
		}
	}
	for _, name := range []string{"getpid", "tcp socket", "unix socket", "connect allowed"} {
		if !r.Allowed[name] {
			t.Errorf("%s was refused", name)
		}
	}
	if r.Files != 64 {
		t.Errorf("open files limited to %d", r.Files)
	}
}

// jsonEnd is where the helper's JSON line ends, before the test runner's
// own output.
func jsonEnd(b []byte) int {
	for i, c := range b {
		if c == '\n' {
			return i
		}
	}
	return len(b)
}

func TestHardenedHelper(t *testing.T) {
	if os.Getenv("QUILZO_SANDBOX_HELPER") != "1" {
		t.Skip("run by TestAHardenedProcessIsConfined")
	}
	runtime.LockOSThread()
	r := hardenedResult{Errnos: map[string]int{}, Allowed: map[string]bool{}}
	_, openPort, _ := net.SplitHostPort(os.Getenv("QUILZO_OPEN"))
	port, _ := strconv.Atoi(openPort)
	st, err := Restrict(Rules{Hardened: true, ConnectPorts: []uint16{uint16(port)},
		Limits: Limits{OpenFiles: 64}})
	r.Status = st
	if err != nil {
		r.Problems = append(r.Problems, "restrict: "+err.Error())
	}
	try := func(name string, nr uintptr, a ...uintptr) {
		args := make([]uintptr, 6)
		copy(args, a)
		fd, _, errno := syscall.RawSyscall6(nr, args[0], args[1], args[2], args[3], args[4], args[5])
		if errno != 0 {
			r.Errnos[name] = int(errno)
			return
		}
		r.Allowed[name] = true
		if name == "tcp socket" || name == "unix socket" {
			syscall.Close(int(fd))
		}
	}
	try("unshare", syscall.SYS_UNSHARE, syscall.CLONE_NEWUSER)
	try("ptrace", syscall.SYS_PTRACE, syscall.PTRACE_TRACEME)
	try("keyctl", uintptr(keyctlNr()), 0)
	try("mount", uintptr(mountNr()), 0, 0, 0, 0, 0)
	try("io_uring", sysIoUringSetup, 1, 0)
	try("clone3", sysClone3, 0, 0)
	try("packet socket", sysSocket, syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	try("raw socket", sysSocket, syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	try("tcp socket", sysSocket, syscall.AF_INET, syscall.SOCK_STREAM, 0)
	try("unix socket", sysSocket, syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	try("getpid", syscall.SYS_GETPID)
	dial := func(name, addr string) {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			r.Problems = append(r.Problems, name+": "+err.Error())
			return
		}
		defer syscall.Close(fd)
		_, p, _ := net.SplitHostPort(addr)
		pn, _ := strconv.Atoi(p)
		if err := syscall.Connect(fd, &syscall.SockaddrInet4{Port: pn, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			if e, ok := err.(syscall.Errno); ok {
				r.Errnos[name] = int(e)
			}
			return
		}
		r.Allowed[name] = true
	}
	dial("connect allowed", os.Getenv("QUILZO_OPEN"))
	dial("connect elsewhere", os.Getenv("QUILZO_SHUT"))
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		r.Files = lim.Cur
	}
	b, _ := json.Marshal(r)
	os.Stdout.Write(append(b, '\n'))
}
