// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build linux

package agentbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/quilzo/quilzo/internal/sandbox"
)

// Native builds the box from the kernel's own parts, with no root and no
// daemon.
//
//	quilzo (this process: the run, and the services on Unix sockets)
//	  └─ quilzo <Init>          new user, PID, network, IPC and UTS namespaces;
//	     │                      root of nothing but itself. Brings up the
//	     │                      loopback and forwards each service's port to
//	     │                      its socket outside.
//	     └─ quilzo <Shim> SPEC  drops every capability, limits, Landlock,
//	          │                 seccomp; then becomes:
//	          └─ the program    in a network with nothing on it but the
//	                            services it was handed
//
// The first process is PID 1 of its namespace, so when it ends, everything
// the program started ends with it; and it is killed when the run's time
// is up, or when this process dies.
type Native struct {
	// Exe is this program, re-executed as the box's first process and as
	// the shim; Init and Shim are the arguments that make it each.
	Exe        string
	Init, Shim []string
}

// The box's own network has only the loopback, with the services on it.
const boxNamespaces = syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET |
	syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS | syscall.CLONE_NEWNS

type initSpec struct {
	Probe   bool      `json:"probe,omitempty"`
	Forward []Service `json:"forward,omitempty"`
	Shim    []string  `json:"shim,omitempty"`
	Env     []string  `json:"env,omitempty"`
	Dir     string    `json:"dir,omitempty"`
}

type shimSpec struct {
	Program   string         `json:"program"`
	Args      []string       `json:"args,omitempty"`
	Read      []string       `json:"read,omitempty"`
	ReadWrite []string       `json:"read_write,omitempty"`
	Ports     []uint16       `json:"ports,omitempty"`
	Limits    sandbox.Limits `json:"limits"`
}

func (n Native) Name() string { return "native" }

var probed sync.Map // Exe → Availability

// Check starts an empty box once, and says whether that worked.
func (n Native) Check() Availability {
	if v, ok := probed.Load(n.Exe); ok {
		return v.(Availability)
	}
	a := n.probe()
	probed.Store(n.Exe, a)
	return a
}

func (n Native) probe() Availability {
	will := Confinement{Backend: "native", Namespaces: true, Landlock: sandbox.ABI(),
		Files: sandbox.Supported(), Ports: sandbox.ABI() >= 4, Seccomp: sandbox.SeccompSupported(), Capabilities: true}
	switch {
	case !sandbox.Supported():
		return Availability{Why: "this kernel has no Landlock, so a program's files could not be confined", Will: will}
	case sandbox.ABI() < 4:
		return Availability{Why: "this kernel's Landlock cannot restrict ports (ABI 4, Linux 6.7)", Will: will}
	case !sandbox.SeccompSupported():
		return Availability{Why: "this build has no system call filter for this architecture", Will: will}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd, err := n.command(ctx, initSpec{Probe: true}, nil)
	if err == nil {
		var out []byte
		out, err = cmd.CombinedOutput()
		if err != nil && len(out) > 0 {
			err = fmt.Errorf("%v: %s", err, firstLine(out))
		}
	}
	if err != nil {
		return Availability{Will: will, Why: "an empty box could not be started (" + err.Error() + "). " +
			"Unprivileged user namespaces are needed: on Ubuntu 23.10 and later AppArmor restricts them " +
			"(kernel.apparmor_restrict_unprivileged_userns)"}
	}
	return Availability{OK: true, Will: will}
}

func firstLine(b []byte) string {
	for i, c := range b {
		if c == '\n' {
			return string(b[:i])
		}
	}
	return string(b)
}

// command is the box's first process, its spec written to it on fd 3 and
// what the shim reports read from fd 4.
func (n Native) command(ctx context.Context, spec initSpec, report *os.File) (*exec.Cmd, error) {
	body, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	go func() {
		_, _ = w.Write(body)
		w.Close()
	}()
	cmd := exec.CommandContext(ctx, n.Exe, n.Init...)
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{r}
	if report != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, report)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 boxNamespaces,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
	}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGKILL) }
	return cmd, nil
}

// Run runs the program in a box and waits for it.
func (n Native) Run(ctx context.Context, s Spec) (Result, error) {
	if a := n.Check(); !a.OK {
		return Result{}, fmt.Errorf("%w: %s", ErrUnavailable, a.Why)
	}
	if !filepath.IsAbs(s.Program) {
		return Result{}, fmt.Errorf("%q is not an absolute path to a program", s.Program)
	}
	if s.Workdir == "" || !filepath.IsAbs(s.Workdir) {
		return Result{}, errors.New("a box needs its own working directory")
	}
	ss := shimSpec{Program: s.Program, Args: s.Args, ReadWrite: []string{s.Workdir}, Limits: s.Limits}
	for _, p := range append(append([]string(nil), systemReads...), s.Read...) {
		if _, err := os.Stat(p); err == nil {
			ss.Read = append(ss.Read, p)
		}
	}
	ss.Read = append(ss.Read, s.Program)
	for _, sv := range s.Services {
		ss.Ports = append(ss.Ports, sv.Port)
	}
	shimArg, err := json.Marshal(ss)
	if err != nil {
		return Result{}, err
	}
	spec := initSpec{Forward: s.Services, Env: s.Env, Dir: s.Workdir,
		Shim: append(append([]string{n.Exe}, n.Shim...), string(shimArg))}

	if s.Wall > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Wall)
		defer cancel()
	}
	rr, rw, err := os.Pipe()
	if err != nil {
		return Result{}, err
	}
	cmd, err := n.command(ctx, spec, rw)
	if err != nil {
		rr.Close()
		rw.Close()
		return Result{}, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s.Stdin, s.Stdout, s.Stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		rr.Close()
		rw.Close()
		return Result{}, err
	}
	rw.Close()
	var conf Confinement
	reported := make(chan struct{})
	go func() {
		defer close(reported)
		b, _ := io.ReadAll(io.LimitReader(rr, 4096))
		rr.Close()
		_ = json.Unmarshal(b, &conf)
	}()
	werr := cmd.Wait()
	<-reported
	conf.Backend, conf.Namespaces = "native", true
	res := Result{Took: time.Since(start), Confined: conf}
	if ctx.Err() == context.DeadlineExceeded {
		res.Stopped = fmt.Sprintf("it ran for its whole time (%s) and was stopped", s.Wall)
	} else if ctx.Err() != nil {
		res.Stopped = "the run was cancelled"
	}
	var ee *exec.ExitError
	switch {
	case werr == nil:
	case errors.As(werr, &ee):
		res.Exit = ee.ExitCode()
		if res.Exit == shimRefused && res.Stopped == "" {
			return res, fmt.Errorf("the program was not started, because its box could not be closed: %s", conf.Note)
		}
	default:
		return res, werr
	}
	return res, nil
}

// shimRefused is the exit code of a shim that would not run the program
// unconfined.
const shimRefused = 125

// InitMain is the box's first process. It does not return.
func InitMain() {
	spec := initSpec{}
	in := os.NewFile(3, "spec")
	if err := json.NewDecoder(io.LimitReader(in, 1<<20)).Decode(&spec); err != nil {
		fail("the box's spec: " + err.Error())
	}
	in.Close()
	if err := loopbackUp(); err != nil {
		fail("the box's loopback: " + err.Error())
	}
	if spec.Probe {
		os.Exit(0)
	}
	proc := ownProc()
	sys := proc && ownSys()
	for _, sv := range spec.Forward {
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(int(sv.Port)))
		if err != nil {
			fail("the box's " + sv.Name + " port: " + err.Error())
		}
		go forward(ln, sv.Socket)
	}
	if len(spec.Shim) == 0 {
		fail("nothing to run")
	}
	report := os.NewFile(4, "report")
	cmd := exec.Command(spec.Shim[0], spec.Shim[1:]...)
	cmd.Env, cmd.Dir = spec.Env, spec.Dir
	if proc {
		cmd.Env = append(append([]string(nil), spec.Env...), boxProc+"=1")
	}
	if sys {
		cmd.Env = append(cmd.Env, boxSys+"=1")
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if report != nil {
		cmd.ExtraFiles = []*os.File{report}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		fail("the program: " + err.Error())
	}
	if report != nil {
		report.Close()
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for s := range sig {
			_ = cmd.Process.Signal(s)
		}
	}()
	err := cmd.Wait()
	var ee *exec.ExitError
	switch {
	case err == nil:
		os.Exit(0)
	case errors.As(err, &ee):
		if st, ok := ee.Sys().(syscall.WaitStatus); ok && st.Signaled() {
			os.Exit(128 + int(st.Signal()))
		}
		os.Exit(ee.ExitCode())
	}
	fail(err.Error())
}

func fail(why string) {
	fmt.Fprintln(os.Stderr, "quilzo box: "+why)
	os.Exit(shimRefused)
}

// boxProc tells the shim the box has a /proc of its own, which it then
// lets the program read; the shim removes it before the program starts.
const boxProc = "QUILZO_BOX_OWN_PROC"

// ownProc gives the box a /proc showing only its own processes, when the
// kernel lets it mount one. Without it the program reads nothing under
// /proc but its own few entries, because the machine's /proc would show it
// every process here.
func ownProc() bool {
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return false
	}
	return syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "") == nil
}

// boxSys tells the shim the box has a /sys of its own, as boxProc does for
// /proc.
const boxSys = "QUILZO_BOX_OWN_SYS"

// ownSys gives the box a /sys of its own: empty, read-only, but for the
// directories programs look in to learn about the machine. The machine's
// /sys lists its hardware, which a program has no business reading; and
// with none at all, a browser's graphics probe (libpci) cannot open
// /sys/bus/pci/devices and exits the whole browser. Here it finds no
// devices and carries on without them.
func ownSys() bool {
	if err := syscall.Mount("tmpfs", "/sys", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC,
		"size=64k,mode=0755"); err != nil {
		return false
	}
	for _, d := range []string{"/sys/bus/pci/devices", "/sys/devices/system/cpu", "/sys/fs/cgroup"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return false
		}
	}
	return syscall.Mount("tmpfs", "/sys", "tmpfs",
		syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "") == nil
}

// loopbackUp raises the box's loopback, which a new network namespace
// starts with down.
func loopbackUp() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var ifr [40]byte // struct ifreq: a 16-byte name, then the flags
	copy(ifr[:], "lo")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return errno
	}
	flags := *(*uint16)(unsafe.Pointer(&ifr[16]))
	*(*uint16)(unsafe.Pointer(&ifr[16])) = flags | syscall.IFF_UP | syscall.IFF_RUNNING
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return errno
	}
	return nil
}

// ShimMain confines this process and becomes the program. It returns only
// when it refused, having said why.
func ShimMain(arg string) {
	runtime.LockOSThread()
	report := os.NewFile(3, "report")
	say := func(c Confinement) {
		if report != nil {
			b, _ := json.Marshal(c)
			_, _ = report.Write(b)
			report.Close()
			report = nil
		}
	}
	var s shimSpec
	if err := json.Unmarshal([]byte(arg), &s); err != nil {
		say(Confinement{Note: "the shim's spec: " + err.Error()})
		os.Exit(shimRefused)
	}
	// What a program reads of itself and of the machine's size: its own
	// entries under /proc, and the three files runtimes size themselves by.
	reads := append([]string(nil), s.Read...)
	procs := []string{"/proc/self", "/proc/cpuinfo", "/proc/meminfo", "/proc/stat"}
	ownProc := os.Getenv(boxProc) == "1"
	if ownProc {
		procs = []string{"/proc"}
	}
	os.Unsetenv(boxProc)
	if os.Getenv(boxSys) == "1" {
		procs = append(procs, "/sys")
	}
	os.Unsetenv(boxSys)
	for _, p := range append(procs, "/dev/urandom", "/dev/random", "/dev/zero") {
		if _, err := os.Stat(p); err == nil {
			reads = append(reads, p)
		}
	}
	st, err := sandbox.Restrict(sandbox.Rules{Read: reads, ReadWrite: append(s.ReadWrite, "/dev/null"),
		ConnectPorts: s.Ports, Hardened: true, Limits: s.Limits})
	c := Confinement{Landlock: st.ABI, Files: st.Enforced, Ports: st.NetworkDenied,
		Seccomp: st.Seccomp, Capabilities: st.CapabilitiesDropped, OwnProc: ownProc, Note: st.NetworkWhy}
	switch {
	case err != nil:
		c.Note = err.Error()
	case !st.Enforced || !st.NetworkDenied || !st.Seccomp || !st.CapabilitiesDropped:
		c.Note = "the box could not be closed: " + st.Why
	default:
		say(c)
		argv := append([]string{s.Program}, s.Args...)
		err = syscall.Exec(s.Program, argv, os.Environ())
		fmt.Fprintln(os.Stderr, "quilzo box: cannot start "+s.Program+": "+err.Error())
		os.Exit(127)
	}
	say(c)
	fmt.Fprintln(os.Stderr, "quilzo box: refusing to run the program unconfined: "+c.Note)
	os.Exit(shimRefused)
}
