//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// The three Landlock syscalls. Added to the generic syscall table together, so
// these numbers hold on every architecture Linux supports them on.
const (
	sysCreateRuleset = 444
	sysAddRule       = 445
	sysRestrictSelf  = 446
)

// Flags.
const (
	createRulesetVersion = 1 << 0
	ruleTypePathBeneath  = 1
)

// Network access rights, added in ABI 4.
//
// TCP only. UDP is not restrictable until ABI 10, which matters and is said
// out loud in Status: a process denied every TCP connection can still send
// UDP, so on a kernel below 10 this bounds the obvious channels and not DNS.
const (
	accessNetBindTCP    = 1 << 0
	accessNetConnectTCP = 1 << 1
)

// Filesystem access rights, by the ABI that introduced them.
const (
	accessExecute    = 1 << 0
	accessWriteFile  = 1 << 1
	accessReadFile   = 1 << 2
	accessReadDir    = 1 << 3
	accessRemoveDir  = 1 << 4
	accessRemoveFile = 1 << 5
	accessMakeChar   = 1 << 6
	accessMakeDir    = 1 << 7
	accessMakeReg    = 1 << 8
	accessMakeSock   = 1 << 9
	accessMakeFifo   = 1 << 10
	accessMakeBlock  = 1 << 11
	accessMakeSym    = 1 << 12
	accessRefer      = 1 << 13 // ABI 2
	accessTruncate   = 1 << 14 // ABI 3
	accessIoctlDev   = 1 << 15 // ABI 5
)

// readAccess and writeAccess are the rights a reader and a writer need.
//
// Split because the point of the sandbox is that an extension reads its inputs
// and writes nothing, and a mask that lumps them together cannot express that.
const (
	readAccess  = accessReadFile | accessReadDir
	writeAccess = accessWriteFile | accessRemoveDir | accessRemoveFile |
		accessMakeChar | accessMakeDir | accessMakeReg | accessMakeSock |
		accessMakeFifo | accessMakeBlock | accessMakeSym
)

// rulesetAttr mirrors struct landlock_ruleset_attr.
type rulesetAttr struct {
	HandledAccessFS  uint64
	HandledAccessNet uint64 // ABI 4
	Scoped           uint64 // ABI 6
}

// There is deliberately no per-port rule type or attribute struct here. The
// network restriction works by declaring the rights and granting nothing, so
// nothing in this package ever builds a port rule — and a type kept against
// the day somebody might is weight for nothing. Whoever adds "allow this port"
// adds them with the code that uses them.

// pathBeneathAttr mirrors struct landlock_path_beneath_attr, which the kernel
// declares __attribute__((packed)) — twelve bytes, not sixteen. Getting this
// wrong is not a compile error; it is a ruleset the kernel reads differently
// from the one that was written.
// Go lays this out as offset 0 for AllowedAccess and offset 8 for ParentFD,
// which is what the kernel reads; the trailing padding Go adds is past the
// twelve bytes it looks at and is therefore harmless.
type pathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
}

// ABI reports the Landlock version this kernel implements, or 0 when it has
// none.
func ABI() int {
	r, _, _ := syscall.Syscall(sysCreateRuleset, 0, 0, createRulesetVersion)
	v := int(r)
	if v <= 0 {
		return 0
	}
	return v
}

// handledFor is the access mask a given ABI understands, and the size of the
// attribute struct it expects.
//
// Both are clamped rather than assumed. Asking a kernel for a right it has not
// heard of fails the entire ruleset, so a build that requests the newest bits
// would sandbox nothing on anything older — the failure mode where the control
// is absent precisely on the systems least likely to be noticed.
func handledFor(abi int) (mask uint64, attrSize uintptr) {
	base := uint64(accessExecute | accessWriteFile | accessReadFile |
		accessReadDir | accessRemoveDir | accessRemoveFile | accessMakeChar |
		accessMakeDir | accessMakeReg | accessMakeSock | accessMakeFifo |
		accessMakeBlock | accessMakeSym)
	switch {
	case abi >= 5:
		mask = base | accessRefer | accessTruncate | accessIoctlDev
	case abi == 4:
		mask = base | accessRefer | accessTruncate
	case abi == 3:
		mask = base | accessRefer | accessTruncate
	case abi == 2:
		mask = base | accessRefer
	default:
		mask = base
	}
	switch {
	case abi >= 6:
		attrSize = 24 // fs + net + scoped
	case abi >= 4:
		attrSize = 16 // fs + net
	default:
		attrSize = 8 // fs only
	}
	return mask, attrSize
}

// handledNetFor is the network mask a given ABI understands.
//
// Zero below 4, where the kernel has no network rules at all and asking for
// them would fail the whole ruleset — the filesystem restriction would be lost
// along with the network one it was reaching for.
func handledNetFor(abi int) uint64 {
	if abi < 4 {
		return 0
	}
	return accessNetBindTCP | accessNetConnectTCP
}

// Supported reports whether this kernel can sandbox at all.
func Supported() bool { return ABI() > 0 }

// Restrict applies rules to the calling thread.
//
// The caller must have locked the thread and must not let the goroutine move
// afterwards, which in practice means calling syscall.Exec immediately. Use
// RestrictAndExec unless you are certain why you are not.
func Restrict(r Rules) (Status, error) {
	abi := ABI()
	st := Status{ABI: abi}
	if abi == 0 {
		st.Why = "this kernel has no Landlock; the subprocess will run with " +
			"the filesystem access of the account that started it"
		return st, nil
	}

	// No new privileges, first. landlock_restrict_self refuses without it, and
	// the reason it refuses is the reason it matters: without the flag a
	// restricted process can execute a setuid binary and leave the domain.
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL,
		uintptr(prSetNoNewPrivs), 1, 0, 0, 0, 0); errno != 0 {
		return st, fmt.Errorf("cannot set no_new_privs: %w", errno)
	}

	mask, attrSize := handledFor(abi)
	netMask := handledNetFor(abi)
	if r.AllowNetwork {
		// Handling nothing is how Landlock expresses "do not restrict this".
		// Declaring the rights and then adding no rule denies everything, so
		// the two must not be confused.
		netMask = 0
	}
	attr := rulesetAttr{HandledAccessFS: mask, HandledAccessNet: netMask}
	fd, _, errno := syscall.Syscall(sysCreateRuleset,
		uintptr(unsafe.Pointer(&attr)), attrSize, 0)
	if errno != 0 {
		return st, fmt.Errorf("cannot create a landlock ruleset: %w", errno)
	}
	defer syscall.Close(int(fd))

	add := func(path string, allowed uint64) error {
		// O_PATH: the ruleset needs a handle to the hierarchy, not the file's
		// contents, and O_PATH opens something the process may not read.
		pfd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("cannot open %s for the sandbox: %w", path, err)
		}
		defer syscall.Close(pfd)

		rule := pathBeneathAttr{
			AllowedAccess: allowed & mask, // clamp: unknown bits fail the call
			ParentFD:      int32(pfd),
		}
		if _, _, errno := syscall.Syscall6(sysAddRule, fd,
			ruleTypePathBeneath, uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
			return fmt.Errorf("cannot allow %s: %w", path, errno)
		}
		return nil
	}

	for _, p := range r.Read {
		if err := add(p, readAccess|accessExecute); err != nil {
			return st, err
		}
	}
	for _, p := range r.ReadWrite {
		if err := add(p, readAccess|writeAccess|accessExecute|accessTruncate); err != nil {
			return st, err
		}
	}

	// No net rules are added on purpose. Declaring the rights and granting
	// none denies every TCP bind and connect, which is what an extension
	// should have: it is handed its input on stdin and answers on stdout, so a
	// socket is either a fetch nobody asked for or an exfiltration channel.
	if _, _, errno := syscall.Syscall(sysRestrictSelf, fd, 0, 0); errno != 0 {
		return st, fmt.Errorf("cannot enforce the ruleset: %w", errno)
	}
	st.Enforced = true
	st.NetworkDenied = netMask != 0
	if st.NetworkDenied && abi < 10 {
		st.NetworkWhy = "TCP only; this kernel cannot restrict UDP (Landlock " +
			"ABI 10 or later), so datagram traffic including DNS is unbounded"
	}
	return st, nil
}

// Constants the syscall package does not name.
const (
	// PR_SET_NO_NEW_PRIVS.
	prSetNoNewPrivs = 38
	// O_PATH: a handle to the hierarchy rather than to the file's contents, so
	// the ruleset can name a directory this process may not read.
	oPath = 0x200000
)

// RestrictAndExec sandboxes this thread and replaces the process image.
//
// The only correct way to sandbox a child from Go, and therefore the only one
// offered. Landlock restricts one thread; execve keeps the domain and hands it
// to the new image, so a program launched this way is wholly restricted
// without anybody having to reason about how many threads the runtime has.
//
// It does not return on success.
func RestrictAndExec(r Rules, argv0 string, argv []string, env []string) error {
	// Locked and never unlocked: the restriction belongs to this thread, and a
	// goroutine that migrated between Restrict and Exec would exec from an
	// unrestricted one. There is no Unlock because there is no path where this
	// returns and the thread is safe to reuse.
	runtime.LockOSThread()

	st, err := Restrict(r)
	if err != nil {
		return err
	}
	if !st.Enforced {
		// Reported, not swallowed. The caller decides whether running
		// unsandboxed is acceptable; this cannot decide it for them, and
		// pretending would be the silent degradation this package exists to
		// avoid.
		fmt.Fprintf(os.Stderr, "quilzo: not sandboxed: %s\n", st.Why)
	}
	return syscall.Exec(argv0, argv, env)
}
