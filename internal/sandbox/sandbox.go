// Package sandbox restricts what a process may read and write, using the
// kernel rather than a promise.
//
// # What this is for
//
// An extension is a subprocess. It gets an empty environment, a timeout and a
// process group that dies as a unit, and that was the whole boundary: it ran
// with the uid that started it, so it could read the token store, the policy
// and the key file. The mitigation was a sentence in a manifest telling
// operators to run extensions as an account that owns nothing, which is advice
// rather than a control.
//
// Landlock is the control. It is unprivileged filesystem access control in the
// Linux kernel since 5.13, and it needs no root, no container and no
// dependency.
//
// # The pitfall this design exists to avoid
//
// landlock_restrict_self applies to the *calling thread*. Go multiplexes
// goroutines across OS threads, so restricting "the process" from Go would mean
// restricting every thread the runtime owns — and Go exposes no supported way
// to do that. The library that manages it reaches into runtime internals with
// go:linkname, which is the sort of thing that breaks on a Go upgrade and takes
// a security control with it.
//
// This never needs that, because of what it is used for. A Landlock domain is
// inherited across execve and by children, so restricting one thread and
// immediately replacing the process image from that same thread produces a
// wholly restricted program:
//
//	runtime.LockOSThread()
//	Restrict(...)          // this thread only
//	syscall.Exec(...)      // the image is replaced; the domain persists
//
// One thread, three syscalls, no runtime internals. Callers that want to
// restrict a child use RestrictAndExec, which is the only correct sequence and
// is therefore the only one offered.
//
// # Best effort, and saying so
//
// The access bits a kernel understands depend on its ABI version, and asking
// for one it does not know fails the whole ruleset. So the mask is clamped to
// what the running kernel supports and the result reports what was actually
// enforced. A sandbox that silently degrades to nothing is worse than none,
// because the operator believes the first one.
package sandbox

// Rules is what a sandboxed process may reach.
//
// Everything not named is denied. That direction is the point: an allow-list
// somebody forgot to extend produces a broken extension and a bug report, and a
// deny-list somebody forgot to extend produces a readable token store and
// nothing at all.
type Rules struct {
	// Read are paths the process may read.
	Read []string
	// ReadWrite are paths it may read and write.
	ReadWrite []string
}

// Status describes what was actually enforced.
type Status struct {
	// ABI is the kernel's Landlock version, 0 when unsupported.
	ABI int
	// Enforced is true when a ruleset was applied to this thread.
	Enforced bool
	// Why explains a sandbox that did not happen, for a caller that has to
	// decide whether to proceed without one.
	Why string
}
