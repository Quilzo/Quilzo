//go:build !windows

package ext

import (
	"os/exec"
	"syscall"
)

// Killing an extension means killing what it started.
//
// Two changes, and both are needed. A process group so the signal reaches
// everything the extension spawned, and WaitDelay (set by the caller) so that
// even if something survives the signal, the pipes are closed and Wait returns
// anyway. The first is the fix; the second is the guarantee, because an
// extension can always find a way to keep a descendant alive and the host must
// not care.
// containment is the process group. Nothing to hold on this platform: the
// group is named by the child's own pid and the signal is what closes it. The
// type exists because Windows needs a job handle to keep, and one call shape
// for both is what stops the two from drifting.
type containment struct{}

func confineProcess(cmd *exec.Cmd) *containment {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid: the whole group.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return &containment{}
}

// run starts the command and waits for it.
//
// Run, because on this platform there is nothing to do in between. Windows
// assigns the process to its job between Start and Wait, which is why the
// caller goes through here rather than calling Run itself.
func (c *containment) run(cmd *exec.Cmd) error { return cmd.Run() }
