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
func confineProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid: the whole group.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
