//go:build windows

package ext

import (
	"os/exec"
	"syscall"
)

// The same containment, as far as Windows offers it without a job object.
//
// CREATE_NEW_PROCESS_GROUP gives the child its own group, so this process's
// console signals do not reach it and the reverse. Killing still reaches only
// the child: a grandchild the extension spawned survives, where the POSIX
// version's negative-pid signal would have taken the whole group.
//
// That difference is real and is not papered over. Containing descendants
// properly on Windows means a job object with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, which is the right answer and is a
// larger piece of work than making the tree compile. Until then this platform
// has weaker containment, and the caller's WaitDelay is what stops a surviving
// grandchild from holding the host: the pipes close and Wait returns regardless
// of what is still running.
func confineProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
}
