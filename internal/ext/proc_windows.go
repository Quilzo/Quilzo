//go:build windows

package ext

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"
)

// Killing an extension means killing what it started, on Windows too.
//
// # What this replaces
//
// CREATE_NEW_PROCESS_GROUP and cmd.Process.Kill(), which reached the child and
// nothing else: a grandchild the extension spawned survived, still holding
// whatever it had opened, with nothing left to reap it. The sandbox argument is
// that an extension cannot outlive the host's decision to stop it, and on this
// platform it could.
//
// # A job object is the Windows process group
//
// A process assigned to a job is in it for life, everything it starts is in it
// too, and JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE means the kernel terminates the
// whole job when the last handle to it closes. That last part is what makes
// this a guarantee rather than a tidy-up: the host does not have to remember to
// kill the tree and does not have to live long enough to do it. If this process
// dies, its handle closes, and the extension's descendants go with it.
//
// # The race, and why the child starts suspended
//
// Assignment happens after the process exists, so a child that runs before it is
// assigned can spawn a grandchild that is outside the job for good. CREATE_
// SUSPENDED closes that window: the process is created, assigned, and only then
// allowed to execute its first instruction. Undoing the suspension needs the
// thread, which os/exec does not expose, so the process's single thread — it can
// only have one, it has not run yet — is found through a toolhelp snapshot.
//
// # No dependency
//
// golang.org/x/sys/windows has every call here. This project has no require
// block and is not getting one, so kernel32 is reached through the standard
// library's lazy-DLL loading, exactly as internal/store/lock_windows.go does for
// LockFileEx. It is more code and it is the same syscall.

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObject    = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJob  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJob = kernel32.NewProc("AssignProcessToJobObject")
	procResumeThread       = kernel32.NewProc("ResumeThread")
	procOpenThread         = kernel32.NewProc("OpenThread")
	procThread32First      = kernel32.NewProc("Thread32First")
	procThread32Next       = kernel32.NewProc("Thread32Next")
)

const (
	// The one that matters: closing the last handle terminates every process
	// in the job.
	jobObjectLimitKillOnJobClose = 0x00002000
	// Which structure SetInformationJobObject is being given.
	jobObjectExtendedLimitInformation = 9
	// A process created suspended has executed nothing, which is the only
	// moment at which assigning it to a job has no race.
	createSuspended     = 0x00000004
	threadSuspendResume = 0x0002
	th32csSnapThread    = 0x00000004

	// PROCESS_SET_QUOTA is not in the standard library's syscall package, so
	// it is named here with its documented value. AssignProcessToJobObject
	// requires it together with PROCESS_TERMINATE, which is.
	processSetQuota = 0x0100
)

// containment is the job this extension and its descendants live in.
type containment struct{ job syscall.Handle }

// confineProcess prepares a command whose whole tree can be stopped.
func confineProcess(cmd *exec.Cmd) *containment {
	c := &containment{}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | createSuspended,
	}
	cmd.Cancel = func() error {
		// Closing the last handle terminates the job: the child, its children,
		// and anything they started. Kill as well, so a command whose job could
		// not be created is still stopped rather than left running because the
		// containment failed.
		c.close()
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	return c
}

// run starts the command inside its job and waits for it.
//
// Start and Wait rather than Run, because the assignment has to happen between
// them: that gap is the whole point of creating the process suspended.
func (c *containment) run(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	defer c.close()

	if err := c.contain(cmd.Process.Pid); err != nil {
		// A process that cannot be contained is not run. Killing it here is
		// the same decision the sandbox makes on other platforms when its
		// confinement is unavailable: refuse rather than proceed unconfined.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("this extension could not be contained: %w", err)
	}
	if err := resume(cmd.Process.Pid); err != nil {
		// It is in the job but suspended, so closing the job on the way out
		// removes it. Left alone it would never run and never exit.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("this extension could not be resumed: %w", err)
	}
	return cmd.Wait()
}

// contain creates the job and puts the process in it.
func (c *containment) contain(pid int) error {
	h, _, err := procCreateJobObject.Call(0, 0)
	if h == 0 {
		return fmt.Errorf("CreateJobObject: %w", err)
	}
	job := syscall.Handle(h)

	info := jobObjectExtendedLimitInfo{}
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	if ok, _, serr := procSetInformationJob.Call(
		uintptr(job),
		uintptr(jobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	); ok == 0 {
		_ = syscall.CloseHandle(job)
		return fmt.Errorf("SetInformationJobObject: %w", serr)
	}

	// The handle os/exec holds is not reachable from here, so the process is
	// opened again. PROCESS_SET_QUOTA and PROCESS_TERMINATE are what
	// AssignProcessToJobObject documents as required.
	const access = processSetQuota | syscall.PROCESS_TERMINATE
	ph, oerr := syscall.OpenProcess(access, false, uint32(pid))
	if oerr != nil {
		_ = syscall.CloseHandle(job)
		return fmt.Errorf("OpenProcess: %w", oerr)
	}
	defer syscall.CloseHandle(ph)

	if ok, _, aerr := procAssignProcessToJob.Call(uintptr(job), uintptr(ph)); ok == 0 {
		_ = syscall.CloseHandle(job)
		return fmt.Errorf("AssignProcessToJobObject: %w", aerr)
	}
	c.job = job
	return nil
}

// close terminates the job, and is safe to call more than once.
func (c *containment) close() {
	if c == nil || c.job == 0 {
		return
	}
	_ = syscall.CloseHandle(c.job)
	c.job = 0
}

// resume lets a process created suspended run.
func resume(pid int) error {
	tid, err := mainThreadOf(pid)
	if err != nil {
		return err
	}
	h, _, oerr := procOpenThread.Call(threadSuspendResume, 0, uintptr(tid))
	if h == 0 {
		return fmt.Errorf("OpenThread: %w", oerr)
	}
	defer syscall.CloseHandle(syscall.Handle(h))

	if r, _, rerr := procResumeThread.Call(h); r == ^uintptr(0) {
		return fmt.Errorf("ResumeThread: %w", rerr)
	}
	return nil
}

// mainThreadOf finds a process's thread. A process that has not run yet has
// exactly one.
func mainThreadOf(pid int) (uint32, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(th32csSnapThread, 0)
	if err != nil {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer syscall.CloseHandle(snap)

	var entry threadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if ok, _, ferr := procThread32First.Call(
		uintptr(snap), uintptr(unsafe.Pointer(&entry))); ok == 0 {
		return 0, fmt.Errorf("Thread32First: %w", ferr)
	}
	for {
		if entry.OwnerProcessID == uint32(pid) {
			return entry.ThreadID, nil
		}
		if ok, _, _ := procThread32Next.Call(
			uintptr(snap), uintptr(unsafe.Pointer(&entry))); ok == 0 {
			return 0, fmt.Errorf("no thread found for process %d", pid)
		}
	}
}

// The structures these calls read, with the layouts the API documents.
// uintptr where the documentation says ULONG_PTR, so the layout is right on
// both architectures.

type threadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobObjectExtendedLimitInfo struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}
