// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sandbox

import "syscall"

const (
	auditArch = 0xc000003e // AUDIT_ARCH_X86_64
	sysClone  = syscall.SYS_CLONE
	sysSocket = syscall.SYS_SOCKET
)

// archPrelude refuses the x32 ABI, whose calls are numbered from bit 30
// and would otherwise slip past every comparison below.
func archPrelude() []sockFilter {
	return []sockFilter{
		jump(bpfJMP|bpfJGE|bpfK, 0x40000000, 0, 1),
		stmt(bpfRET|bpfK, retErrno|uint32(syscall.ENOSYS)),
	}
}

func denied() []uint32 {
	return []uint32{
		syscall.SYS_PTRACE, 310, 311, // process_vm_readv, process_vm_writev
		syscall.SYS_KEXEC_LOAD, 320, // kexec_file_load
		syscall.SYS_INIT_MODULE, 313, syscall.SYS_DELETE_MODULE, // 313 finit_module
		syscall.SYS_CREATE_MODULE, syscall.SYS_GET_KERNEL_SYMS, syscall.SYS_QUERY_MODULE,
		321, syscall.SYS_PERF_EVENT_OPEN, 323, // bpf, userfaultfd
		syscall.SYS_KEYCTL, syscall.SYS_ADD_KEY, syscall.SYS_REQUEST_KEY,
		syscall.SYS_MOUNT, syscall.SYS_UMOUNT2, syscall.SYS_PIVOT_ROOT,
		syscall.SYS_SWAPON, syscall.SYS_SWAPOFF, syscall.SYS_REBOOT,
		308, syscall.SYS_UNSHARE, // setns
		304, 303, // open_by_handle_at, name_to_handle_at
		syscall.SYS_IOPL, syscall.SYS_IOPERM, syscall.SYS_QUOTACTL, syscall.SYS_ACCT,
		syscall.SYS_SETTIMEOFDAY, syscall.SYS_CLOCK_SETTIME, syscall.SYS_ADJTIMEX, 305, // clock_adjtime
		syscall.SYS_SYSLOG, syscall.SYS_VHANGUP, syscall.SYS_LOOKUP_DCOOKIE,
		syscall.SYS_NFSSERVCTL, syscall.SYS_USELIB,
		sysIoUringSetup, sysIoUringEnter, sysIoUringRegister,
		sysOpenTree, sysMoveMount, sysFsopen, sysFsconfig, sysFsmount, sysFspick,
		sysPidfdGetfd, sysMountSetattr, sysQuotactlFd, sysStatmount, sysListmount, sysOpenTreeAttr,
	}
}

func keyctlNr() uint32 { return syscall.SYS_KEYCTL }
func mountNr() uint32  { return syscall.SYS_MOUNT }
