// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sandbox

// The generic table's numbers, which arm64 uses; spelt out because the
// syscall package does not name all of them here.
const (
	auditArch = 0xc00000b7 // AUDIT_ARCH_AARCH64
	sysClone  = 220
	sysSocket = 198
)

func archPrelude() []sockFilter { return nil }

func denied() []uint32 {
	return []uint32{
		117, 270, 271, // ptrace, process_vm_readv, process_vm_writev
		104, 294, // kexec_load, kexec_file_load
		105, 273, 106, // init_module, finit_module, delete_module
		280, 241, 282, // bpf, perf_event_open, userfaultfd
		219, 217, 218, // keyctl, add_key, request_key
		40, 39, 41, // mount, umount2, pivot_root
		224, 225, 142, // swapon, swapoff, reboot
		268, 97, // setns, unshare
		265, 264, // open_by_handle_at, name_to_handle_at
		60, 89, // quotactl, acct
		170, 112, 171, 266, // settimeofday, clock_settime, adjtimex, clock_adjtime
		116, 58, 18, 42, // syslog, vhangup, lookup_dcookie, nfsservctl
		sysIoUringSetup, sysIoUringEnter, sysIoUringRegister,
		sysOpenTree, sysMoveMount, sysFsopen, sysFsconfig, sysFsmount, sysFspick,
		sysPidfdGetfd, sysMountSetattr, sysQuotactlFd, sysStatmount, sysListmount, sysOpenTreeAttr,
	}
}

func keyctlNr() uint32 { return 219 }
func mountNr() uint32  { return 40 }
