// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package agentbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/sandbox"
)

// Finding STACK-F5. In the reference compose container the native box could
// not start, and the reason given was AppArmor on Ubuntu 23.10, on a machine
// with no AppArmor at all. What refused the user namespace was the
// container: Docker's default system call filter, under no-new-privileges
// and no capabilities. The reason is now read from what the machine says
// about itself.
func TestTheBoxSaysWhatRefusedItsNamespaces(t *testing.T) {
	if !sandbox.Supported() || sandbox.ABI() < 4 || !sandbox.SeccompSupported() {
		t.Skip("the probe stops before starting a box here")
	}
	const container = "Name:\tquilzo\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n"
	const host = "Name:\tquilzo\nCapEff:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\n"
	for _, c := range []struct {
		name  string
		facts map[string]string
		want  string
		not   string
	}{
		{"a container's system call filter", map[string]string{"/proc/self/status": container},
			"system call filter", "AppArmor"},
		{"Ubuntu's AppArmor restriction", map[string]string{"/proc/self/status": host,
			"/proc/sys/kernel/apparmor_restrict_unprivileged_userns": "1\n"},
			"apparmor_restrict_unprivileged_userns", "system call filter"},
		{"user namespaces switched off", map[string]string{"/proc/self/status": host,
			"/proc/sys/user/max_user_namespaces": "0\n"},
			"user.max_user_namespaces", "AppArmor"},
		{"Debian's older switch", map[string]string{"/proc/self/status": host,
			"/proc/sys/kernel/unprivileged_userns_clone": "0\n"},
			"kernel.unprivileged_userns_clone", "AppArmor"},
		{"nothing to point at", map[string]string{"/proc/self/status": host},
			"user namespaces", "AppArmor"},
	} {
		t.Run(c.name, func(t *testing.T) {
			saved := readProc
			t.Cleanup(func() { readProc = saved })
			readProc = func(p string) ([]byte, error) {
				if v, ok := c.facts[p]; ok {
					return []byte(v), nil
				}
				return nil, os.ErrNotExist
			}
			// A first process that cannot start, so the probe fails the way
			// a refused namespace does, without depending on this machine.
			n := Native{Exe: filepath.Join(t.TempDir(), "no-such-quilzo")}
			a := n.probe()
			if a.OK {
				t.Fatal("a box started from a program that does not exist")
			}
			if !strings.Contains(a.Why, c.want) || strings.Contains(a.Why, c.not) {
				t.Errorf("want %q and not %q in:\n%s", c.want, c.not, a.Why)
			}
		})
	}
}
