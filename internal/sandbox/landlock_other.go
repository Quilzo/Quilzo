//go:build !linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Landlock is a Linux facility. Everywhere else this reports that it is not
// sandboxing rather than quietly doing nothing, because a caller that believes
// it has a sandbox and does not is worse off than one that knows.

func ABI() int        { return 0 }
func Supported() bool { return false }

func Restrict(Rules) (Status, error) {
	return Status{Why: "filesystem sandboxing needs Linux; this process " +
		"will run with the access of the account that started it"}, nil
}

func RestrictAndExec(r Rules, argv0 string, argv []string, env []string) error {
	st, _ := Restrict(r)
	fmt.Fprintf(os.Stderr, "quilzo: not sandboxed: %s\n", st.Why)
	if _, err := exec.LookPath(argv0); err != nil {
		return err
	}
	return syscall.Exec(argv0, argv, env)
}
