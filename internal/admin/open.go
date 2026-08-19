package admin

import (
	"os/exec"
	"runtime"
)

// Opening the interface, without becoming a desktop application.
//
// The whole of what a native wrapper adds, minus the toolchain: a window that
// appears when the program starts. The manifest beside this file lets the
// browser install that window properly; this is what saves somebody typing the
// address the first time.
//
// Deliberately fail-soft and deliberately not checked. A server that refused to
// start because it could not open a browser would be useless on exactly the
// machines that matter most — a container, a server over SSH, CI — and the
// address is printed either way, so a failure here costs nothing.

// Open asks the desktop to open a URL, and reports whether the attempt was
// even possible on this platform.
//
// The command per platform rather than a library. There are three of them, they
// have not changed in twenty years, and a dependency for this would be a
// release process inside ours in exchange for eleven lines.
func Open(url string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		// rundll32 rather than `start`, which is a shell builtin and would
		// need a shell — and a shell is a place an argument becomes a command.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return false
	}
	// Started rather than run. Waiting would block the server's own startup
	// behind a browser that may take seconds to appear, and the exit status of
	// a launcher says nothing about whether a page opened.
	return cmd.Start() == nil
}
