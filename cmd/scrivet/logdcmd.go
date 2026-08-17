package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/quilzo/quilzo/internal/logd"
)

// The socket lives beside the log, not inside the store.
//
// Both ends have to reach it, and only one of them owns the store. Defaulting
// it into the store meant the writer could not bind it — `listen unix
// /srv/store/log.sock: bind: permission denied` — which is not a permissions
// mistake to work around but the separation working: an account that can
// create files in the store is an account that can edit the store.
//
// So the writer needs nothing from the store at all. It is given a directory
// it owns, and the store holds a pointer to that directory which the readers
// follow.
func logSocketPath(root string) string {
	return filepath.Join(auditDir(root), "log.sock")
}

// cmdLogd runs the log writer.
//
// Meant to run as its own account, started by systemd or a container's init.
// The CMS then reaches it over a socket and never opens the log file — so
// anything that can execute code as the CMS can add records, which is
// unavoidable, but cannot rewrite what is already there.
func cmdLogd(root string, args []string) error {
	fs := flag.NewFlagSet("logd", flag.ContinueOnError)
	socket := fs.String("socket", "", "where to listen; defaults to the store")
	allow := fs.String("allow-uid", "",
		"comma-separated uids permitted to submit; empty means anyone who can "+
			"reach the socket")
	logDir := fs.String("log-dir", "",
		"directory this account owns, where the log and its key live; "+
			"recorded in the store so other commands find it")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Refusing to run as root. The writer needs to open one file for appending
	// and bind one socket; root buys it nothing and costs everything if it is
	// ever wrong about a path.
	if os.Geteuid() == 0 {
		return fmt.Errorf(
			"the log writer will not run as root. It needs to append to one " +
				"file and bind one socket, and running it as root means a " +
				"mistake about either is a mistake with root's reach.\n" +
				"  Run it as a dedicated account that owns the log file")
	}

	// Set before anything computes a default from it.
	//
	// The store is deliberately not consulted to check the two agree. This
	// account may have no access to the store at all, which is the point of
	// the separation, so a check here would report a disagreement precisely
	// when the deployment is correct. `scrivet logd status`, run by the
	// account that does own the store, is where they are compared.
	if *logDir != "" {
		if err := os.MkdirAll(*logDir, 0o750); err != nil {
			return err
		}
		logDirOverride = *logDir
	}

	path := *socket
	if path == "" {
		if *logDir != "" {
			path = filepath.Join(*logDir, "log.sock")
		} else {
			path = logSocketPath(root)
		}
	}

	var uids []int
	for _, u := range strings.Split(*allow, ",") {
		if u = strings.TrimSpace(u); u == "" {
			continue
		}
		n, err := strconv.Atoi(u)
		if err != nil {
			return fmt.Errorf("%q is not a uid", u)
		}
		uids = append(uids, n)
	}

	l, err := openAudit(root)
	if err != nil {
		return err
	}
	listener, err := logd.Listen(path)
	if err != nil {
		return err
	}
	defer listener.Close()

	srv := &logd.Server{
		Log: l, AllowUID: uids,
		OnRefusal: func(reason string, uid int) {
			// Refusals go to stderr rather than into the log. Writing them into
			// the log would let anybody who can reach the socket fill it with
			// entries by submitting rubbish, which is a denial of service
			// against the thing being protected.
			fmt.Fprintf(os.Stderr, "%srefused (uid %d): %s%s\n",
				yellow, uid, reason, reset)
		},
	}

	fmt.Fprintf(os.Stderr, "%slog writer on %s%s\n", dim, path, reset)
	fmt.Fprintf(os.Stderr, "  %srunning as uid %d; the CMS submits over this "+
		"socket and never opens the log%s\n", dim, os.Geteuid(), reset)
	if len(uids) > 0 {
		fmt.Fprintf(os.Stderr, "  %saccepting submissions from uid %v only%s\n",
			dim, uids, reset)
	} else {
		fmt.Fprintf(os.Stderr, "  %sany account that can reach the socket may "+
			"submit; --allow-uid narrows that%s\n", yellow, reset)
	}

	// A clean shutdown removes the socket, so the next start is not a stale one
	// even though Listen handles that case too.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		_ = listener.Close()
	}()
	return srv.Serve(listener)
}

// cmdLogdStatus reports whether the separation is actually in force.
func cmdLogdStatus(root string) error {
	sock := logSocketPath(root)
	logPath := auditPath(root)

	_, sockErr := os.Stat(sock)
	running := sockErr == nil
	separated, why := logd.CheckOwnership(logPath, os.Geteuid())

	if w.JSON(map[string]any{
		"socket": sock, "writer_present": running,
		"separated": separated, "detail": why,
	}) {
		return nil
	}

	if !running {
		w.Human("no log writer\n")
		w.Human("  %sthis process writes the audit log itself, so anything that "+
			"can\n  execute code as this account can rewrite the record of what "+
			"it did%s\n", yellow, reset)
		w.Human("\n  %srun `scrivet logd` as a separate account that owns %s%s\n",
			dim, logPath, reset)
		w.Human("  %sthat moves the requirement from code execution as the CMS "+
			"to root%s\n", dim, reset)
		return nil
	}

	w.Human("log writer at %s%s%s\n", bold, sock, reset)
	if separated {
		w.Human("  %s%s%s\n", green, why, reset)
	} else {
		w.Human("  %s%s%s\n", yellow, why, reset)
		w.Human("  %sthe writer is running but the separation is not in force, "+
			"which is\n  worse than not running it: somebody believes it%s\n",
			yellow, reset)
	}
	w.Human("\n  %sroot can still rewrite the log. What stops that being "+
		"deniable is a\n  published tree head — `scrivet auditlog anchor`%s\n",
		dim, reset)
	return nil
}
