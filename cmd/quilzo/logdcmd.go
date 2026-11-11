// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/quilzo/quilzo/internal/logd"
	"github.com/quilzo/quilzo/internal/research"
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
	signUID := fs.String("sign-uid", "",
		"comma-separated uids that may ask for heads and statements; empty "+
			"means every account that may submit")
	signGID := fs.String("sign-gid", "",
		"comma-separated groups an account must connect as to ask for heads "+
			"and statements; empty means any")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// What is left after the flags, answered before anything else. Main
	// answers `quilzo logd help` itself, and not the service's own command
	// with help put after it (`logd --log-dir /srv/audit help`): the word
	// was ignored, so as root the writer refused to run, and as any other
	// account it started, the help never printed. Help never refuses, and
	// a word this takes none of is refused rather than ignored.
	if rest := fs.Args(); len(rest) > 0 {
		if rest[0] == "help" {
			commandHelp("logd", nil)
			return nil
		}
		return fmt.Errorf("quilzo logd takes flags and nothing else, and was given %q: quilzo logd help", rest[0])
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
	// when the deployment is correct. `quilzo logd status`, run by the
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

	uids, err := idList(*allow, "uid")
	if err != nil {
		return err
	}
	// Who may have the log's key speak, of those who may submit. Every
	// account that may submit could, so in the reference compose the public
	// site, which runs as the admin's uid, could have a feature package or
	// a research plan signed as this site's own.
	signers, err := idList(*signUID, "uid")
	if err != nil {
		return err
	}
	signGroups, err := idList(*signGID, "group")
	if err != nil {
		return err
	}

	srv, err := newLogWriter(root, uids)
	if err != nil {
		return err
	}
	srv.SignUID, srv.SignGID = signers, signGroups
	listener, err := logd.Listen(path)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Fprintf(os.Stderr, "%slog writer on %s%s\n", dim, path, reset)
	fmt.Fprintf(os.Stderr, "  %srunning as uid %d; the CMS submits over this "+
		"socket and never opens the log%s\n", dim, os.Geteuid(), reset)
	if srv.Heads != nil {
		fmt.Fprintf(os.Stderr, "  %sit signs the log's heads; the public keys are at %s%s\n",
			dim, headKeysPath(root), reset)
	} else {
		fmt.Fprintf(os.Stderr, "  %sit signs no heads: %s%s\n", yellow, srv.HeadsWhy, reset)
	}
	if len(uids) > 0 {
		fmt.Fprintf(os.Stderr, "  %saccepting submissions from uid %v only%s\n",
			dim, uids, reset)
	} else {
		fmt.Fprintf(os.Stderr, "  %sany account that can reach the socket may "+
			"submit; --allow-uid narrows that%s\n", yellow, reset)
	}
	switch {
	case len(signers) > 0 || len(signGroups) > 0:
		fmt.Fprintf(os.Stderr, "  %ssigning for %s only%s\n", dim, signersWords(signers, signGroups), reset)
	case srv.Heads != nil:
		fmt.Fprintf(os.Stderr, "  %severy account that may submit may ask it to sign; --sign-uid and "+
			"--sign-gid narrow that%s\n", dim, reset)
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

// idList reads a comma-separated list of numeric ids, of a kind: uid or
// group.
func idList(raw, kind string) ([]int, error) {
	var out []int
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%q is not a %s", v, kind)
		}
		out = append(out, n)
	}
	return out, nil
}

// signersWords says who may ask the writer for a signature.
func signersWords(uids, groups []int) string {
	var parts []string
	if len(uids) > 0 {
		parts = append(parts, fmt.Sprintf("uid %v", uids))
	}
	if len(groups) > 0 {
		parts = append(parts, fmt.Sprintf("accounts connecting as group %v", groups))
	}
	return strings.Join(parts, ", and ")
}

// newLogWriter is the writer cmdLogd serves: the log, its file, and the key
// that signs its heads, all in the directory this account owns.
func newLogWriter(root string, uids []int) (*logd.Server, error) {
	l, err := openAudit(root)
	if err != nil {
		return nil, err
	}
	// The log file exists from the start, owned by this account, so `logd
	// status` and every reader can tell the separation is in force before
	// the first record arrives. Until then there was no file to own, and the
	// CMS asking for a head was told the log was its own.
	f, err := os.OpenFile(auditPath(root), os.O_CREATE|os.O_WRONLY|os.O_APPEND, keyMode(root))
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	srv := &logd.Server{
		Log: l, AllowUID: uids,
		// Every kind of statement this program signs with the log's keys,
		// and no other: a feature package (feature export --sign) and a
		// registered research plan.
		Statements: []string{featureContext, research.PlanContext},
		OnRefusal: func(reason string, uid int) {
			// Refusals go to stderr rather than into the log. Writing them into
			// the log would let anybody who can reach the socket fill it with
			// entries by submitting rubbish, which is a denial of service
			// against the thing being protected.
			fmt.Fprintf(os.Stderr, "%srefused (uid %d): %s%s\n",
				yellow, uid, reason, reset)
		},
	}
	// The head key, made here on first start: head.key at 0600, this
	// account's alone, and head.pub.json at 0644 beside it for everybody
	// who checks a head. A writer that cannot load it, or finds one that
	// is not its own alone (logd.CheckKey), still writes the log, which
	// matters more, and says why each signature is refused.
	if kerr := logd.CheckKey(headKeyPath(root), os.Geteuid()); kerr != nil {
		srv.HeadsWhy = kerr.Error()
	} else if srv.Heads, err = localHeadSigner(root); err != nil {
		srv.Heads, srv.HeadsWhy = nil, err.Error()
	}
	return srv, nil
}

// cmdLogdStatus reports whether the separation is actually in force.
func cmdLogdStatus(root string) error {
	sock := logSocketPath(root)
	logPath := auditPath(root)

	_, sockErr := os.Stat(sock)
	running := sockErr == nil
	separated, why := logd.CheckOwnership(logPath, os.Geteuid())
	// Who signs this store's heads, and why none can be made now if none
	// can: read, and asked of the writer, never loaded (headsSignedBy).
	byWriter, refuses := headsSignedBy(root)
	keyID := ""
	if v, err := publishedVerifier(headKeysPath(root)); err == nil {
		keyID = v.KeyID()
	}
	signer := "this account"
	if byWriter {
		signer = "the log writer"
	}

	if w.JSON(map[string]any{
		"socket": sock, "writer_present": running,
		"separated": separated, "detail": why,
		"heads_signed_by": signer, "head_keys": headKeysPath(root), "head_key_id": keyID,
		"writer_signs": byWriter && refuses == "", "writer_refuses": refuses,
	}) {
		return nil
	}

	if !running {
		w.Human("no log writer\n")
		switch {
		case separated && !canAppend(logPath):
			// The separation in force with its writer stopped, as under the
			// reference compose with logd down. Said as this account writing
			// the log itself, which it cannot: what it does goes unrecorded,
			// and an agent's actions are refused (auditReady), until the
			// writer runs.
			w.Human("  %sthe log is another account's, which is the separation in force, and nothing\n"+
				"  is writing it: this account cannot, so until the writer runs what it does is\n"+
				"  not recorded, and what an agent would do is refused%s\n", yellow, reset)
			w.Human("  %s%s%s\n", dim, why, reset)
			w.Human("\n  %sstart `quilzo logd` as the account that owns %s%s\n", dim, logPath, reset)
		case !mayWriteLog(logPath):
			// A log the writer has not made yet, in its directory, or one
			// this account cannot so much as look at: not another account's
			// as far as this account can tell, and not this account's to
			// write either. Said as this account writing it itself.
			w.Human("  %snothing is writing the log, and this account cannot: it is not this\n"+
				"  account's to make or to open, so until the writer runs what it does is\n"+
				"  not recorded, and what an agent would do is refused%s\n", yellow, reset)
			w.Human("  %s%s%s\n", dim, why, reset)
			w.Human("\n  %sstart `quilzo logd` as the account that owns %s%s\n", dim, filepath.Dir(logPath), reset)
		default:
			w.Human("  %sthis process writes the audit log itself, so anything that "+
				"can\n  execute code as this account can rewrite the record of what "+
				"it did%s\n", yellow, reset)
			w.Human("\n  %srun `quilzo logd` as a separate account that owns %s%s\n",
				dim, logPath, reset)
			w.Human("  %sthat moves the requirement from code execution as the CMS "+
				"to root%s\n", dim, reset)
		}
		// The log is another account's and its key out of this one's
		// reach, as under the reference compose with the writer stopped:
		// every head waits for the writer, which nothing above says, and
		// the JSON already reported it as refused.
		if byWriter {
			w.Human("\n  %sits heads are the writer's to sign, so no head, receipt or round of the\n"+
				"  audit stream can be made until it runs:\n  %s%s\n", yellow, refuses, reset)
		}
		return nil
	}

	w.Human("log writer at %s%s%s\n", bold, sock, reset)
	// A socket left behind is not a writer. Said, since every record goes
	// to it and is refused while nothing answers.
	if err := logd.Reachable(sock); err != nil {
		w.Human("  %snothing answers on it, so no record can be written until the writer runs again:\n"+
			"  %v%s\n", yellow, err, reset)
	}
	if separated {
		w.Human("  %s%s%s\n", green, why, reset)
	} else {
		w.Human("  %s%s%s\n", yellow, why, reset)
		w.Human("  %sthe writer is running but the separation is not in force, "+
			"which is\n  worse than not running it: somebody believes it%s\n",
			yellow, reset)
	}
	switch {
	case byWriter && keyID == "":
		// Said before the refusal it causes, because the remedy is the
		// writer's and the refusal names only the file it could not read.
		// The line said "the writer signs its heads" while no head could
		// be checked against keys it had not published, so none was made.
		w.Human("  %sthe writer is to sign this store's heads, and publishes no keys at\n"+
			"  %s, so none can be made: it predates head signing, or could not\n"+
			"  make its key. Restart it with this version and read what it prints%s\n",
			yellow, headKeysPath(root), reset)
	case byWriter && refuses != "":
		w.Human("  %sthe writer is to sign this store's heads, and signs none, so no head,\n"+
			"  receipt or round of the audit stream can be made:\n  %s%s\n", yellow, refuses, reset)
	case byWriter:
		w.Human("  %sthe writer signs its heads with key %s, which this account cannot\n"+
			"  read. The public keys are at %s%s\n", green, keyID, headKeysPath(root), reset)
	default:
		w.Human("  %sheads are signed by this account, with the key beside the log%s\n", dim, reset)
	}
	w.Human("\n  %sroot can still rewrite the log. What stops that being "+
		"deniable is a\n  published tree head — `quilzo auditlog anchor`%s\n",
		dim, reset)
	return nil
}

// canAppend reports whether this account could append to the log at path
// itself. Opening it to append changes nothing in it.
func canAppend(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// mayWriteLog reports whether this account could write the log at path
// itself, as it does with no writer running: append to it, or make it in
// its directory while there is none yet. Asked without writing anything.
//
// Not whether the log is another account's alone. A log the writer has not
// made yet, in a directory that is the writer's, is nobody's, and one in a
// directory this account may not look into cannot be inspected at all:
// both were taken for this account's own, and `logd status` and the
// posture scan said this process writes the log itself of a log it could
// not open.
//
// A directory another account owns is taken as closed to this one unless
// its mode lets a group or others write in it: the one case where this
// cannot tell, and the answer that keeps saying the CMS may write its own
// log is the one that sends somebody to look.
func mayWriteLog(path string) bool {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return canAppend(path)
	case !errors.Is(err, fs.ErrNotExist):
		return false
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return false
	}
	theirs, _ := logd.CheckOwnership(filepath.Dir(path), os.Geteuid())
	return !theirs || os.Geteuid() == 0 || info.Mode().Perm()&0o022 != 0
}
