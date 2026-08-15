// Package logd is a log writer that runs as somebody else.
//
// # What this changes, precisely
//
// Without it, the process that publishes content is the process that writes the
// audit log, so anything that can execute code as the CMS can rewrite the
// record of what it did. That is a low bar: a template bug, a dependency, a
// mistake in this program.
//
// With it, the log file is owned by a different account and the CMS cannot open
// it at all. The CMS can submit a record over a socket and nothing else — it
// cannot seek, truncate, reorder or delete, because it does not hold a
// descriptor that could. Compromising the CMS no longer compromises the record
// of the compromise.
//
// It does not stop root. Nothing running on the machine can. What it does is
// move the requirement from "code execution as the web application" to "root",
// which is a large gap in practice — and root's rewrite is still caught by a
// published tree head, which is the layer above this one.
//
// # Why the writer computes the chain
//
// The submitting process sends what happened. It does not send a sequence
// number, a previous hash or an entry hash, and if it tries, they are
// discarded.
//
// This is the part that matters. If the CMS computed the chain, a compromised
// CMS could submit a self-consistent run of forged entries and the log would
// verify perfectly. Because the writer computes it, a compromised CMS can add
// records — which is unavoidable, it is the thing generating events — but
// cannot make the log say anything about what came before.
//
// # Why a socket and not a pipe
//
// A pipe would tie the writer's lifetime to one process. Content is published
// by the server, by the CLI, and by a scheduler on a timer, and all three have
// to reach the same log. A unix socket lets the writer outlive any of them, and
// the filesystem enforces who may connect — which is the same permission model
// as the log file itself rather than a second one to get wrong.
package logd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rsh1k/scrivet/internal/audit"
)

// MaxRecordBytes bounds one submission.
//
// An audit record is a few hundred bytes. Sixty-four kilobytes is far past any
// real one and short of the point where a client can make the writer allocate
// something worth noticing.
const MaxRecordBytes = 64 << 10

// SubmitTimeout bounds how long a client may hold a connection.
//
// A client that opens a connection and sends nothing would otherwise occupy the
// writer indefinitely, which is a denial of service against the log — and a log
// that stops recording is the precondition for everything else.
const SubmitTimeout = 5 * time.Second

// Submission is what a client sends.
//
// Deliberately not audit.Record: the fields that make an entry verifiable are
// absent from this type, so a client cannot supply them even by accident. A
// separate type is stronger than validation, because there is nothing to
// validate.
type Submission struct {
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	Outcome   string            `json:"outcome"`
	Principal string            `json:"principal"`
	Kind      string            `json:"kind"`
	Model     string            `json:"model,omitempty"`
	Verified  bool              `json:"verified"`
	Detail    map[string]string `json:"detail,omitempty"`
}

// Response is what the writer answers.
type Response struct {
	// Seq and Hash are assigned by the writer, so a client learns where its
	// record landed without having chosen.
	Seq   int64  `json:"seq,omitempty"`
	Hash  string `json:"hash,omitempty"`
	Error string `json:"error,omitempty"`
}

// Server accepts submissions and appends them.
type Server struct {
	// Log is the only thing holding a descriptor on the file.
	Log *audit.Log
	// AllowUID restricts which accounts may submit. Empty means any account
	// that can reach the socket, which the socket's own mode already limits.
	AllowUID []int
	// OnRefusal is called when a submission is rejected, so a refusal is
	// visible rather than being a silent gap in the log.
	OnRefusal func(reason string, uid int)

	mu sync.Mutex
}

// Serve accepts connections until the listener closes.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed") {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(SubmitTimeout))

	uid := -1
	if u, err := peerUID(conn); err == nil {
		uid = u
		if !s.allowed(u) {
			// Refused before anything is read. A connection from an account
			// that should not be submitting is itself worth knowing about, and
			// reading its payload first would mean parsing bytes from somebody
			// already established as unauthorised.
			s.refuse(conn, fmt.Sprintf(
				"uid %d is not permitted to submit audit records", u), u)
			return
		}
	}

	r := bufio.NewReaderSize(conn, MaxRecordBytes)
	line, err := r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	if len(line) >= MaxRecordBytes {
		s.refuse(conn, "the submission is too large to be an audit record", uid)
		return
	}

	var sub Submission
	if err := json.Unmarshal(line, &sub); err != nil {
		s.refuse(conn, "the submission is not JSON", uid)
		return
	}

	// One writer at a time. The chain is a sequence and two goroutines
	// computing "the previous hash" concurrently would produce two entries
	// claiming the same predecessor.
	s.mu.Lock()
	event, err := s.Log.Append(audit.Record{
		Action: sub.Action, Resource: sub.Resource,
		Outcome:   audit.Outcome(sub.Outcome),
		Principal: sub.Principal, Kind: audit.Kind(sub.Kind),
		Model: sub.Model, Verified: sub.Verified, Detail: sub.Detail,
	})
	s.mu.Unlock()

	if err != nil {
		s.refuse(conn, err.Error(), uid)
		return
	}
	_ = json.NewEncoder(conn).Encode(Response{Seq: event.Seq, Hash: event.Hash})
}

func (s *Server) allowed(uid int) bool {
	if len(s.AllowUID) == 0 {
		return true
	}
	for _, u := range s.AllowUID {
		if u == uid {
			return true
		}
	}
	return false
}

func (s *Server) refuse(conn net.Conn, reason string, uid int) {
	if s.OnRefusal != nil {
		s.OnRefusal(reason, uid)
	}
	_ = json.NewEncoder(conn).Encode(Response{Error: reason})
}

// peerUID reads the connecting account from the kernel.
//
// Asked of the kernel rather than of the client, which is the entire point:
// a uid a client tells you is a claim, and a uid SO_PEERCRED returns is a fact
// the client cannot influence.
func peerUID(conn net.Conn) (int, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *syscall.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(
			int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return -1, err
	}
	if credErr != nil {
		return -1, credErr
	}
	return int(cred.Uid), nil
}

// Listen creates the socket with a mode that decides who may submit.
//
// 0660 and a group: the filesystem is the access control, which is the same
// mechanism protecting the log file rather than a second one to configure
// wrongly. A stale socket from a previous run is removed, because a writer that
// will not start after an unclean shutdown is a writer somebody disables.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if info, err := os.Stat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf(
				"%s exists and is not a socket. Refusing to remove it: this "+
					"path is configuration, and deleting whatever happens to be "+
					"there is how a writer overwrites something it should not",
				path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Submit sends one record to the writer.
//
// The client learns the sequence number it was given, which is what lets a
// caller report where something landed without ever holding the log.
func Submit(path string, sub Submission) (*Response, error) {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("the log writer is not reachable at %s: %w",
			path, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(SubmitTimeout))

	body, err := json.Marshal(sub)
	if err != nil {
		return nil, err
	}
	if len(body) >= MaxRecordBytes {
		return nil, fmt.Errorf("this record is %d bytes, past the limit",
			len(body))
	}
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return nil, err
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("the writer did not answer: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("the writer refused: %s", resp.Error)
	}
	return &resp, nil
}

// CheckOwnership reports whether the separation is actually in force.
//
// Configuration that is not in effect is worse than no configuration, because
// somebody believes it. This answers the only question that matters: can the
// account running the CMS write the log file directly, in which case the socket
// is a formality it can bypass.
func CheckOwnership(logPath string, cmsUID int) (bool, string) {
	info, err := os.Stat(logPath)
	if err != nil {
		return false, fmt.Sprintf("cannot inspect %s: %v", logPath, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, "this platform does not report file ownership"
	}

	if int(st.Uid) == cmsUID {
		return false, fmt.Sprintf(
			"%s is owned by the same account that runs the CMS (uid %d), so "+
				"that account can rewrite it directly and the socket is a "+
				"formality it can bypass", logPath, cmsUID)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return false, fmt.Sprintf(
			"%s is mode %04o, so accounts other than its owner can write to it",
			logPath, info.Mode().Perm())
	}
	return true, fmt.Sprintf(
		"%s is owned by uid %d and the CMS runs as uid %d, so the CMS cannot "+
			"open it for writing", logPath, st.Uid, cmsUID)
}
