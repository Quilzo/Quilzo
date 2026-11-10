// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package logd

import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// Signing for the accounts that may not hold the key.
//
// # Why the writer holds the head key
//
// A signed head says "this site's log had these entries". The key that
// signs it lived beside the log and was made by whichever process asked for
// a head first, which in a separated deployment is the CMS — and the CMS
// cannot write that directory, so `auditlog head`, every receipt and every
// round of the audit stream failed with "read-only file system". Making the
// directory writable for it is not the fix: an account that can create files
// beside the log can rename the log.
//
// So the writer holds the key, and the CMS asks it for a signature over the
// socket it already uses for records. The writer is also the right holder on
// its merits: the CMS holding the key could sign a head over any root it
// liked, including one over entries the log never held.
//
// # Why the client sends a size and nothing else
//
// The request names how many entries, from the first, the head is to cover.
// The writer reads them from its own file and computes the root itself. A
// client that could send a root would have the writer sign whatever it was
// told, which is the CMS holding the key by another route. HeadRequest has
// no field for one, so a root in a request is not refused: there is nowhere
// for it to go, the same argument as Submission's.
//
// The time on the head is the writer's clock, for the same reason: a client
// that chose it could backdate a commitment to entries that did not exist
// yet.

// SignTimeout bounds a signing request once it has been read.
//
// Longer than SubmitTimeout, which bounds a client that sends nothing: a
// head is computed over the whole log, and a log of years takes longer to
// hash than a record takes to append.
const SignTimeout = 30 * time.Second

// MaxStatementBytes bounds what a statement may cover.
//
// What is signed this way is a digest: of a feature package, of a research
// plan. A few hundred bytes is generous, and a client that sends more is not
// asking for a digest to be signed.
const MaxStatementBytes = 4 << 10

// HeadRequest asks for a signed head over the first Size entries.
type HeadRequest struct {
	Size int `json:"size"`
}

// StatementRequest asks for a statement over Message under Context: the
// signature a feature package or a research plan carries, which a verifier
// checks against the same published keys as a head (audit.Statement).
type StatementRequest struct {
	Context string `json:"context"`
	Message []byte `json:"message"`
}

// request is a line read for a signing request before it is read as a
// record. A line with neither field is a Submission, as every line was
// before these existed.
//
// A writer older than these reads a signing request as a submission with no
// action, which the log refuses, so the request fails out loud rather than
// leaving an empty record behind.
type request struct {
	SignHead      *HeadRequest      `json:"sign_head,omitempty"`
	SignStatement *StatementRequest `json:"sign_statement,omitempty"`
}

// signing reports whether a line asks for a signature, and answers it.
func (s *Server) signing(conn net.Conn, line []byte, uid int) bool {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		return false
	}
	switch {
	case req.SignHead != nil:
		deadline := time.Now().Add(SignTimeout)
		_ = conn.SetDeadline(deadline)
		s.signHead(conn, *req.SignHead, uid, deadline)
	case req.SignStatement != nil:
		_ = conn.SetDeadline(time.Now().Add(SignTimeout))
		s.signStatement(conn, *req.SignStatement, uid)
	default:
		return false
	}
	return true
}

// noSigner is the refusal while the writer has no key to sign with.
func (s *Server) noSigner() string {
	why := s.HeadsWhy
	if why == "" {
		why = "it was started without one"
	}
	return "this writer signs nothing: " + why
}

// oneHead waits, until deadline, for the writer to be computing no other
// head, and returns what ends this one.
//
// One at a time, because a head holds every entry of the log in memory
// while it is computed. Reading the log once held up every record, which
// kept heads in single file as a side effect; without that, heads asked for
// at once each held a copy of their own, and any account that may submit
// could ask for enough to have the writer killed for its memory, after
// which nothing is written at all. Records do not wait in this line: only
// heads do, and a head is worth less than a record.
func (s *Server) oneHead(deadline time.Time) (func(), bool) {
	s.headOnce.Do(func() { s.headSlot = make(chan struct{}, 1) })
	wait := time.NewTimer(time.Until(deadline))
	defer wait.Stop()
	select {
	case s.headSlot <- struct{}{}:
		return func() { <-s.headSlot }, true
	case <-wait.C:
		return nil, false
	}
}

func (s *Server) signHead(conn net.Conn, req HeadRequest, uid int, deadline time.Time) {
	if s.Heads == nil {
		s.refuse(conn, s.noSigner(), uid)
		return
	}
	if req.Size < 0 {
		s.refuse(conn, "a head covers a number of entries, and that is not one", uid)
		return
	}
	release, ok := s.oneHead(deadline)
	if !ok {
		s.refuse(conn, "the writer was computing other heads until this one's time ran out: ask again", uid)
		return
	}
	defer release()
	// The writer's own file, read back through the handle that appends to
	// it. Not verified first: a head over a log that has been tampered with
	// still commits to what the file holds, and that is what makes the
	// tampering provable against a head published before it. A writer that
	// refused would stop the stream at the moment somebody most needs it.
	events, err := s.Log.Events()
	if err != nil {
		s.refuse(conn, "the log cannot be read back to sign a head over it: "+err.Error(), uid)
		return
	}
	if req.Size > len(events) {
		s.refuse(conn, fmt.Sprintf("the log holds %d entries, so there is no head over the first %d",
			len(events), req.Size), uid)
		return
	}
	head, err := audit.TreeHead(events[:req.Size], time.Now())
	if err != nil {
		s.refuse(conn, err.Error(), uid)
		return
	}
	signed, err := s.Heads.Sign(head)
	if err != nil {
		s.refuse(conn, err.Error(), uid)
		return
	}
	_ = json.NewEncoder(conn).Encode(Response{Head: &signed})
}

func (s *Server) signStatement(conn net.Conn, req StatementRequest, uid int) {
	if s.Heads == nil {
		s.refuse(conn, s.noSigner(), uid)
		return
	}
	// Named contexts only. Every statement this program makes has a reader
	// that checks it under one context, and a writer that signed under any
	// would sign the next kind of statement before anybody had decided the
	// CMS should be able to ask for it. The head's own context is refused by
	// audit.SignStatement whatever this list says.
	if !slices.Contains(s.Statements, req.Context) {
		s.refuse(conn, fmt.Sprintf("this writer signs no statement under %q", req.Context), uid)
		return
	}
	if len(req.Message) == 0 || len(req.Message) > MaxStatementBytes {
		s.refuse(conn, fmt.Sprintf("a statement covers a digest of at most %d bytes, and this is %d",
			MaxStatementBytes, len(req.Message)), uid)
		return
	}
	st, err := s.Heads.SignStatement(req.Context, req.Message)
	if err != nil {
		s.refuse(conn, err.Error(), uid)
		return
	}
	_ = json.NewEncoder(conn).Encode(Response{Statement: &st})
}

// SignHead asks the writer at path for a signed head over the first size
// entries of its log. The root in the answer is the writer's own; a caller
// that computed one of its own compares them (cmd/quilzo, writerSigner).
func SignHead(path string, size int) (*audit.SignedHead, error) {
	resp, err := exchange(path, request{SignHead: &HeadRequest{Size: size}}, SignTimeout)
	if err != nil {
		return nil, err
	}
	if resp.Head == nil {
		return nil, fmt.Errorf("the writer answered without a head: it may predate head signing")
	}
	return resp.Head, nil
}

// SignStatement asks the writer at path for a statement over msg under
// context.
func SignStatement(path, context string, msg []byte) (*audit.Statement, error) {
	resp, err := exchange(path, request{SignStatement: &StatementRequest{Context: context, Message: msg}}, SignTimeout)
	if err != nil {
		return nil, err
	}
	if resp.Statement == nil {
		return nil, fmt.Errorf("the writer answered without a statement: it may predate statement signing")
	}
	return resp.Statement, nil
}
