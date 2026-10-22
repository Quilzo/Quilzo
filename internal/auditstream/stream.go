// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package auditstream pushes the audit log out as it is written, to a SIEM
// that keeps it where Quilzo cannot reach (NIST SP 800-53 AU-4(1), AU-9(2)).
//
// Pushed, so Quilzo grants nobody a way in. Each batch is a run of records
// as OCSF (internal/siem), with what lets the receiver prove it lost
// nothing and nothing was changed on the way:
//
//   - the sequence range it covers, which follows the last one exactly;
//   - the chain envelope, each record's hash and the one before the first;
//   - each record's Merkle leaf, and a tree head over the log up to the last
//     record, signed with the audit head keys (Ed25519 and ML-DSA), which a
//     receiver keeping the leaves recomputes and checks;
//   - an HTTP message signature (RFC 9421) over the method, the address,
//     the content type and the body's digest (RFC 9530), with a key kept for
//     this alone.
//
// Delivery is at least once: the cursor moves only when the receiver takes
// the batch, and a receiver that says it holds less, or more, moves it
// there. The same stream suits any SIEM that reads OCSF; Receiver is the
// receiving half, for one that wants the proofs.
package auditstream

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/httpsig"
	"github.com/quilzo/quilzo/internal/siem"
	"github.com/quilzo/quilzo/internal/translog"
)

// MaxBatch is the most records one batch carries.
const MaxBatch = 500

// Covered are the request components every batch's signature covers, and
// the ones a receiver requires.
var Covered = []string{"@method", "@target-uri", "content-type", "content-digest"}

// Batch is what one request carries.
type Batch struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
	// OCSF is the records as OCSF, one JSON object per line.
	OCSF     string        `json:"ocsf"`
	Envelope siem.Envelope `json:"envelope"`
	// Leaves are each record's Merkle leaf data, hex, in order.
	Leaves []string `json:"leaves"`
	// Head is the signed tree head over the log's first To records.
	Head audit.SignedHead `json:"head"`
}

// Cursor is how far the stream has got, kept in one file.
type Cursor struct {
	// Sent is the last sequence number the receiver took.
	Sent     int64     `json:"sent"`
	At       time.Time `json:"at,omitzero"`
	Error    string    `json:"error,omitempty"`
	Failures int       `json:"failures,omitempty"`
	// Since is when the failures began, for saying how long it has failed.
	Since time.Time `json:"since,omitzero"`
}

// KeyID names a stream key by its public half.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "quilzo-stream-" + hex.EncodeToString(sum[:8])
}

// Sender pushes batches.
type Sender struct {
	URL    string
	Key    ed25519.PrivateKey
	Client *http.Client
	// Read is the whole audit log; Heads signs a tree head.
	Read  func() ([]audit.Event, error)
	Heads *audit.HeadSigner
	// CursorPath is where the cursor is kept.
	CursorPath string
	// Reveal sends identifiers in the clear instead of pseudonymised.
	Reveal bool
}

// Status is the cursor as it stands.
func (s *Sender) Status() (Cursor, error) {
	var c Cursor
	err := atomicfile.Update(s.CursorPath, func(f *Cursor) error {
		c = *f
		return atomicfile.ErrUnchanged
	})
	return c, err
}

// Batch builds the batch after the cursor, or nil when nothing is waiting.
func (s *Sender) Batch(events []audit.Event, sent int64, now time.Time) (*Batch, error) {
	var last int64
	for _, e := range events {
		if e.Seq > last {
			last = e.Seq
		}
	}
	if last <= sent {
		return nil, nil
	}
	to := min(sent+MaxBatch, last)
	res, err := siem.Export(siem.OCSF, events, siem.Options{Reveal: s.Reveal, Since: sent + 1, Until: to}, now)
	if err != nil {
		return nil, err
	}
	var upto []audit.Event
	b := &Batch{From: sent + 1, To: to, OCSF: res.Body, Envelope: res.Chain}
	for _, e := range events {
		if e.Seq > to {
			continue
		}
		upto = append(upto, e)
		if e.Seq >= b.From {
			leaf, err := audit.LeafHash(e)
			if err != nil {
				return nil, err
			}
			b.Leaves = append(b.Leaves, hex.EncodeToString(leaf))
		}
	}
	head, err := audit.TreeHead(upto, now)
	if err != nil {
		return nil, err
	}
	if b.Head, err = s.Heads.Sign(head); err != nil {
		return nil, err
	}
	return b, nil
}

// Push sends what is waiting, a batch at a time, until nothing is or a
// batch is refused; it reports how many records the receiver took.
func (s *Sender) Push(ctx context.Context, now time.Time) (int, error) {
	if s.URL == "" {
		return 0, errors.New("no stream is set: siem.stream.url")
	}
	events, err := s.Read()
	if err != nil {
		return 0, err
	}
	total := 0
	for {
		c, err := s.Status()
		if err != nil {
			return total, err
		}
		b, err := s.Batch(events, c.Sent, now)
		if err != nil || b == nil {
			return total, s.note(c.Sent, err, now)
		}
		took, err := s.send(ctx, b, now)
		if err != nil {
			return total, s.note(c.Sent, err, now)
		}
		if err := s.note(took, nil, now); err != nil {
			return total, err
		}
		if took >= b.To {
			total += int(b.To - b.From + 1)
		}
		if took != b.To {
			// The receiver holds less or more than this batch: the cursor
			// is where it said, and the next round starts from there.
			return total, nil
		}
	}
}

// note records the outcome of a round.
func (s *Sender) note(sent int64, failed error, now time.Time) error {
	err := atomicfile.Update(s.CursorPath, func(c *Cursor) error {
		c.Sent = sent
		if failed == nil {
			c.At, c.Error, c.Failures, c.Since = now.UTC(), "", 0, time.Time{}
			return nil
		}
		if c.Failures == 0 {
			c.Since = now.UTC()
		}
		c.Failures++
		c.Error = failed.Error()
		return nil
	})
	if err != nil {
		return err
	}
	return failed
}

// send delivers one batch and returns the last sequence number the
// receiver holds: the batch's end when it took it, or where it says it is.
func (s *Sender) send(ctx context.Context, b *Batch, now time.Time) (int64, error) {
	body, err := json.Marshal(b)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	httpsig.SetContentDigest(req, body)
	pub := s.Key.Public().(ed25519.PublicKey)
	if err := httpsig.Sign(req, KeyID(pub), httpsig.Ed25519, s.Key, Covered, now); err != nil {
		return 0, err
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("the receiver could not be reached: %w", err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	var ans struct {
		Holds *int64 `json:"holds"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(msg, &ans)
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return b.To, nil
	case resp.StatusCode == http.StatusConflict && ans.Holds != nil && *ans.Holds >= 0:
		return *ans.Holds, nil
	}
	why := ans.Error
	if why == "" {
		why = string(bytes.TrimSpace(msg))
	}
	return 0, fmt.Errorf("the receiver answered %d: %s", resp.StatusCode, why)
}

// ErrGap is a batch that does not follow the last one the receiver holds.
type ErrGap struct{ Holds int64 }

func (e *ErrGap) Error() string {
	return "this batch does not follow the last record held, " + strconv.FormatInt(e.Holds, 10)
}

// Receiver is the receiving half: it takes a batch only when it is signed by
// a key it knows, follows the last one exactly, and its leaves rebuild the
// signed head.
type Receiver struct {
	Keys  []httpsig.PublicKey
	Heads *audit.HeadVerifier
	// MaxAge bounds how old a signature may be.
	MaxAge time.Duration

	log *translog.Log
}

// Restore gives the receiver the leaves it already holds, in order.
func (rc *Receiver) Restore(leaves []string) error {
	rc.log = translog.New()
	for _, l := range leaves {
		b, err := hex.DecodeString(l)
		if err != nil {
			return fmt.Errorf("a held leaf is not hex: %w", err)
		}
		rc.log.Append(b)
	}
	return nil
}

// Holds is the last sequence number taken.
func (rc *Receiver) Holds() int64 {
	if rc.log == nil {
		return 0
	}
	return int64(rc.log.Size())
}

// Accept checks a request carrying a batch and takes it.
func (rc *Receiver) Accept(r *http.Request, body []byte, now time.Time) (*Batch, error) {
	if rc.log == nil {
		rc.log = translog.New()
	}
	maxAge := rc.MaxAge
	if maxAge <= 0 {
		maxAge = httpsig.DefaultMaxAge
	}
	signed, err := httpsig.Verify(r, rc.Keys, maxAge, now)
	if err != nil {
		return nil, err
	}
	if signed == nil {
		return nil, errors.New("the batch is not signed")
	}
	for _, c := range Covered {
		if !signed.Covers(c) {
			return nil, fmt.Errorf("the signature does not cover %s", c)
		}
	}
	if err := httpsig.CheckSignedDigest(r, body, signed); err != nil {
		return nil, err
	}
	var b Batch
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, fmt.Errorf("the batch is not readable: %w", err)
	}
	if b.From != rc.Holds()+1 {
		return nil, &ErrGap{Holds: rc.Holds()}
	}
	n := b.To - b.From + 1
	if b.To < b.From || int64(len(b.Leaves)) != n || int64(len(b.Envelope.Hashes)) != n ||
		b.Envelope.FirstSeq != b.From || b.Envelope.LastSeq != b.To {
		return nil, errors.New("the batch's range, leaves and envelope do not agree")
	}
	if err := rc.Heads.Verify(b.Head); err != nil {
		return nil, fmt.Errorf("the tree head does not verify: %w", err)
	}
	if b.Head.Size != int(b.To) {
		return nil, fmt.Errorf("the tree head covers %d records, and the batch ends at %d", b.Head.Size, b.To)
	}
	staged, err := rc.stage(b.Leaves)
	if err != nil {
		return nil, err
	}
	if got := staged.Head(); got.Root != b.Head.Root {
		return nil, errors.New("the leaves do not rebuild the signed tree head: a record was dropped or changed")
	}
	rc.log = staged
	return &b, nil
}

// stage is the held log with leaves appended, leaving the held one alone.
func (rc *Receiver) stage(leaves []string) (*translog.Log, error) {
	staged := rc.log.Clone()
	for _, l := range leaves {
		b, err := hex.DecodeString(l)
		if err != nil {
			return nil, fmt.Errorf("a leaf is not hex: %w", err)
		}
		staged.Append(b)
	}
	return staged, nil
}
