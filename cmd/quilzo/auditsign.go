// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/logd"
)

// The key that signs audit heads, and the file that publishes its public half.
//
// Separate from audit.key, which is a pseudonymisation secret and not a
// signing key: one turns a name into a stable token, the other says this site
// published this root. Sharing a key between the two would mean handing out
// the ability to forge heads to anybody who needs to re-identify a log entry.

func headKeyPath(root string) string {
	return filepath.Join(auditDir(root), "head.key")
}

// headKeysPath is the public half, meant to be copied anywhere.
//
// Published as its own file because a verifier outside this building needs it
// and must not need anything else: a head, this file, and the tool. Nothing in
// it is secret.
func headKeysPath(root string) string {
	return filepath.Join(auditDir(root), "head.pub.json")
}

// storedSeeds is what head.key holds: two 32-byte seeds, base64.
//
// Seeds rather than keys, because an ML-DSA private key is several kilobytes
// and its seed regenerates it exactly. Sixty-four bytes is small enough to
// write down, which is the difference between a key that gets backed up and
// one that does not.
type storedSeeds struct {
	Ed25519 string `json:"ed25519_seed"`
	MLDSA   string `json:"mldsa_seed"`
}

type publishedKeys struct {
	KeyID   string `json:"key_id"`
	Ed25519 string `json:"ed25519"`
	MLDSA   string `json:"mldsa"`
	Note    string `json:"note"`
}

// headSigning is what signs for the log: the key itself, or the log writer
// that holds it.
//
// Every caller signs a head it computed (auditlog head, receipts, the audit
// stream, engagement packages) or a statement over a digest (feature
// packages, research plans), and reads the public half to say what checks
// it. Neither needs to know which of the two is signing.
type headSigning interface {
	Sign(audit.Head) (audit.SignedHead, error)
	SignStatement(context string, msg []byte) (audit.Statement, error)
	Verifier() *audit.HeadVerifier
	PostQuantum() bool
	Why() string
}

// headSigner is what signs this store's heads.
//
// The log writer, where the separation is in force: it holds head.key in
// the directory it owns and this account cannot write, and in the
// reference compose cannot write at all, so loading the key here failed
// with "read-only file system" on every receipt, every head and every
// round of the audit stream. Where the log is this account's own (in the
// store, or a writer running as this same account) the key is loaded here,
// as it always was.
func headSigner(root string) (headSigning, error) {
	if sock, ok := writerSigns(root); ok {
		ws, err := newWriterSigner(root, sock)
		if err != nil {
			return nil, err
		}
		return ws, nil
	}
	s, err := localHeadSigner(root)
	if err != nil {
		// The log is another account's and nothing listens for it: the
		// key is the writer's, and the fix is the writer, not a chown that
		// would hand this account the key. So the cause is given bare,
		// without the advice localHeadSigner adds for a log this account
		// keeps itself: under the reference compose, with the writer
		// stopped, the message said both to start the writer and to chown
		// its key over, and only the first is right.
		if separated, _ := logd.CheckOwnership(auditPath(root), os.Geteuid()); separated {
			cause := err
			var pe *fs.PathError
			if errors.As(err, &pe) {
				cause = pe
			}
			return nil, fmt.Errorf("%s.\n  %v", writerNotRunning(root), cause)
		}
		return nil, err
	}
	return s, nil
}

// writerNotRunning is what stops a head being made where the log is
// another account's and no writer listens for it.
func writerNotRunning(root string) string {
	return fmt.Sprintf("the log writer holds this store's head key, and it is not running (%s): "+
		"start quilzo logd, as the account that owns the log", logSocketPath(root))
}

// headsSignedBy says who signs this store's heads, as headSigner would
// choose, and why no head can be made now (empty when one can).
//
// Worked out without loading the key, which would make one where there is
// none: `logd status` and the audit log screen report on the key, and a
// report that changes what it reports on is not a report. Where the writer
// is to sign, it is asked, with a head over no entries, rather than
// assumed to: a writer that cannot use its key still writes the log and
// says why on its own stderr, which nobody running the CMS reads, and the
// key it once published says nothing about whether it signs with it now.
// That head reads nothing and writes nothing, and goes through the checks
// every caller makes, the root and the published keys.
func headsSignedBy(root string) (byWriter bool, refused string) {
	if sock, ok := writerSigns(root); ok {
		ws, err := newWriterSigner(root, sock)
		if err != nil {
			return true, err.Error()
		}
		nothing, err := audit.TreeHead(nil, time.Now())
		if err == nil {
			_, err = ws.Sign(nothing)
		}
		if err != nil {
			return true, err.Error()
		}
		return true, ""
	}
	// The log is another account's and no writer listens. headSigner falls
	// back to a key this account can read, as it did before the writer
	// held one; without one, the heads wait for the writer.
	if separated, _ := logd.CheckOwnership(auditPath(root), os.Geteuid()); separated {
		if f, err := os.Open(headKeyPath(root)); err == nil {
			_ = f.Close()
			return false, ""
		}
		return true, writerNotRunning(root)
	}
	return false, ""
}

// writerSigns reports whether the log writer signs this store's heads: the
// separation is in force, as `quilzo logd status` reports it, with a writer
// on the socket and the log owned by an account this one is not.
func writerSigns(root string) (string, bool) {
	sock := logSocketPath(root)
	if !fileExists(sock) {
		return "", false
	}
	separated, _ := logd.CheckOwnership(auditPath(root), os.Geteuid())
	return sock, separated
}

// localHeadSigner loads the signing keys, creating them on first use.
//
// Created rather than demanded: an unsigned head is the state this exists to
// end, and requiring a setup command first would mean the default stayed
// unsigned for everybody who did not read about it. The log writer calls
// this when it starts, for the directory it owns.
func localHeadSigner(root string) (*audit.HeadSigner, error) {
	var seeds storedSeeds
	body, err := os.ReadFile(headKeyPath(root))
	switch {
	case os.IsNotExist(err):
		edSeed, mlSeed, gerr := audit.GenerateHeadSeeds()
		if gerr != nil {
			return nil, gerr
		}
		seeds = storedSeeds{
			Ed25519: base64.StdEncoding.EncodeToString(edSeed),
			MLDSA:   base64.StdEncoding.EncodeToString(mlSeed),
		}
		out, merr := json.MarshalIndent(seeds, "", "  ")
		if merr != nil {
			return nil, merr
		}
		if werr := os.MkdirAll(auditDir(root), 0o700); werr != nil {
			return nil, werr
		}
		// 0600. Anybody who reads this can sign a head saying the log is
		// something it is not, which is the one claim this whole mechanism
		// exists to make unforgeable.
		if werr := os.WriteFile(headKeyPath(root), append(out, '\n'), 0o600); werr != nil {
			return nil, fmt.Errorf("cannot write the head signing key: %w", werr)
		}
	case os.IsPermission(err):
		// A key this account cannot read beside a log it keeps itself,
		// made by another account: root running a command, say. The
		// writer never gets here with another account's key, which it
		// refuses before reading (logd.CheckKey): a chown would hand it a
		// key somebody else has held.
		return nil, fmt.Errorf("cannot read the head signing key at %s: %w\n"+
			"  it belongs to the account that writes the log, which holds it at 0600:\n"+
			"    chown <log-account> %s",
			headKeyPath(root), err, headKeyPath(root))
	case err != nil:
		return nil, err
	default:
		if uerr := json.Unmarshal(body, &seeds); uerr != nil {
			return nil, fmt.Errorf("%s is not readable: %w", headKeyPath(root), uerr)
		}
	}

	edSeed, err := base64.StdEncoding.DecodeString(seeds.Ed25519)
	if err != nil {
		return nil, fmt.Errorf("the Ed25519 seed is not base64: %w", err)
	}
	mlSeed, err := base64.StdEncoding.DecodeString(seeds.MLDSA)
	if err != nil {
		return nil, fmt.Errorf("the ML-DSA seed is not base64: %w", err)
	}
	s, err := audit.NewHeadSigner(edSeed, mlSeed)
	if err != nil {
		return nil, err
	}

	// The public half is rewritten whenever the key is loaded, so it cannot
	// drift from the key that is actually signing. A published key that names
	// a retired one is worse than none: it makes every genuine head look
	// forged.
	if err := writePublishedKeys(root, s); err != nil {
		return nil, err
	}
	return s, nil
}

// writerSigner signs through the log writer, which holds the key.
//
// It checks what it is handed before handing it on. The writer's head is
// over the writer's file, and one whose root is not the root this process
// computed means the two are not reading the same log: a receipt whose
// proofs resolve against one root under a head naming another proves
// nothing, so it is refused here rather than found out by whoever checks
// it. And every signature is checked against the published keys
// (head.pub.json), so a writer signing with a key other than the one it
// publishes is caught by the first caller rather than by an auditor.
type writerSigner struct {
	socket, keys string
	// pub is the published verifier, as callers are given it; check is the
	// same key, accepting a single signature where the writer has no
	// ML-DSA half to make the second.
	pub, check *audit.HeadVerifier
}

func newWriterSigner(root, sock string) (*writerSigner, error) {
	keys := headKeysPath(root)
	v, err := publishedVerifier(keys)
	if err != nil {
		return nil, fmt.Errorf("the log writer signs this store's heads, and its public keys "+
			"cannot be read: %w\n  the writer makes them when it starts; restart quilzo logd "+
			"with this version", err)
	}
	check := *v
	if _, ml := v.PublicKeys(); len(ml) == 0 {
		check.AcceptSingle = true
	}
	return &writerSigner{socket: sock, keys: keys, pub: v, check: &check}, nil
}

func (s *writerSigner) Sign(h audit.Head) (audit.SignedHead, error) {
	sh, err := logd.SignHead(s.socket, h.Size)
	if err != nil {
		return audit.SignedHead{}, fmt.Errorf("the log writer holds this store's head key "+
			"and did not sign: %w", err)
	}
	if sh.Size != h.Size || sh.Root != h.Root {
		return audit.SignedHead{}, fmt.Errorf("the log writer's head over the first %d "+
			"entries has root %s, and this account read root %s from the same entries: the "+
			"log it reads is not the one the writer keeps (quilzo auditlog verify)",
			sh.Size, sh.Root, h.Root)
	}
	if err := s.check.Verify(*sh); err != nil {
		return audit.SignedHead{}, fmt.Errorf("the log writer's head does not verify against "+
			"%s: %w", s.keys, err)
	}
	return *sh, nil
}

func (s *writerSigner) SignStatement(context string, msg []byte) (audit.Statement, error) {
	st, err := logd.SignStatement(s.socket, context, msg)
	if err != nil {
		return audit.Statement{}, fmt.Errorf("the log writer holds this store's signing key "+
			"and did not sign: %w", err)
	}
	if err := s.check.VerifyStatement(context, msg, *st); err != nil {
		return audit.Statement{}, fmt.Errorf("the log writer's signature does not verify "+
			"against %s: %w", s.keys, err)
	}
	return *st, nil
}

func (s *writerSigner) Verifier() *audit.HeadVerifier { return s.pub }

func (s *writerSigner) PostQuantum() bool {
	_, ml := s.pub.PublicKeys()
	return len(ml) > 0
}

func (s *writerSigner) Why() string {
	if s.PostQuantum() {
		return ""
	}
	return "the log writer publishes an Ed25519 key alone (" + s.keys + "), so its heads " +
		"carry one signature: it was built against a module without ML-DSA"
}

func writePublishedKeys(root string, s *audit.HeadSigner) error {
	v := s.Verifier()
	ed, ml := v.PublicKeys()
	out, err := json.MarshalIndent(publishedKeys{
		KeyID:   v.KeyID(),
		Ed25519: base64.StdEncoding.EncodeToString(ed),
		MLDSA:   base64.StdEncoding.EncodeToString(ml),
		Note: "Public keys for this site's audit heads. Copy this anywhere; " +
			"nothing in it is secret. A head verifies only if both signatures " +
			"do — see quilzo auditlog verify-head.",
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(auditDir(root), 0o700); err != nil {
		return err
	}
	// Replaced in one step, because it is read while it is written: this
	// runs every time the key is loaded, by every agent receipt, audit head
	// and round of the audit stream, and a research plan is checked against
	// this file whenever its project is shown. Truncated and then written,
	// a check landing between the two read an empty file and reported an
	// honest plan as one that does not check.
	return atomicfile.Write(headKeysPath(root), append(out, '\n'), 0o644)
}

// verifyHead checks a signed head from a file against published keys.
//
// A separate command because verification is what somebody outside does, and
// the thing they have is a file. It reads keys from --keys so that an auditor
// can check a head against the keys they were given rather than against
// whatever this machine currently holds — which would be checking a claim
// against itself.
func auditVerifyHead(root string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf(
			"usage: quilzo auditlog verify-head <head.json> [--keys head.pub.json]")
	}
	headPath := args[0]
	keysPath := headKeysPath(root)
	for i := 1; i < len(args)-1; i++ {
		if args[i] == "--keys" {
			keysPath = args[i+1]
		}
	}

	body, err := os.ReadFile(headPath)
	if err != nil {
		return err
	}
	var sh audit.SignedHead
	if err := json.Unmarshal(body, &sh); err != nil {
		return fmt.Errorf("%s is not a signed head: %w", headPath, err)
	}

	kb, err := os.ReadFile(keysPath)
	if err != nil {
		return fmt.Errorf("cannot read the public keys at %s: %w", keysPath, err)
	}
	var pub publishedKeys
	if err := json.Unmarshal(kb, &pub); err != nil {
		return fmt.Errorf("%s is not a published key file: %w", keysPath, err)
	}
	ed, err := base64.StdEncoding.DecodeString(pub.Ed25519)
	if err != nil {
		return fmt.Errorf("the published Ed25519 key is not base64: %w", err)
	}
	ml, err := base64.StdEncoding.DecodeString(pub.MLDSA)
	if err != nil {
		return fmt.Errorf("the published ML-DSA key is not base64: %w", err)
	}
	v, err := audit.NewHeadVerifier(ed, ml)
	if err != nil {
		return err
	}
	if err := v.Verify(sh); err != nil {
		return fmt.Errorf("this head does not verify: %w", err)
	}

	if w.JSON(map[string]any{
		"verified": true, "size": sh.Size, "root": sh.Root,
		"key_id": sh.KeyID, "algorithms": []string{"ed25519", "ml-dsa-65"},
	}) {
		return nil
	}
	w.Human("%sverified%s  %d entries, root %s\n", bold, reset, sh.Size, sh.Root)
	w.Human("  %ssigned by %s with Ed25519 and ML-DSA-65, and both check out%s\n",
		dim, sh.KeyID, reset)
	w.Human("\n  %sthis says the head came from that key. Whether it describes\n"+
		"  the log you hold is a separate question:%s\n", dim, reset)
	w.Human("    %squilzo auditlog consistency%s\n", dim, reset)
	return nil
}
