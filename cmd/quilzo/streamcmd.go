// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auditstream"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// The audit log pushed to a SIEM as it is written (internal/auditstream):
// `quilzo siem stream`, and the round quilzo serve runs.

// StreamEvery is how often quilzo serve sends what is waiting.
const StreamEvery = 15 * time.Second

func streamKeyPath(root string) string    { return filepath.Join(root, "stream.key") }
func streamCursorPath(root string) string { return filepath.Join(root, "stream.json") }

// streamKey is the key batches are signed with, made on first use and kept
// beside the store, private to its account.
func streamKey(root string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(streamKeyPath(root))
	if errors.Is(err, os.ErrNotExist) {
		_, key, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, gerr
		}
		enc := base64.StdEncoding.EncodeToString(key.Seed())
		if werr := os.WriteFile(streamKeyPath(root), []byte(enc+"\n"), 0o600); werr != nil {
			return nil, fmt.Errorf("cannot keep the stream key: %w", werr)
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(string(trimNewline(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not a stream key", streamKeyPath(root))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// streamSender is the stream as configured, or nil when none is set.
func streamSender(root string) (*auditstream.Sender, error) {
	cfg := mustConfig(root)
	url := cfg.Raw("siem.stream.url")
	if url == "" {
		return nil, nil
	}
	key, err := streamKey(root)
	if err != nil {
		return nil, err
	}
	heads, err := headSigner(root)
	if err != nil {
		return nil, err
	}
	reach := fetch.OnThisNetwork
	if cfg.Bool("siem.stream.allow_remote") {
		reach = fetch.Anywhere
	}
	return &auditstream.Sender{URL: url, Key: key, Client: fetch.Speaking("siem", reach, 30*time.Second),
		Read: func() ([]audit.Event, error) { return audit.Read(auditPath(root)) }, Heads: heads,
		CursorPath: streamCursorPath(root), Reveal: cfg.Bool("siem.stream.reveal")}, nil
}

// streamJob sends what is waiting; quilzo serve runs it every StreamEvery.
// Read afresh each round, so setting siem.stream.url starts it and clearing
// it stops it without a restart.
func streamJob(root string) upkeep.Job {
	return upkeep.Job{Name: "stream", Do: func(now time.Time) (int, error) {
		s, err := streamSender(root)
		if err != nil || s == nil {
			return 0, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		return s.Push(ctx, now)
	}}
}

// cmdSiemStream is `quilzo siem stream status | key | send`.
func cmdSiemStream(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "key":
		key, err := streamKey(root)
		if err != nil {
			return err
		}
		pub := key.Public().(ed25519.PublicKey)
		heads, err := headSigner(root)
		if err != nil {
			return err
		}
		ed, ml := heads.Verifier().PublicKeys()
		out := map[string]string{"key_id": auditstream.KeyID(pub), "alg": "ed25519",
			"public_key":  base64.StdEncoding.EncodeToString(pub),
			"head_key_id": heads.Verifier().KeyID(), "head_ed25519": base64.StdEncoding.EncodeToString(ed),
			"head_mldsa": base64.StdEncoding.EncodeToString(ml)}
		if w.JSON(out) {
			return nil
		}
		w.Human("give the receiving SIEM these, to check what it is sent:\n")
		w.Human("  batches are signed by   %s (ed25519) %s\n", out["key_id"], out["public_key"])
		w.Human("  tree heads are signed by %s (ed25519 and ML-DSA); --json gives both public keys in full\n", out["head_key_id"])
		return nil
	case "status":
		s, err := streamSender(root)
		if err != nil {
			return err
		}
		if s == nil {
			if w.JSON(map[string]any{"set": false}) {
				return nil
			}
			w.Human("no stream is set; quilzo config set siem.stream.url https://...\n")
			return nil
		}
		c, err := s.Status()
		if err != nil {
			return err
		}
		if w.JSON(map[string]any{"set": true, "url": s.URL, "cursor": c}) {
			return nil
		}
		w.Human("streaming to %s\n  sent up to record %d", s.URL, c.Sent)
		if !c.At.IsZero() {
			w.Human(", last at %s", c.At.UTC().Format("15:04 2 Jan"))
		}
		w.Human("\n")
		if c.Failures > 0 {
			w.Human("  %sfailing since %s (%d tries): %s%s\n", yellow, c.Since.UTC().Format("15:04 2 Jan"),
				c.Failures, c.Error, reset)
		}
		return nil
	case "send":
		s, err := streamSender(root)
		if err != nil {
			return err
		}
		if s == nil {
			return errors.New("no stream is set; quilzo config set siem.stream.url https://...")
		}
		n, err := s.Push(context.Background(), time.Now())
		if err != nil {
			return err
		}
		w.Human("sent %d record(s)\n", n)
		return nil
	}
	return errors.New("usage: quilzo siem stream [status] | key | send")
}
