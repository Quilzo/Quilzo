// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auditstream"
	"github.com/quilzo/quilzo/internal/httpsig"
)

// The store pushes its audit log to a SIEM on this machine: the receiver,
// given the keys quilzo siem stream key prints, takes every record and can
// prove it holds them all, unchanged.
func TestTheAuditLogStreamsToAReceiverGivenItsKeys(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	key, err := streamKey(root)
	if err != nil {
		t.Fatal(err)
	}
	heads, err := headSigner(root)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	recv := &auditstream.Receiver{Heads: heads.Verifier(),
		Keys: []httpsig.PublicKey{{ID: auditstream.KeyID(pub), Alg: httpsig.Ed25519, Ed: pub}}}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		if _, err := recv.Accept(r, body, time.Now()); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		}
	}))
	defer srv.Close()
	if err := cmdConfig(root, []string{"set", "siem.stream.url", srv.URL + "/quilzo"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSiemStream(root, []string{"send"}); err != nil {
		t.Fatal(err)
	}
	s, _ := streamSender(root)
	c, _ := s.Status()
	if c.Sent == 0 || recv.Holds() != c.Sent || c.Error != "" {
		t.Fatalf("sent %d, the receiver holds %d: %s", c.Sent, recv.Holds(), c.Error)
	}
	if again, _ := streamKey(root); base64.StdEncoding.EncodeToString(again) != base64.StdEncoding.EncodeToString(key) {
		t.Error("the stream key changed between uses")
	}
	if err := cmdConfig(root, []string{"set", "siem.stream.url", "http://siem.example.com/in"}); err == nil {
		t.Error("a stream over plain http to another machine was accepted")
	}
}
