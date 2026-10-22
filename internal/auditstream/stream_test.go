// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auditstream

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/httpsig"
)

var now = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

type rig struct {
	sender *Sender
	recv   *Receiver
	log    *audit.Log
	srv    *httptest.Server
	mu     sync.Mutex
	took   []*Batch
	// tamper changes a request's body before the receiver reads it.
	tamper func([]byte) []byte
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	pseudonyms, err := audit.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.New(audit.Options{Path: filepath.Join(dir, "audit.jsonl"), Source: "test-host", Key: pseudonyms})
	if err != nil {
		t.Fatal(err)
	}
	ed, ml, err := audit.GenerateHeadSeeds()
	if err != nil {
		t.Fatal(err)
	}
	heads, err := audit.NewHeadSigner(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{log: l, recv: &Receiver{Keys: []httpsig.PublicKey{{ID: KeyID(pub), Alg: httpsig.Ed25519, Ed: pub}},
		Heads: heads.Verifier(), MaxAge: 10 * 365 * 24 * time.Hour}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		if r.tamper != nil {
			body = r.tamper(body)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		b, err := r.recv.Accept(req, body, now)
		var gap *ErrGap
		switch {
		case errors.As(err, &gap):
			w.WriteHeader(http.StatusConflict)
			fmt.Fprintf(w, `{"holds":%d}`, gap.Holds)
		case err != nil:
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		default:
			r.took = append(r.took, b)
		}
	}))
	t.Cleanup(r.srv.Close)
	r.sender = &Sender{URL: r.srv.URL + "/ingest", Key: key, Client: r.srv.Client(),
		Read:  func() ([]audit.Event, error) { return audit.Read(filepath.Join(dir, "audit.jsonl")) },
		Heads: heads, CursorPath: filepath.Join(dir, "stream.json")}
	return r
}

func (r *rig) write(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := r.log.Append(audit.Record{Action: "publish", Resource: "/", Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman, Verified: true}); err != nil {
			t.Fatal(err)
		}
	}
}

// The log goes out as it grows: each batch follows the last, is signed, and
// rebuilds a signed tree head at the receiver; the cursor moves as the
// receiver takes each.
func TestTheLogGoesOutInSignedBatchesThatFollowEachOther(t *testing.T) {
	r := newRig(t)
	r.write(t, 3)
	if n, err := r.sender.Push(context.Background(), now); err != nil || n != 3 {
		t.Fatalf("first push: %d %v", n, err)
	}
	r.write(t, 2)
	if n, err := r.sender.Push(context.Background(), now); err != nil || n != 2 {
		t.Fatalf("second push: %d %v", n, err)
	}
	if n, err := r.sender.Push(context.Background(), now); err != nil || n != 0 {
		t.Fatalf("nothing waiting: %d %v", n, err)
	}
	if len(r.took) != 2 || r.took[1].From != 4 || r.took[1].To != 5 || r.recv.Holds() != 5 {
		t.Fatalf("taken: %d batches, holds %d", len(r.took), r.recv.Holds())
	}
	if !strings.Contains(r.took[0].OCSF, `"class_uid"`) || strings.Contains(r.took[0].OCSF, `"dana"`) {
		t.Error("the records are not OCSF, or name people in the clear")
	}
	if c, _ := r.sender.Status(); c.Sent != 5 || c.Error != "" {
		t.Errorf("cursor %+v", c)
	}
}

// More than a batch's worth goes in batches, in order.
func TestALongLogGoesInSeveralBatches(t *testing.T) {
	r := newRig(t)
	r.write(t, MaxBatch+7)
	if n, err := r.sender.Push(context.Background(), now); err != nil || n != MaxBatch+7 {
		t.Fatalf("%d %v", n, err)
	}
	if len(r.took) != 2 || r.took[0].To != MaxBatch || r.took[1].From != MaxBatch+1 {
		t.Fatalf("batches %+v", len(r.took))
	}
}

// A receiver that holds less than the cursor says so, and the sender goes
// back and sends again from there.
func TestAReceiverThatLostRecordsIsSentThemAgain(t *testing.T) {
	r := newRig(t)
	r.write(t, 4)
	if _, err := r.sender.Push(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	held := []string{}
	for _, b := range r.took {
		held = append(held, b.Leaves...)
	}
	if err := r.recv.Restore(held[:2]); err != nil {
		t.Fatal(err)
	}
	r.write(t, 1)
	r.sender.Push(context.Background(), now)
	if c, _ := r.sender.Status(); c.Sent != 2 {
		t.Fatalf("the cursor did not go back to what the receiver holds: %+v", c)
	}
	if n, err := r.sender.Push(context.Background(), now); err != nil || n != 3 || r.recv.Holds() != 5 {
		t.Fatalf("sent again: %d %v, holds %d", n, err, r.recv.Holds())
	}
}

// A batch changed on the way, signed by a key the receiver does not know,
// or whose leaves do not rebuild its head, is refused, and the cursor stays.
func TestAChangedOrStrangeBatchIsRefused(t *testing.T) {
	r := newRig(t)
	r.write(t, 2)
	r.tamper = func(b []byte) []byte { return bytes.Replace(b, []byte(`"from":1`), []byte(`"from":1 `), 1) }
	if _, err := r.sender.Push(context.Background(), now); err == nil || !strings.Contains(strings.ToLower(err.Error()), "digest") {
		t.Errorf("a changed body: %v", err)
	}
	r.tamper = nil
	if c, _ := r.sender.Status(); c.Sent != 0 || c.Failures != 1 || c.Error == "" {
		t.Errorf("the cursor moved on a refusal: %+v", c)
	}

	events, _ := r.sender.Read()
	b, err := r.sender.Batch(events, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	b.Leaves[1] = b.Leaves[0]
	body, _ := json.Marshal(b)
	req := httptest.NewRequest(http.MethodPost, r.srv.URL+"/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	httpsig.SetContentDigest(req, body)
	pub := r.sender.Key.Public().(ed25519.PublicKey)
	if err := httpsig.Sign(req, KeyID(pub), httpsig.Ed25519, r.sender.Key, Covered, now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.recv.Accept(req, body, now); err == nil || !strings.Contains(err.Error(), "rebuild") {
		t.Errorf("a dropped record: %v", err)
	}

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	r.sender.Key = other
	if _, err := r.sender.Push(context.Background(), now); err == nil {
		t.Error("a batch signed by an unknown key was taken")
	}
	if r.recv.Holds() != 0 {
		t.Errorf("the receiver took something: %d", r.recv.Holds())
	}
}

// sign signs a batch body as the sender would, over the components given.
func sign(t *testing.T, r *rig, b *Batch, components []string) (*http.Request, []byte) {
	t.Helper()
	body, _ := json.Marshal(b)
	req := httptest.NewRequest(http.MethodPost, r.srv.URL+"/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	httpsig.SetContentDigest(req, body)
	if components != nil {
		pub := r.sender.Key.Public().(ed25519.PublicKey)
		if err := httpsig.Sign(req, KeyID(pub), httpsig.Ed25519, r.sender.Key, components, now); err != nil {
			t.Fatal(err)
		}
	}
	return req, body
}

// An unsigned batch, one signed over too little, one whose head another key
// signed, and one whose head covers a different length are each refused.
func TestABatchProvesItselfOrIsRefused(t *testing.T) {
	r := newRig(t)
	r.write(t, 2)
	events, _ := r.sender.Read()
	b, err := r.sender.Batch(events, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if req, body := sign(t, r, b, nil); true {
		if _, err := r.recv.Accept(req, body, now); err == nil || !strings.Contains(err.Error(), "not signed") {
			t.Errorf("unsigned: %v", err)
		}
	}
	req, body := sign(t, r, b, []string{"@method", "content-type", "content-digest"})
	if _, err := r.recv.Accept(req, body, now); err == nil || !strings.Contains(err.Error(), "@target-uri") {
		t.Errorf("signed over too little: %v", err)
	}

	ed, ml, _ := audit.GenerateHeadSeeds()
	stranger, _ := audit.NewHeadSigner(ed, ml)
	forged := *b
	if forged.Head, err = stranger.Sign(b.Head.Head); err != nil {
		t.Fatal(err)
	}
	req, body = sign(t, r, &forged, Covered)
	if _, err := r.recv.Accept(req, body, now); err == nil || !strings.Contains(err.Error(), "tree head does not verify") {
		t.Errorf("a head another key signed: %v", err)
	}

	short, _ := audit.TreeHead(events[:1], now)
	shortHead, _ := r.sender.Heads.Sign(short)
	wrong := *b
	wrong.Head = shortHead
	req, body = sign(t, r, &wrong, Covered)
	if _, err := r.recv.Accept(req, body, now); err == nil || !strings.Contains(err.Error(), "covers 1 records") {
		t.Errorf("a head over a different length: %v", err)
	}
	if r.recv.Holds() != 0 {
		t.Errorf("something was taken: %d", r.recv.Holds())
	}
}
