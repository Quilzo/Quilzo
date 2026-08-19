package api

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/replica"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The two endpoints a replica needs, and what they must not do.

func TestAReplicaReadsARefAndAnObject(t *testing.T) {
	s, readTok, _ := setup(t)
	head := s.Store.GetRef(site.RefLive)

	w := req(t, s, "GET", "/api/v1/replica/ref/live", readTok, nil, nil)
	if w.Code != 200 {
		t.Fatalf("reading a ref gave %d: %s", w.Code, w.Body)
	}
	var ref struct{ Commit string }
	if err := json.Unmarshal(w.Body.Bytes(), &ref); err != nil {
		t.Fatal(err)
	}
	if ref.Commit != head {
		t.Errorf("the ref answered %s, the store is at %s", ref.Commit, head)
	}

	w = req(t, s, "GET", "/api/v1/replica/object/"+head, readTok, nil, nil)
	if w.Code != 200 {
		t.Fatalf("reading an object gave %d: %s", w.Code, w.Body)
	}
	var obj struct{ Kind, Payload string }
	if err := json.Unmarshal(w.Body.Bytes(), &obj); err != nil {
		t.Fatal(err)
	}
	if obj.Kind != store.KindCommit {
		t.Errorf("a commit was served as a %q", obj.Kind)
	}
	payload, err := base64.StdEncoding.DecodeString(obj.Payload)
	if err != nil {
		t.Fatal(err)
	}
	// The property the whole protocol rests on: what came off the wire hashes
	// to what was asked for, so the receiving store will accept it.
	if got := store.ObjectID(obj.Kind, payload); got != head {
		t.Errorf("what was served hashes to %s, not to %s. A replica would "+
			"refuse it, correctly, and never be able to sync", got, head)
	}
	// Immutable, because the name is the hash. This is what makes an edge
	// replica cost nothing to keep warm.
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("an object is served as %q; it can never change", cc)
	}
}

// Nothing here accepts an object.
//
// A push endpoint is an authenticated write endpoint whose timing somebody else
// chooses. A store that wants content pulls it.
func TestAReplicaCannotPush(t *testing.T) {
	s, _, writeTok := setup(t)
	head := s.Store.GetRef(site.RefLive)

	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		w := req(t, s, method, "/api/v1/replica/object/"+head, writeTok, nil, nil)
		if w.Code == 200 || w.Code == 201 {
			t.Errorf("%s on an object was accepted (%d)", method, w.Code)
		}
		w = req(t, s, method, "/api/v1/replica/ref/live", writeTok, nil, nil)
		if w.Code == 200 || w.Code == 201 {
			t.Errorf("%s on a ref was accepted (%d)", method, w.Code)
		}
	}
}

// It takes a credential.
func TestReplicationIsNotOpenToStrangers(t *testing.T) {
	s, _, _ := setup(t)
	head := s.Store.GetRef(site.RefLive)

	for _, path := range []string{
		"/api/v1/replica/ref/live", "/api/v1/replica/object/" + head,
	} {
		if w := req(t, s, "GET", path, "", nil, nil); w.Code == 200 {
			t.Errorf("%s answered an anonymous request", path)
		}
	}
}

// A store does not serve on another peer's head.
//
// Replication is between two stores that were paired. Passing a third store's
// head through this one makes it look like content this store stands behind,
// which the operator who paired them never agreed to.
func TestAPeersHeadIsNotServedOn(t *testing.T) {
	s, readTok, _ := setup(t)
	head := s.Store.GetRef(site.RefLive)
	if err := s.Store.SetRef(replica.QuarantineRef("elsewhere"), head); err != nil {
		t.Fatal(err)
	}

	w := req(t, s, "GET",
		"/api/v1/replica/ref/"+replica.QuarantineRef("elsewhere"), readTok, nil, nil)
	if w.Code == 200 {
		t.Error("a third store's head was served on, so a chain of peers " +
			"launders content through stores that never agreed to it")
	}
}

// An absent object and a malformed one get the same answer.
func TestAnAbsentObjectIsNotAnOracle(t *testing.T) {
	s, readTok, _ := setup(t)
	absent := store.ObjectID(store.KindBlob, []byte("nothing is stored here"))

	w := req(t, s, "GET", "/api/v1/replica/object/"+absent, readTok, nil, nil)
	if w.Code != 404 {
		t.Errorf("an absent object gave %d, want 404", w.Code)
	}
	w2 := req(t, s, "GET", "/api/v1/replica/object/not-an-id", readTok, nil, nil)
	if w2.Code != 404 {
		t.Errorf("a malformed id gave %d, want the same 404 an absent object "+
			"gets — two answers make this an oracle for what is stored",
			w2.Code)
	}
}
