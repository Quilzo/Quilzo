// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assist

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

var mp4 = append([]byte("\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom"), make([]byte, 64)...)

type seen struct {
	mu    sync.Mutex
	paths []string
	keys  []string
}

func (s *seen) add(r *http.Request, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths = append(s.paths, r.Method+" "+r.URL.Path)
	s.keys = append(s.keys, r.Header.Get(key))
}

func fastPolls(t *testing.T) {
	was := filmPoll
	filmPoll = time.Millisecond
	t.Cleanup(func() { filmPoll = was })
}

// Veo: started, asked after until done, fetched with the key from the
// provider's own host; a redirect to another host goes there without it.
func TestAVideoIsMadeByVeo(t *testing.T) {
	fastPolls(t)
	var elsewhere seen
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.add(r, "x-goog-api-key")
		_, _ = w.Write(mp4)
	}))
	defer other.Close()
	var here seen
	asked := 0
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		here.add(r, "x-goog-api-key")
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":predictLongRunning"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["parameters"].(map[string]any)["aspectRatio"] != "9:16" {
				http.Error(w, "shape", 400)
				return
			}
			_, _ = w.Write([]byte(`{"name":"models/veo-x/operations/op1"}`))
		case r.URL.Path == "/models/veo-x/operations/op1":
			asked++
			if asked < 3 {
				_, _ = w.Write([]byte(`{"done":false}`))
				return
			}
			_, _ = w.Write([]byte(`{"done":true,"response":{"generateVideoResponse":{"generatedSamples":[{"video":{"uri":"` +
				srv.URL + `/files/v1:download"}}]}}}`))
		case r.URL.Path == "/files/v1:download":
			http.Redirect(w, r, other.URL+"/blob", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	h := &HTTPModel{BaseURL: srv.URL, APIKey: "veo-key", Model: "veo-x", Client: srv.Client(), Auth: "header:x-goog-api-key", Wire: WireVeo}
	other.Client() // trust both: one transport trusting both servers
	h.Client.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(other.Certificate())
	video, _, err := h.Film(context.Background(), "a bakery at dawn", "9:16")
	if err != nil {
		t.Fatal(err)
	}
	if string(video[4:8]) != "ftyp" || asked != 3 {
		t.Fatalf("%d asks", asked)
	}
	for i, k := range here.keys {
		if k != "veo-key" {
			t.Errorf("%s went without the key", here.paths[i])
		}
	}
	if len(elsewhere.keys) != 1 || elsewhere.keys[0] != "" {
		t.Fatalf("the key followed a redirect to another host: %v", elsewhere.keys)
	}
}

// fal's queue: taken, asked after, answered with a video on its storage,
// which is fetched without the key; addresses off its host are refused.
func TestAVideoIsMadeOnFalsQueue(t *testing.T) {
	fastPolls(t)
	var cdn seen
	store := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cdn.add(r, "Authorization")
		_, _ = w.Write(mp4)
	}))
	defer store.Close()
	statusURL := ""
	polls := 0
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Key fal-key" {
			http.Error(w, "key", 401)
			return
		}
		switch {
		case r.Method == "POST" && r.URL.Path == "/fal-ai/some-video":
			_, _ = w.Write([]byte(`{"request_id":"r1","status_url":"` + statusURL + `","response_url":"` + srv.URL + `/fal-ai/some-video/requests/r1"}`))
		case r.URL.Path == "/fal-ai/some-video/requests/r1/status":
			polls++
			if polls < 2 {
				_, _ = w.Write([]byte(`{"status":"IN_QUEUE"}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"COMPLETED"}`))
		case r.URL.Path == "/fal-ai/some-video/requests/r1":
			_, _ = w.Write([]byte(`{"video":{"url":"` + store.URL + `/files/out.mp4"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	statusURL = srv.URL + "/fal-ai/some-video/requests/r1/status"
	h := &HTTPModel{BaseURL: srv.URL, APIKey: "fal-key", Model: "fal-ai/some-video", Client: srv.Client(), Auth: "key", Wire: WireFalQueue}
	h.Client.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(store.Certificate())
	video, _, err := h.Film(context.Background(), "a bakery at dawn", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(video[4:8]) != "ftyp" || len(cdn.keys) != 1 || cdn.keys[0] != "" {
		t.Fatalf("the key went to the storage: %v", cdn.keys)
	}
	statusURL = "https://elsewhere.example/status"
	if _, _, err := h.Film(context.Background(), "again", ""); err == nil || !strings.Contains(err.Error(), "own host") {
		t.Fatalf("a status address off the queue's host: %v", err)
	}
	if _, _, err := h.Film(context.Background(), "x", "4:3"); err == nil {
		t.Error("a shape that is not one")
	}
	words := &HTTPModel{BaseURL: srv.URL, Model: "m", Client: srv.Client()}
	if _, _, err := words.Film(context.Background(), "x", ""); err == nil {
		t.Error("a chat model made a video")
	}
}
