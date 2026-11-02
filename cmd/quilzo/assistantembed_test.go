// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
)

// subjectOf is a stand-in embedding model: which of the shop's subjects a
// text is about, or none.
func subjectOf(s string) []float64 {
	s = strings.ToLower(s)
	switch {
	case strings.Contains(s, "return") || strings.Contains(s, "refund"):
		return []float64{1, 0, 0}
	case strings.Contains(s, "deliver") || strings.Contains(s, "ship"):
		return []float64{0, 1, 0}
	}
	return []float64{0, 0, 1}
}

// embeddingServer serves /embeddings with the stand-in model, counting the
// texts it is sent.
func embeddingServer(t *testing.T, texts *int64, seen *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		atomic.AddInt64(texts, int64(len(in.Input)))
		*seen = append(*seen, in.Input...)
		type item struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		}
		var out struct {
			Data []item `json:"data"`
		}
		for i, s := range in.Input {
			out.Data = append(out.Data, item{i, subjectOf(s)})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func setEmbeddings(t *testing.T, root, route string) {
	t.Helper()
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("chatbot.embeddings", route, "to find passages by meaning", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
}

// A chatbot that answers with a model finds a passage asked about in
// other words once the site is embedded: its passages once, kept by their
// hash and embedded no second time; the question as it is asked. A chatbot
// that only quotes its pages, and one kept to one route, send nothing.
func TestAChatbotFindsAPassageByWhatItMeans(t *testing.T) {
	root := publishedShop(t)
	var chatCalls, embedded int64
	var sent []string
	chat := modelServer(t, false, &chatCalls)
	vectors := embeddingServer(t, &embedded, &sent)
	for _, args := range [][]string{
		{"route", "add", "words", "--url", chat.URL + "/v1", "--model", "small"},
		{"route", "add", "vectors", "--url", vectors.URL + "/v1", "--model", "embed-small", "--embeds"},
	} {
		if err := cmdGateway(root, args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{
		{"add", "help", "--title", "Help", "--model"},
		{"add", "quotes", "--title", "Quotes"},
		{"add", "kept", "--title", "Kept", "--model", "--route", "words", "--route-only"},
	} {
		if err := cmdAssistant(root, args); err != nil {
			t.Fatal(err)
		}
	}
	ask := func(name, q string) assistant.Answer {
		t.Helper()
		a, _ := loadAssistant(root, name)
		idx, err := assistantIndex(root, a)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := assistantModelAt(root, a)
		ans, err := assistant.Respond(context.Background(), a, idx, m, q)
		if err != nil {
			t.Fatal(err)
		}
		return ans
	}
	const q = "may I have a refund on ink I have used"
	// Before: words alone, and nothing about refunds on the site.
	if ans := ask("help", q); ans.Mode == "model" {
		t.Fatalf("answered by words alone: %+v", ans)
	}

	setEmbeddings(t, root, "vectors")
	if err := cmdAssistant(root, []string{"embed"}); err != nil {
		t.Fatal(err)
	}
	first := atomic.LoadInt64(&embedded)
	if first == 0 {
		t.Fatal("nothing was embedded")
	}
	if err := cmdAssistant(root, []string{"embed", "help"}); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&embedded) != first {
		t.Error("a passage was embedded twice")
	}
	if err := cmdAssistant(root, []string{"embed", "quotes"}); err == nil {
		t.Error("a chatbot that only quotes its pages was embedded for")
	}

	ans := ask("help", q)
	if ans.Mode != "model" || len(ans.Sources) == 0 || ans.Sources[0].Page != "returns" {
		t.Fatalf("not found by meaning: mode %s, %+v, %s", ans.Mode, ans.Sources, ans.Note)
	}
	if atomic.LoadInt64(&embedded) != first+1 || sent[len(sent)-1] != q {
		t.Errorf("the question was not embedded as asked: %d %q", atomic.LoadInt64(&embedded)-first, sent[len(sent)-1])
	}
	before := atomic.LoadInt64(&embedded)
	ask("quotes", q)
	ask("kept", q)
	if atomic.LoadInt64(&embedded) != before {
		t.Error("a chatbot that quotes, or is kept to one route, sent a question to be embedded")
	}
	// The vectors are kept by hash: no page's words are in them.
	_ = filepath.WalkDir(embeddingsDir(root), func(p string, d os.DirEntry, err error) error {
		if b, _ := os.ReadFile(p); strings.Contains(string(b), "Opened ink") {
			t.Errorf("a page's words are kept at %s", p)
		}
		return nil
	})
	if b, _ := os.ReadFile(usagePath(root)); !strings.Contains(string(b), `"consumer":"embed:help"`) {
		t.Errorf("embedding was not charged: %s", b)
	}
}
