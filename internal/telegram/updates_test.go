package telegram

import (
	"context"
	"encoding/json"
	"github.com/quilzo/quilzo/internal/chat"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPI stands in for api.telegram.org, recording what was sent to it.
type fakeAPI struct {
	mu      sync.Mutex
	calls   []string
	bodies  []map[string]any
	updates string
}

func (f *fakeAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)

		f.mu.Lock()
		f.calls = append(f.calls, method)
		f.bodies = append(f.bodies, body)
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if method == "getUpdates" && f.updates != "" {
			updates := f.updates
			f.updates = ""
			_, _ = io.WriteString(w, `{"ok":true,"result":`+updates+`}`)
			return
		}
		if method == "getUpdates" {
			_, _ = io.WriteString(w, `{"ok":true,"result":[]}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true,"result":{}}`)
	}))
}

func (f *fakeAPI) sent() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]map[string]any, len(f.bodies))
	copy(out, f.bodies)
	return out
}

func router(t *testing.T, api *fakeAPI, appURL string) (*Router, *httptest.Server) {
	t.Helper()
	srv := api.server(t)
	return &Router{
		Bot:      &Bot{Token: botToken, BaseURL: srv.URL},
		AppURL:   appURL,
		BotToken: botToken,
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
	}, srv
}

// The requirement the Telegram Apps Center checks first, and the one that
// decides whether anybody can use this at all: /start has to answer, in
// English, with a way in.
func TestStartAnswersInEnglishWithAWorkingLink(t *testing.T) {
	api := &fakeAPI{}
	r, srv := router(t, api, "https://pages.example.com/")
	defer srv.Close()

	err := r.Handle(context.Background(), Update{
		ID: 1, From: User{ID: 42, FirstName: "Ada", Username: "ada"},
		Chat: 42, Text: "/start", IsCommand: true,
	})
	if err != nil {
		t.Fatalf("/start failed: %v", err)
	}

	sent := api.sent()
	if len(sent) != 1 {
		t.Fatalf("expected one message, got %d", len(sent))
	}
	text, _ := sent[0]["text"].(string)
	if !strings.Contains(text, "Ada") {
		t.Errorf("the greeting does not use the name Telegram sent: %q", text)
	}
	// Not a language check — a check that it is not empty and reads as English
	// prose rather than a key nobody translated.
	if !strings.Contains(text, "publishes a web page") {
		t.Errorf("the greeting does not say what this does:\n%s", text)
	}

	// The button, and the credential in it.
	markup, ok := sent[0]["reply_markup"].(map[string]any)
	if !ok {
		t.Fatal("no button was attached, so there is no way in")
	}
	rows := markup["inline_keyboard"].([]any)
	button := rows[0].([]any)[0].(map[string]any)
	webApp, ok := button["web_app"].(map[string]any)
	if !ok {
		t.Fatal("the button is not a Mini App button")
	}
	link, _ := webApp["url"].(string)
	if !strings.HasPrefix(link, "https://pages.example.com/?") {
		t.Fatalf("the button points at %q", link)
	}

	// And the link it minted actually works, which is the part that would
	// otherwise be assumed.
	query := link[strings.Index(link, "?")+1:]
	app := &App{BotToken: botToken, Spender: chat.NewMemory(),
		Now: func() time.Time { return time.Unix(1700000000, 0) }}
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/?"+query, nil))
	if w.Code != http.StatusOK {
		t.Errorf("the link the bot sent does not open: %d\n%s", w.Code, w.Body.String())
	}
}

// Every other message gets an answer too. A bot that silently ignores things
// reads as broken, and "it did nothing" is the most common reason somebody
// stops using one.
func TestEveryMessageGetsAnAnswer(t *testing.T) {
	for _, text := range []string{"/help", "/privacy", "/terms", "/nonsense", "hello"} {
		api := &fakeAPI{}
		r, srv := router(t, api, "https://pages.example.com/")

		if err := r.Handle(context.Background(), Update{
			ID: 1, From: User{ID: 1}, Chat: 1,
			Text: text, IsCommand: strings.HasPrefix(text, "/"),
		}); err != nil {
			t.Errorf("%q failed: %v", text, err)
		}
		sent := api.sent()
		srv.Close()

		if len(sent) == 0 {
			t.Errorf("%q got no answer at all", text)
			continue
		}
		if answer, _ := sent[0]["text"].(string); strings.TrimSpace(answer) == "" {
			t.Errorf("%q got an empty answer", text)
		}
	}
}

// A command in a group arrives as /start@thebot. Not handling that means the
// bot is silent in exactly the place it was added deliberately.
func TestACommandAddressedToTheBotIsUnderstood(t *testing.T) {
	api := &fakeAPI{}
	r, srv := router(t, api, "https://pages.example.com/")
	defer srv.Close()

	if err := r.Handle(context.Background(), Update{
		ID: 1, From: User{ID: 1}, Chat: 1,
		Text: "/start@quilzo_bot", IsCommand: true,
	}); err != nil {
		t.Fatal(err)
	}
	sent := api.sent()
	if len(sent) == 0 {
		t.Fatal("no answer")
	}
	if _, hasButton := sent[0]["reply_markup"]; !hasButton {
		t.Error("/start@thebot did not get the button that /start gets")
	}
}

// Polling acknowledges by advancing the offset, and does so after handling.
// The other way round loses an update when handling fails.
func TestPollingAdvancesTheOffsetAfterHandling(t *testing.T) {
	api := &fakeAPI{updates: `[
		{"update_id":10,"message":{"from":{"id":1,"is_bot":false,"first_name":"A"},
		 "chat":{"id":1},"text":"/help"}},
		{"update_id":11,"message":{"from":{"id":2,"is_bot":true,"first_name":"B"},
		 "chat":{"id":2},"text":"/start"}}
	]`}
	r, srv := router(t, api, "https://pages.example.com/")
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = r.Poll(ctx, nil); close(done) }()

	// Wait for the second getUpdates, which is the one carrying the offset.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		api.mu.Lock()
		calls := len(api.calls)
		api.mu.Unlock()
		if calls >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	var offsets []float64
	for i, body := range api.sent() {
		api.mu.Lock()
		method := ""
		if i < len(api.calls) {
			method = api.calls[i]
		}
		api.mu.Unlock()
		if method != "getUpdates" {
			continue
		}
		if o, ok := body["offset"].(float64); ok {
			offsets = append(offsets, o)
		}
	}
	if len(offsets) == 0 {
		t.Fatal("no offset was ever sent, so every update would be redelivered forever")
	}
	if offsets[0] != 12 {
		t.Errorf("offset advanced to %v; it must be one past the last update "+
			"seen, including the one from a bot that was skipped", offsets[0])
	}
}

// A message from another bot is skipped rather than answered, or two of these
// talking to each other is a loop.
func TestAMessageFromABotIsNotAnswered(t *testing.T) {
	api := &fakeAPI{updates: `[{"update_id":1,"message":{
		"from":{"id":9,"is_bot":true,"first_name":"Other"},
		"chat":{"id":9},"text":"/start"}}]`}
	r, srv := router(t, api, "https://pages.example.com/")
	defer srv.Close()

	updates, err := r.Bot.Updates(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 1 {
		t.Fatalf("expected the update to still advance the offset, got %d", len(updates))
	}
	if updates[0].From.ID != 0 {
		t.Error("a message from a bot was passed through as something to answer")
	}
}

// The webhook acts on whatever is posted to it, so the secret is the whole
// access control. A wrong one is a 404 rather than a 403: distinguishing them
// tells whoever is probing which half they got right.
func TestTheWebhookRefusesWithoutTheSecret(t *testing.T) {
	api := &fakeAPI{}
	r, srv := router(t, api, "https://pages.example.com/")
	defer srv.Close()

	body := `{"update_id":1,"message":{"from":{"id":1,"is_bot":false,
		"first_name":"A"},"chat":{"id":1},"text":"/start"}}`
	handler := r.WebhookHandler("s3cret")

	for _, presented := range []string{"", "wrong", "S3CRET"} {
		req := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(body))
		if presented != "" {
			req.Header.Set("X-Telegram-Bot-Api-Secret-Token", presented)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("a secret of %q gave %d, want 404", presented, w.Code)
		}
	}
	if len(api.sent()) != 0 {
		t.Error("an unauthenticated webhook post caused a message to be sent")
	}

	req := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(body))
	req.Header.Set("X-Telegram-Bot-Api-Secret-Token", "s3cret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("the genuine secret gave %d", w.Code)
	}
	if len(api.sent()) == 0 {
		t.Error("an authenticated webhook post produced no answer")
	}
}

// A webhook must be https and must have a secret, refused at the point of
// setting it rather than discovered when updates arrive in clear.
func TestSettingAWebhookRefusesPlainHTTPAndAnEmptySecret(t *testing.T) {
	api := &fakeAPI{}
	r, srv := router(t, api, "https://pages.example.com/")
	defer srv.Close()

	if err := r.Bot.SetWebhook(context.Background(),
		"http://example.com/hook", "s"); err == nil {
		t.Error("a plain http webhook was accepted")
	}
	if err := r.Bot.SetWebhook(context.Background(),
		"https://example.com/hook", "  "); err == nil {
		t.Error("a webhook with no secret was accepted")
	}
}

// The pages a listing requires have to exist and say something.
func TestTermsAndPrivacyAreServed(t *testing.T) {
	a := &App{BotToken: botToken, Spender: chat.NewMemory()}
	for _, path := range []string{"/terms", "/privacy"} {
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Errorf("GET %s gave %d", path, w.Code)
		}
		// A page the Apps Center will read. Long enough to say something.
		if w.Body.Len() < 800 {
			t.Errorf("GET %s returned %d bytes; that is not a policy",
				path, w.Body.Len())
		}
	}
	// A health endpoint is a public URL, so every fact on it is free to
	// whoever is probing — which is why it is deliberately tiny and says
	// nothing about the version, the store or whether a token is present.
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusOK {
		t.Errorf("GET /health gave %d", w.Code)
	}
	if w.Body.Len() > 64 {
		t.Errorf("the health endpoint returned %d bytes; it should say almost "+
			"nothing: %s", w.Body.Len(), w.Body.String())
	}
	for _, leak := range []string{botToken, "token", "version", "store"} {
		if strings.Contains(strings.ToLower(w.Body.String()), strings.ToLower(leak)) {
			t.Errorf("the health endpoint mentions %q: %s", leak, w.Body.String())
		}
	}
}
