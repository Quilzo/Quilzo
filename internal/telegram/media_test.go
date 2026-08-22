package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLibrary records what the bot tried to store.
type fakeLibrary struct {
	mu     sync.Mutex
	saved  []StoredFile
	bodies map[string][]byte
	err    error
	kind   string
}

func (f *fakeLibrary) Save(owner, name string, body []byte, alt string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", "", f.err
	}
	kind := f.kind
	if kind == "" {
		kind = "image"
	}
	id := fmt.Sprintf("%016x%048x", len(f.saved)+1, 0)
	if f.bodies == nil {
		f.bodies = map[string][]byte{}
	}
	f.bodies[id] = body
	f.saved = append(f.saved, StoredFile{
		ID: id, Kind: kind, Name: name, Alt: alt, Width: 800, Height: 600,
	})
	return id, kind, nil
}

func (f *fakeLibrary) Describe(id, alt string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.saved {
		if f.saved[i].ID == id {
			f.saved[i].Alt = alt
			return nil
		}
	}
	return fmt.Errorf("no such file")
}

func (f *fakeLibrary) Recent(owner string, limit int) []StoredFile {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]StoredFile, len(f.saved))
	copy(out, f.saved)
	return out
}

func (f *fakeLibrary) files() []StoredFile {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]StoredFile, len(f.saved))
	copy(out, f.saved)
	return out
}

// fileAPI answers getFile and then serves the bytes, the way Telegram does.
func fileAPI(t *testing.T, api *fakeAPI, payload []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/file/bot") {
			_, _ = w.Write(payload)
			return
		}
		method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)

		api.mu.Lock()
		api.calls = append(api.calls, method)
		api.bodies = append(api.bodies, body)
		api.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if method == "getFile" {
			_, _ = io.WriteString(w,
				`{"ok":true,"result":{"file_path":"photos/file_1.jpg","file_size":9}}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true,"result":{}}`)
	}))
}

func mediaRouter(t *testing.T, api *fakeAPI, lib MediaStore, payload []byte) (*Router, *httptest.Server) {
	t.Helper()
	srv := fileAPI(t, api, payload)
	return &Router{
		Bot:      &Bot{Token: botToken, BaseURL: srv.URL},
		AppURL:   "https://pages.example.com/",
		BotToken: botToken,
		Media:    lib,
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
	}, srv
}

func photoUpdate(caption string) Update {
	return Update{
		ID: 1, From: User{ID: 42, FirstName: "Ada"}, Chat: 42,
		Text: caption, HasAttachment: true,
		Attachment: Attachment{
			FileID: "AgACAgIAAxk", Name: "photo.jpg",
			Caption: caption, Kind: "photo", Size: 9,
		},
	}
}

// The flow the whole feature exists for: send a photograph, it lands in the
// library with its caption as the description.
func TestAPhotographWithACaptionIsStoredAndDescribed(t *testing.T) {
	api := &fakeAPI{}
	lib := &fakeLibrary{}
	r, srv := mediaRouter(t, api, lib, []byte("JPEGBYTES"))
	defer srv.Close()

	if err := r.Handle(context.Background(),
		photoUpdate("The press, mid-run")); err != nil {
		t.Fatal(err)
	}

	files := lib.files()
	if len(files) != 1 {
		t.Fatalf("expected one file, got %d", len(files))
	}
	if files[0].Alt != "The press, mid-run" {
		t.Errorf("the caption did not become the description: %q", files[0].Alt)
	}
	if string(lib.bodies[files[0].ID]) != "JPEGBYTES" {
		t.Errorf("the wrong bytes were stored: %q", lib.bodies[files[0].ID])
	}
	if files[0].NeedsDescription() {
		t.Error("a described image still reports as needing one")
	}
}

// Without a caption the bot has to ask, because an image nobody has described
// does not publish — and this surface must not be the hole in that.
func TestAPhotographWithoutACaptionIsAskedAbout(t *testing.T) {
	api := &fakeAPI{}
	lib := &fakeLibrary{}
	r, srv := mediaRouter(t, api, lib, []byte("JPEGBYTES"))
	defer srv.Close()

	if err := r.Handle(context.Background(), photoUpdate("")); err != nil {
		t.Fatal(err)
	}
	sent := api.sent()
	if len(sent) == 0 {
		t.Fatal("nothing was said back")
	}
	text, _ := sent[len(sent)-1]["text"].(string)
	if !strings.Contains(text, "needs a description") {
		t.Errorf("the bot did not ask for a description:\n%s", text)
	}
	// And the id has to be in that message, because a reply to it is the
	// entire mechanism for getting the description back.
	if !reFileTag.MatchString(text) {
		t.Errorf("the message carries no file id, so a reply cannot find it:\n%s", text)
	}
}

// A reply to the bot's own message attaches the description. This is the whole
// of the state mechanism: it lives in the chat, not in this process.
func TestAReplyToTheBotDescribesTheFile(t *testing.T) {
	api := &fakeAPI{}
	lib := &fakeLibrary{}
	r, srv := mediaRouter(t, api, lib, []byte("JPEGBYTES"))
	defer srv.Close()

	if err := r.Handle(context.Background(), photoUpdate("")); err != nil {
		t.Fatal(err)
	}
	sent := api.sent()
	ask, _ := sent[len(sent)-1]["text"].(string)

	err := r.Handle(context.Background(), Update{
		ID: 2, From: User{ID: 42}, Chat: 42,
		Text:    "A cast-iron press with a sheet of paper on the bed",
		ReplyTo: ask,
	})
	if err != nil {
		t.Fatal(err)
	}
	files := lib.files()
	if files[0].Alt != "A cast-iron press with a sheet of paper on the bed" {
		t.Errorf("the reply did not describe the file: %q", files[0].Alt)
	}
}

// A reply quoting somebody else's id must not describe their file. The id is
// resolved against what this person has, not against the library.
func TestAReplyCannotDescribeSomebodyElsesFile(t *testing.T) {
	api := &fakeAPI{}
	lib := &fakeLibrary{}
	r, srv := mediaRouter(t, api, lib, []byte("JPEGBYTES"))
	defer srv.Close()

	// A file that is not in this person's library at all.
	err := r.Handle(context.Background(), Update{
		ID: 1, From: User{ID: 42}, Chat: 42,
		Text:    "mine now",
		ReplyTo: "Saved your photo. #00000000deadbeef",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(lib.files()) != 0 {
		t.Fatal("a file appeared from nowhere")
	}
	sent := api.sent()
	text, _ := sent[len(sent)-1]["text"].(string)
	if !strings.Contains(text, "not in your library") {
		t.Errorf("the refusal did not say why:\n%s", text)
	}
}

// Only a reply to the bot carries state the bot put there. A reply to another
// person quoting an id would otherwise be a way to describe their file.
func TestOnlyARepliedBotMessageCarriesState(t *testing.T) {
	raw := rawUpdate{UpdateID: 1, Message: json.RawMessage(`{
		"from":{"id":1,"is_bot":false,"first_name":"A"},
		"chat":{"id":1},"text":"a description",
		"reply_to_message":{"text":"Saved your photo. #0000000000000001",
		                    "from":{"is_bot":false}}}`)}
	if u := updateFrom(raw); u.ReplyTo != "" {
		t.Errorf("a reply to a person was treated as state: %q", u.ReplyTo)
	}

	raw.Message = json.RawMessage(`{
		"from":{"id":1,"is_bot":false,"first_name":"A"},
		"chat":{"id":1},"text":"a description",
		"reply_to_message":{"text":"Saved your photo. #0000000000000001",
		                    "from":{"is_bot":true}}}`)
	if u := updateFrom(raw); !strings.Contains(u.ReplyTo, "#0000000000000001") {
		t.Errorf("a reply to the bot lost its state: %q", u.ReplyTo)
	}
}

// Telegram sends a photograph at several sizes and the smallest is a thumbnail.
// Taking the wrong one puts a 100px image on a page.
func TestTheLargestPhotoSizeIsTaken(t *testing.T) {
	raw := json.RawMessage(`{"photo":[
		{"file_id":"small","width":100,"height":100,"file_size":900},
		{"file_id":"medium","width":320,"height":320,"file_size":9000},
		{"file_id":"large","width":1280,"height":1280,"file_size":90000}]}`)
	a, ok := attachmentOf(raw)
	if !ok {
		t.Fatal("a photo message was not recognised")
	}
	if a.FileID != "large" {
		t.Errorf("took %q; Telegram orders these smallest first, so the last "+
			"is the one worth putting on a page", a.FileID)
	}
}

// Every kind Telegram can send is recognised, with a filename hint that points
// the decoder at the right format first.
func TestEveryMediaKindIsRecognised(t *testing.T) {
	cases := map[string]struct{ json, name, kind string }{
		"voice":     {`{"voice":{"file_id":"v","mime_type":"audio/ogg"}}`, "voice.ogg", "voice note"},
		"audio":     {`{"audio":{"file_id":"a","file_name":"song.mp3"}}`, "song.mp3", "audio"},
		"video":     {`{"video":{"file_id":"m","file_name":"clip.mp4"}}`, "clip.mp4", "video"},
		"animation": {`{"animation":{"file_id":"g","file_name":"loop.mp4"}}`, "loop.mp4", "animation"},
		"document":  {`{"document":{"file_id":"d","file_name":"page.png"}}`, "page.png", "file"},
	}
	for name, c := range cases {
		a, ok := attachmentOf(json.RawMessage(c.json))
		if !ok {
			t.Errorf("%s was not recognised", name)
			continue
		}
		if a.Name != c.name {
			t.Errorf("%s got the filename hint %q, want %q", name, a.Name, c.name)
		}
		if a.Kind != c.kind {
			t.Errorf("%s was called %q, want %q", name, a.Kind, c.kind)
		}
	}
	if _, ok := attachmentOf(json.RawMessage(`{"text":"hello"}`)); ok {
		t.Error("a plain message was read as an attachment")
	}
}

// A file too large to fetch is refused before the transfer, with the reason.
func TestAFileOverTheLimitIsRefusedWithoutDownloading(t *testing.T) {
	api := &fakeAPI{}
	lib := &fakeLibrary{}
	r, srv := mediaRouter(t, api, lib, []byte("x"))
	defer srv.Close()

	u := photoUpdate("")
	u.Attachment.Size = MaxDownload + 1
	if err := r.Handle(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if len(lib.files()) != 0 {
		t.Error("an oversized file was stored")
	}
	for _, call := range api.calls {
		if call == "getFile" {
			t.Error("the download was attempted despite the size being known")
		}
	}
}

// The library's own refusal reaches the person, in its own words. It refuses by
// decoding rather than by extension, so those words are specific and useful.
func TestALibraryRefusalIsPassedOn(t *testing.T) {
	api := &fakeAPI{}
	lib := &fakeLibrary{err: fmt.Errorf(
		"SVG is XML that browsers execute. Export it as PNG or WebP")}
	r, srv := mediaRouter(t, api, lib, []byte("<svg/>"))
	defer srv.Close()

	if err := r.Handle(context.Background(), photoUpdate("")); err != nil {
		t.Fatal(err)
	}
	sent := api.sent()
	text, _ := sent[len(sent)-1]["text"].(string)
	if !strings.Contains(text, "Export it as PNG") {
		t.Errorf("the refusal was summarised rather than passed on:\n%s", text)
	}
}

// A path Telegram returns is joined onto a URL, so it is checked rather than
// trusted — a path escaping upward would be a request to somewhere else.
func TestATraversingFilePathIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w,
			`{"ok":true,"result":{"file_path":"../../etc/passwd","file_size":9}}`)
	}))
	defer srv.Close()

	b := &Bot{Token: botToken, BaseURL: srv.URL}
	if _, _, err := b.Download(context.Background(), "any"); err == nil {
		t.Error("a traversing file path was followed")
	}
}

// A body larger than it claimed is caught by the read rather than by trusting
// the header.
func TestABodyLargerThanClaimedIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/file/bot") {
			// Far more than it said, and more than the limit.
			for i := 0; i < (MaxDownload/1024)+16; i++ {
				_, _ = w.Write(make([]byte, 1024))
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w,
			`{"ok":true,"result":{"file_path":"photos/f.jpg","file_size":9}}`)
	}))
	defer srv.Close()

	b := &Bot{Token: botToken, BaseURL: srv.URL}
	if _, _, err := b.Download(context.Background(), "any"); err == nil {
		t.Error("a body larger than the limit was accepted")
	}
}
