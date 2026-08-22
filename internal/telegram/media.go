package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// Sending the bot a photograph, and having it end up on a page.
//
// # Why this is the feature worth having
//
// Everybody's pictures are already in Telegram. A publishing tool that lives in
// Telegram and still makes you find a file, open an upload dialog and choose it
// has thrown away the only advantage it had. Forwarding a photograph into a chat
// is the shortest path from "I have this" to "it is on my site" that exists, and
// it is available to exactly one kind of application.
//
// Voice notes are the same argument and nobody makes it: Telegram records them
// as OGG, which is a format the media library already accepts, so a spoken note
// becomes audio on a page with no conversion anywhere.
//
// # Why the bytes are re-validated after download
//
// They come from api.telegram.org, which is a third party, over a URL this
// program constructs from a path that third party supplied. Telegram is not the
// adversary here — but "a file that arrived from somewhere" is a file, and the
// media library's whole design is that a format is proven by decoding rather
// than asserted by a name. So a download is treated exactly like an upload: same
// acceptance, same pixel bounds, same refusals.
//
// # Why alt text is asked for rather than skipped
//
// An image without a description does not publish. That is the gate, and this
// surface must not be the hole in it — so a photograph sent with a caption uses
// the caption, and one sent without gets asked. The asking is stateless: the
// bot's reply carries the file's own id, and a reply to that message is how the
// description finds its way back. No session, no pending-uploads table, nothing
// to expire.

// MaxDownload is the ceiling on a file this will fetch.
//
// The Bot API refuses to serve a file over 20 MB through getFile at all, so
// anything larger fails at Telegram's end whatever this says. The number is here
// so the failure is this program's, with a sentence explaining it, rather than a
// bare "file is too big" from somebody else's API.
const MaxDownload = 20 << 20

// Attachment is a file somebody sent the bot.
type Attachment struct {
	// FileID is Telegram's handle for it, valid for downloading.
	FileID string
	// Name is a filename hint. The bytes decide the format; this only chooses
	// which decoder is tried first.
	Name string
	// Caption is what they typed with it, used as the description.
	Caption string
	// Kind is what Telegram called it, for the message back.
	Kind string
	// Size is what Telegram says it is, before downloading. Checked early so a
	// file that cannot work is refused without spending the transfer.
	Size int64
}

// MediaStore is the library, as much of it as this surface needs.
//
// An interface so this package does not import the media packages, and so the
// whole flow is testable without a directory on disk. The host decides what
// counts as acceptable, which is where that decision already lives.
type MediaStore interface {
	// Save validates bytes and stores them, returning the id a page refers to
	// and a short human description of what it turned out to be.
	Save(owner, name string, body []byte, alt string) (id, what string, err error)
	// Describe attaches a description to a stored file. Images need one before
	// they can be published, and this is how one arrives late.
	Describe(id, alt string) error
	// Recent lists what an owner has, newest first.
	Recent(owner string, limit int) []StoredFile
}

// StoredFile is one thing in the library, in the terms a screen needs.
type StoredFile struct {
	ID   string
	Kind string
	Name string
	Alt  string
	// Width and Height are zero for anything that is not an image.
	Width  int
	Height int
}

// Short is the id as it appears in a chat message: enough to identify, short
// enough to read. The full id is what a page stores.
func (f StoredFile) Short() string {
	if len(f.ID) < 16 {
		return f.ID
	}
	return f.ID[:16]
}

// NeedsDescription reports whether this cannot be published yet.
func (f StoredFile) NeedsDescription() bool {
	return f.Kind == "image" && strings.TrimSpace(f.Alt) == ""
}

// reFileTag finds a file id in a message the bot sent earlier.
//
// This is the whole of the "which file are we describing" mechanism. The id
// travels in the bot's own message, a person replies to that message, and
// Telegram hands the replied-to text back — so the state lives in the chat
// rather than in this process. Nothing to store, nothing to expire, and it
// survives a restart because it was never in memory.
var reFileTag = regexp.MustCompile(`#([0-9a-f]{16})\b`)

// Download fetches a file by its Telegram id.
//
// Two requests, because that is the API: getFile turns an id into a path, and
// the path is fetched from a different host. Both are bounded.
func (b *Bot) Download(ctx context.Context, fileID string) (name string, body []byte, err error) {
	var meta struct {
		FilePath string `json:"file_path"`
		FileSize int64  `json:"file_size"`
	}
	if err := b.call(ctx, "getFile",
		map[string]any{"file_id": fileID}, &meta); err != nil {
		return "", nil, err
	}
	if meta.FilePath == "" {
		return "", nil, fmt.Errorf("Telegram returned no path for that file")
	}
	if meta.FileSize > MaxDownload {
		return "", nil, fmt.Errorf(
			"that file is %d MB and the Bot API will not serve anything over "+
				"%d MB", meta.FileSize>>20, MaxDownload>>20)
	}
	// The path comes from Telegram and is joined onto a URL, so it is checked
	// rather than trusted: a path escaping upward would be a request to
	// somewhere else on that host, and the fix is a pattern rather than a
	// cleaning function.
	if strings.Contains(meta.FilePath, "..") || strings.HasPrefix(meta.FilePath, "/") {
		return "", nil, fmt.Errorf("Telegram returned a path this will not follow")
	}

	endpoint := b.base() + "/file/bot" + b.Token + "/" + meta.FilePath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", nil, fmt.Errorf("that file could not be requested")
	}
	resp, err := b.client().Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("that file could not be fetched: %s",
			scrub(err.Error(), b.Token))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("Telegram answered %d for that file", resp.StatusCode)
	}

	// One byte past the limit, so a body that lies about its length is caught
	// by the read rather than by trusting the header.
	body, err = io.ReadAll(io.LimitReader(resp.Body, MaxDownload+1))
	if err != nil {
		return "", nil, fmt.Errorf("that file could not be read")
	}
	if int64(len(body)) > MaxDownload {
		return "", nil, fmt.Errorf(
			"that file is larger than the %d MB limit", MaxDownload>>20)
	}
	return lastSegment(meta.FilePath), body, nil
}

func lastSegment(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// attachmentOf reads whichever media a message carries.
//
// Ordered by how specific the type is. A voice note is also a document to some
// clients and an audio file to others, so the narrower reading wins — otherwise
// the filename hint is wrong and the format is decoded twice for nothing.
func attachmentOf(raw json.RawMessage) (Attachment, bool) {
	var m struct {
		Caption string `json:"caption"`
		Photo   []struct {
			FileID   string `json:"file_id"`
			Width    int    `json:"width"`
			Height   int    `json:"height"`
			FileSize int64  `json:"file_size"`
		} `json:"photo"`
		Voice *struct {
			FileID   string `json:"file_id"`
			MIME     string `json:"mime_type"`
			FileSize int64  `json:"file_size"`
		} `json:"voice"`
		Audio *struct {
			FileID   string `json:"file_id"`
			MIME     string `json:"mime_type"`
			FileName string `json:"file_name"`
			FileSize int64  `json:"file_size"`
		} `json:"audio"`
		Video *struct {
			FileID   string `json:"file_id"`
			MIME     string `json:"mime_type"`
			FileName string `json:"file_name"`
			FileSize int64  `json:"file_size"`
		} `json:"video"`
		Animation *struct {
			FileID   string `json:"file_id"`
			FileName string `json:"file_name"`
			FileSize int64  `json:"file_size"`
		} `json:"animation"`
		Document *struct {
			FileID   string `json:"file_id"`
			MIME     string `json:"mime_type"`
			FileName string `json:"file_name"`
			FileSize int64  `json:"file_size"`
		} `json:"document"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return Attachment{}, false
	}

	switch {
	case len(m.Photo) > 0:
		// The last entry is the largest. Telegram sends the same photograph at
		// several sizes and the smallest is a thumbnail nobody wants on a page.
		best := m.Photo[len(m.Photo)-1]
		return Attachment{
			FileID: best.FileID, Name: "photo.jpg", Caption: m.Caption,
			Kind: "photo", Size: best.FileSize,
		}, true
	case m.Voice != nil:
		// Telegram records voice notes as OGG, which the library already
		// accepts — so a spoken note becomes audio on a page with no
		// conversion anywhere.
		return Attachment{
			FileID: m.Voice.FileID, Name: "voice.ogg", Caption: m.Caption,
			Kind: "voice note", Size: m.Voice.FileSize,
		}, true
	case m.Audio != nil:
		return Attachment{
			FileID: m.Audio.FileID, Name: nameOr(m.Audio.FileName, "audio.mp3"),
			Caption: m.Caption, Kind: "audio", Size: m.Audio.FileSize,
		}, true
	case m.Video != nil:
		return Attachment{
			FileID: m.Video.FileID, Name: nameOr(m.Video.FileName, "video.mp4"),
			Caption: m.Caption, Kind: "video", Size: m.Video.FileSize,
		}, true
	case m.Animation != nil:
		return Attachment{
			FileID:  m.Animation.FileID,
			Name:    nameOr(m.Animation.FileName, "animation.mp4"),
			Caption: m.Caption, Kind: "animation", Size: m.Animation.FileSize,
		}, true
	case m.Document != nil:
		// A document is whatever somebody attached, so the filename is the only
		// hint there is — and the bytes still decide.
		return Attachment{
			FileID:  m.Document.FileID,
			Name:    nameOr(m.Document.FileName, "file"),
			Caption: m.Caption, Kind: "file", Size: m.Document.FileSize,
		}, true
	}
	return Attachment{}, false
}

func nameOr(name, fallback string) string {
	if strings.TrimSpace(name) == "" {
		return fallback
	}
	return name
}

// receive stores a file somebody sent, and says what happens next.
func (r *Router) receive(ctx context.Context, u Update) error {
	if r.Media == nil {
		return r.Bot.Say(ctx, u.Chat,
			"This installation has nowhere to put files, so nothing was saved.")
	}
	a := u.Attachment
	if a.Size > MaxDownload {
		return r.Bot.Say(ctx, u.Chat, fmt.Sprintf(
			"That is %d MB. The Bot API will not hand a bot anything over %d MB, "+
				"so it cannot be fetched — send a smaller version.",
			a.Size>>20, MaxDownload>>20))
	}

	name, body, err := r.Bot.Download(ctx, a.FileID)
	if err != nil {
		return r.Bot.Say(ctx, u.Chat, "That could not be fetched. "+err.Error())
	}
	if a.Name != "" {
		name = a.Name
	}

	id, what, err := r.Media.Save(u.From.Handle(), name, body, a.Caption)
	if err != nil {
		// The library's own words. It refuses by decoding rather than by
		// extension, so its refusals say something specific and useful.
		return r.Bot.Say(ctx, u.Chat, "Not saved. "+err.Error())
	}

	short := id
	if len(short) > 16 {
		short = short[:16]
	}
	if strings.TrimSpace(a.Caption) == "" && what == "image" {
		return r.Bot.Say(ctx, u.Chat, fmt.Sprintf(
			"Saved your %s. #%s\n\n"+
				"It needs a description before it can go on a page — a "+
				"sentence saying what is in it, for somebody who cannot see "+
				"it. Reply to this message with one.\n\n"+
				"A page with an undescribed image does not publish, so this "+
				"is the step that would otherwise stop you later.", a.Kind, short))
	}
	return r.Bot.Say(ctx, u.Chat, fmt.Sprintf(
		"Saved your %s. #%s\n\nIt is in your library — open /start and it is "+
			"there to choose.", a.Kind, short))
}

// describe attaches a description sent as a reply to the bot's own message.
func (r *Router) describe(ctx context.Context, u Update) (bool, error) {
	if r.Media == nil || u.ReplyTo == "" || u.Text == "" || u.IsCommand {
		return false, nil
	}
	found := reFileTag.FindStringSubmatch(u.ReplyTo)
	if found == nil {
		return false, nil
	}
	short := found[1]

	// The short id is resolved against what this person has, so a reply
	// carrying somebody else's id describes nothing.
	for _, f := range r.Media.Recent(u.From.Handle(), 200) {
		if f.Short() != short {
			continue
		}
		if err := r.Media.Describe(f.ID, u.Text); err != nil {
			return true, r.Bot.Say(ctx, u.Chat, "That could not be saved. "+err.Error())
		}
		return true, r.Bot.Say(ctx, u.Chat,
			"Described. That image can go on a page now.")
	}
	return true, r.Bot.Say(ctx, u.Chat,
		"That file is not in your library. Send it again and reply to the "+
			"message that comes back.")
}

// mediaHelp is what /media says.
func (r *Router) mediaHelp(ctx context.Context, u Update) error {
	if r.Media == nil {
		return r.Bot.Say(ctx, u.Chat, "This installation stores no files.")
	}
	files := r.Media.Recent(u.From.Handle(), 12)
	if len(files) == 0 {
		return r.Bot.Say(ctx, u.Chat,
			"Your library is empty.\n\n"+
				"Send me a photograph, a video, a voice note or an audio file "+
				"and it goes in. Add a caption and that becomes the "+
				"description; without one I will ask, because an image with "+
				"no description does not publish.")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Your library, newest first:\n")
	needs := 0
	for _, f := range files {
		fmt.Fprintf(&b, "\n#%s  %s", f.Short(), f.Kind)
		if f.Width > 0 {
			fmt.Fprintf(&b, "  %d×%d", f.Width, f.Height)
		}
		if f.NeedsDescription() {
			needs++
			b.WriteString("  — no description yet")
		}
	}
	if needs > 0 {
		fmt.Fprintf(&b, "\n\n%d of these cannot go on a page until they are "+
			"described. Send the file again and reply with a sentence.", needs)
	}
	return r.Bot.Say(ctx, u.Chat, b.String())
}
