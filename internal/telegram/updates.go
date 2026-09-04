package telegram

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"github.com/quilzo/quilzo/internal/egress"
	"io"
	"net/http"
	"strings"
	"time"
)

// Receiving messages: the half that lets somebody actually start.
//
// # Why this exists separately from the Mini App
//
// The Mini App is a web page. Getting to it requires a credential, and the
// credential is minted by a bot — so without something answering /start, the
// only way in was a terminal command, which is not a way in for anybody the
// feature is for.
//
// # Long polling by default, webhook by choice
//
// A webhook is more efficient and needs the bot itself to be publicly
// reachable over https with a valid certificate. Long polling needs none of
// that: it works from a laptop, from behind a NAT, from a machine with no
// inbound anything. Since the Mini App already has to be behind https for
// Telegram to open it, making the *bot* need its own public endpoint as well
// would double the setup for no gain during development.
//
// So polling is the default and the webhook is there for a deployment that
// wants it. Both end at the same Router, so the behaviour cannot differ between
// how you happen to be running it — which is the failure this package would
// otherwise invite.
//
// # Why the webhook verifies a secret
//
// A webhook endpoint is a URL on the public internet that causes this program
// to act on whatever is posted to it. Telegram supports a secret token sent in
// a header for exactly this reason, and without it the endpoint accepts
// instructions from anybody who guesses the path. It is required here rather
// than optional: an unauthenticated webhook is not a webhook, it is a form.

// pollTimeout is how long a getUpdates call waits for something to happen.
//
// Telegram holds the connection open until there is an update or this expires,
// so a long value means fewer requests rather than slower responses. Fifty
// seconds sits inside every proxy timeout worth worrying about.
const pollTimeout = 50 * time.Second

// maxUpdateText bounds what is read out of a message.
//
// Nothing here uses a long message — the only text that matters is a command —
// and a bound means a very large message cannot become a very large string.
const maxUpdateText = 4096

// rawUpdate is Telegram's shape, decoded once.
//
// The message stays raw so the media reader can look inside it without this
// struct having to mirror every attachment type Telegram supports — which is a
// list that grows, and a struct that mirrors it is a struct that goes stale
// quietly. It was also decoded twice, once per delivery path, which is two
// places for the two paths to start disagreeing.
type rawUpdate struct {
	UpdateID int64           `json:"update_id"`
	Message  json.RawMessage `json:"message"`
}

// rawMessage is the part every path needs.
type rawMessage struct {
	From *struct {
		ID        int64  `json:"id"`
		IsBot     bool   `json:"is_bot"`
		Username  string `json:"username"`
		FirstName string `json:"first_name"`
	} `json:"from"`
	Chat *struct {
		ID int64 `json:"id"`
	} `json:"chat"`
	Text    string `json:"text"`
	Caption string `json:"caption"`
	// ReplyToMessage is how a description finds the file it describes: the
	// bot put an id in its own message, and the reply carries that text back.
	// State in the chat rather than in this process.
	ReplyToMessage *struct {
		Text string `json:"text"`
		From *struct {
			IsBot bool `json:"is_bot"`
		} `json:"from"`
	} `json:"reply_to_message"`
}

// updateFrom turns Telegram's shape into this program's, or into a bare
// acknowledgement when there is nothing to act on.
//
// An update this program does not handle still has to come back with its id, or
// the offset never advances past it and it is redelivered forever.
func updateFrom(raw rawUpdate) Update {
	if len(raw.Message) == 0 {
		return Update{ID: raw.UpdateID}
	}
	var m rawMessage
	if err := json.Unmarshal(raw.Message, &m); err != nil {
		return Update{ID: raw.UpdateID}
	}
	if m.From == nil || m.Chat == nil || m.From.IsBot {
		// Bots talking to bots is a loop nobody asked for.
		return Update{ID: raw.UpdateID}
	}

	text := m.Text
	if text == "" {
		text = m.Caption
	}
	if len(text) > maxUpdateText {
		text = text[:maxUpdateText]
	}
	text = strings.TrimSpace(text)

	u := Update{
		ID: raw.UpdateID,
		From: User{
			ID:        m.From.ID,
			Username:  m.From.Username,
			FirstName: m.From.FirstName,
		},
		Chat:      m.Chat.ID,
		Text:      text,
		IsCommand: strings.HasPrefix(text, "/"),
	}
	// Only a reply to the *bot* carries state this program put there. A reply
	// to another person's message quoting an id would otherwise be a way to
	// describe somebody else's file.
	if m.ReplyToMessage != nil && m.ReplyToMessage.From != nil &&
		m.ReplyToMessage.From.IsBot {
		u.ReplyTo = m.ReplyToMessage.Text
	}
	if a, ok := attachmentOf(raw.Message); ok {
		u.Attachment = a
		u.HasAttachment = true
	}
	return u
}

// Update is one thing that happened, in the shape this program uses.
//
// A narrow struct rather than a mirror of Telegram's. Every field here is one
// the router acts on, so there is nothing to be tempted into trusting later:
// a struct with forty fields is an invitation to use the thirty-nine nobody
// checked.
type Update struct {
	ID   int64
	From User
	Chat int64
	Text string
	// IsCommand is true when the text begins with a slash, which is how
	// Telegram tells a user's words apart from an instruction.
	IsCommand bool
	// ReplyTo is the text of the bot's own message this replies to, when it
	// replies to one. Empty otherwise, including for a reply to somebody else.
	ReplyTo string
	// Attachment is the file this message carried, if any.
	Attachment    Attachment
	HasAttachment bool
}

// Updates fetches what has happened since an offset.
//
// The offset is Telegram's acknowledgement mechanism: asking for updates after
// n confirms everything up to n, so an update is delivered again until it has
// been asked past. That is what makes a crash mid-handling safe, and it is why
// the offset is advanced after the handler runs rather than before.
func (b *Bot) Updates(ctx context.Context, offset int64) ([]Update, error) {
	payload := map[string]any{
		"timeout":         int(pollTimeout.Seconds()),
		"allowed_updates": []string{"message"},
	}
	if offset > 0 {
		payload["offset"] = offset
	}

	var raw []rawUpdate
	// A client whose own timeout outlasts the poll, or every long poll ends as
	// a transport error a few seconds before Telegram would have answered.
	poller := *b
	poller.HTTP = egress.Client("chat", pollTimeout+15*time.Second)
	if err := poller.call(ctx, "getUpdates", payload, &raw); err != nil {
		return nil, err
	}

	out := make([]Update, 0, len(raw))
	for _, u := range raw {
		out = append(out, updateFrom(u))
	}
	return out, nil
}

// SetWebhook points Telegram at an address, with a secret it must present.
func (b *Bot) SetWebhook(ctx context.Context, endpoint, secret string) error {
	if !strings.HasPrefix(endpoint, "https://") {
		return fmt.Errorf(
			"a webhook has to be https; %q is not. Telegram will refuse it, "+
				"and an update posted in clear is a message read by whatever "+
				"is between", endpoint)
	}
	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf(
			"a webhook needs a secret token. Without one the endpoint acts on " +
				"whatever is posted to it by anybody who finds the path, which " +
				"is not a webhook, it is a form")
	}
	return b.call(ctx, "setWebhook", map[string]any{
		"url":             endpoint,
		"secret_token":    secret,
		"allowed_updates": []string{"message"},
		// Anything queued while this was pointed somewhere else is not worth
		// replaying into a different deployment.
		"drop_pending_updates": true,
	}, nil)
}

// DeleteWebhook stops Telegram posting updates, so polling can take over.
//
// Needed because the two are exclusive: getUpdates fails while a webhook is
// set, with an error that does not obviously say so.
func (b *Bot) DeleteWebhook(ctx context.Context) error {
	return b.call(ctx, "deleteWebhook",
		map[string]any{"drop_pending_updates": false}, nil)
}

// Router turns an update into an answer.
//
// It holds no state. Everything it needs to say is a function of the update and
// the configuration, which is what lets the same router serve both the polling
// loop and the webhook without either being a special case.
type Router struct {
	Bot *Bot
	// AppURL is where the Mini App is served, and where a minted link points.
	AppURL string
	// BotToken keys the links this hands out. Held separately from Bot so a
	// router can be built in a test without a working API client.
	BotToken string
	// Media is the library files sent to the bot go into. Nil means the bot
	// says it stores nothing rather than accepting a photograph and dropping
	// it, which is the failure somebody only notices when the page is empty.
	Media MediaStore
	// Now is the clock, injectable for tests.
	Now func() time.Time
}

func (r *Router) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Handle answers one update.
//
// English by default and without configuration, because that is what the
// Telegram Apps Center checks and because a bot whose first reply is in a
// language the reader does not have is a bot they close.
func (r *Router) Handle(ctx context.Context, u Update) error {
	if u.Chat == 0 || u.From.ID == 0 {
		return nil
	}
	command, _, _ := strings.Cut(strings.ToLower(u.Text), " ")
	// Telegram appends @thebot to commands in groups.
	command, _, _ = strings.Cut(command, "@")

	// A file, which is the shortest path there is from "I have this" to "it is
	// on my site" — and the reason this runs before the command switch is that
	// a photograph with a caption has both.
	if u.HasAttachment {
		return r.receive(ctx, u)
	}
	// A reply to one of the bot's own messages, carrying the description an
	// image needs before it can be published.
	if handled, err := r.describe(ctx, u); handled {
		return err
	}

	switch command {
	case "/start":
		return r.sendStart(ctx, u)
	case "/help":
		return r.Bot.Say(ctx, u.Chat, helpText)
	case "/media":
		return r.mediaHelp(ctx, u)
	case "/privacy":
		return r.Bot.Say(ctx, u.Chat, r.privacyText())
	case "/terms":
		return r.Bot.Say(ctx, u.Chat, r.termsText())
	default:
		if u.IsCommand {
			return r.Bot.Say(ctx, u.Chat,
				"I do not know that one. /start opens the page editor, "+
					"/media lists your files, /help explains what this does.")
		}
		// Not a command. Rather than ignoring it, which reads as broken, this
		// says what to do — the text of a message is not how a page gets
		// written here, and saying so is cheaper than a person guessing.
		return r.Bot.Say(ctx, u.Chat,
			"Pages are written in the editor rather than in this chat, so "+
				"nothing was saved. Send /start to open it — or send me a "+
				"photograph, a video or a voice note and it goes straight "+
				"into your library.")
	}
}

func (r *Router) sendStart(ctx context.Context, u Update) error {
	app := &App{BotToken: r.BotToken, Now: r.Now}
	link, err := app.LinkFor(u.From, r.AppURL)
	if err != nil {
		// The reason is for the operator, not the person in the chat: it is
		// almost always a misconfigured address, which they can do nothing
		// about and should not be shown the internals of.
		_ = r.Bot.Say(ctx, u.Chat,
			"This is not set up correctly yet, so there is nothing to open. "+
				"Whoever runs this bot will see why in its log.")
		return err
	}
	greeting := "Hello."
	if u.From.FirstName != "" {
		greeting = "Hello, " + u.From.FirstName + "."
	}
	return r.Bot.SendLink(ctx, u.Chat,
		greeting+"\n\n"+startText, "Write a page", link)
}

const startText = "This publishes a web page from a form. You write a title " +
	"and some words; it makes a page and puts it online.\n\n" +
	"Before anything is published it is checked — an image with no " +
	"description, a heading that skips a level, or text too faint to read " +
	"against its background is refused rather than published with a warning. " +
	"If yours is refused you will see exactly which check said so.\n\n" +
	"The button below works once and lasts fifteen minutes."

const helpText = "What this does: turns a form into a published web page.\n\n" +
	"/start — open the editor\n" +
	"/media — the files you have sent me\n" +
	"/terms — what you are agreeing to\n" +
	"/privacy — what is stored, which is very little\n\n" +
	"Send me a photograph, a video, an audio file or a voice note and it goes " +
	"into your library, ready to put on a page. A caption becomes the " +
	"description; without one I will ask for it, because an image nobody has " +
	"described does not publish.\n\n" +
	"There is no HTML field, on purpose. What you type is text, and the " +
	"template it lands in cannot execute anything — so a page here cannot " +
	"carry a script, whoever wrote it."

func (r *Router) privacyText() string {
	if r.AppURL != "" {
		return "What is stored: your Telegram user id, and whatever you type " +
			"into the page. Nothing else — no phone number, no contacts, no " +
			"message history, no analytics, and no cookies.\n\n" +
			"Your page is public, because that is what publishing a page " +
			"means.\n\nIn full: " + strings.TrimSuffix(r.AppURL, "/") + "/privacy"
	}
	return "What is stored: your Telegram user id, and whatever you type into " +
		"the page. Nothing else."
}

func (r *Router) termsText() string {
	if r.AppURL != "" {
		return "In short: publish what you have the right to publish, it is " +
			"public, and it can be taken down.\n\nIn full: " +
			strings.TrimSuffix(r.AppURL, "/") + "/terms"
	}
	return "In short: publish what you have the right to publish, it is " +
		"public, and it can be taken down."
}

// Poll runs the long-polling loop until the context is cancelled.
//
// The offset advances after the handler returns, not before. An update that
// fails mid-handling is therefore delivered again rather than lost, which is
// the right way round for something that publishes: a duplicate greeting is a
// nuisance and a silently dropped one is a person who thinks the bot is broken.
//
// A handler error stops the offset advancing for that update but does not stop
// the loop, because one malformed message should not take the bot down.
func (r *Router) Poll(ctx context.Context, onError func(error)) error {
	var offset int64
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		updates, err := r.Bot.Updates(ctx, offset)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if onError != nil {
				onError(err)
			}
			// A pause, so a persistent failure is a slow retry rather than a
			// tight loop against somebody else's API.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
			continue
		}
		for _, u := range updates {
			if herr := r.Handle(ctx, u); herr != nil && onError != nil {
				onError(herr)
			}
			offset = u.ID + 1
		}
	}
}

// WebhookHandler serves updates posted by Telegram.
//
// The secret is checked in constant time and before the body is read. Anything
// that fails is a 404 rather than a 403: an endpoint that distinguishes "wrong
// secret" from "wrong path" tells whoever is probing which of the two they got
// right.
func (r *Router) WebhookHandler(secret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || strings.TrimSpace(secret) == "" {
			http.NotFound(w, req)
			return
		}
		presented := req.Header.Get("X-Telegram-Bot-Api-Secret-Token")
		if !hmac.Equal([]byte(presented), []byte(secret)) {
			http.NotFound(w, req)
			return
		}

		body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		if err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		var raw rawUpdate
		if err := json.Unmarshal(body, &raw); err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		// Answered before handling. Telegram retries anything it does not get a
		// prompt 200 for, and a retry storm caused by slow handling is worse
		// than a greeting that arrives a moment later.
		w.WriteHeader(http.StatusOK)

		u := updateFrom(raw)
		if u.From.ID == 0 {
			return
		}
		_ = r.Handle(req.Context(), u)
	})
}
