package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The bot, which is the only part of this that talks outward.
//
// # Why this is small
//
// The Bot API has a hundred methods and this needs three: confirm the token
// works, send somebody a button, and answer a message. Wrapping the rest would
// be a library nobody asked for, and every method added is another shape of
// untrusted response to handle.
//
// # Why the token is never a flag
//
// A bot token is a bearer credential for an identity a billion people can
// message. Passed as a command-line flag it lands in shell history, in `ps`
// output for every user on the machine, and in any process listing a monitoring
// agent collects. So it comes from the environment or a file with an owner and a
// mode, and the command refuses a flag rather than accepting one and warning.
//
// # Why responses are read with a bound
//
// api.telegram.org is a third party. A response body with no limit is a way for
// whatever is at the other end of that name — including whatever answers when
// DNS is lying — to spend this process's memory. The limit is generous for the
// methods used and finite, which is the property that matters.

// maxResponse bounds a Bot API reply. The largest of these is a getMe, which is
// a few hundred bytes; a megabyte is four orders of magnitude of headroom and
// still a bound.
const maxResponse = 1 << 20

// Bot calls the Telegram Bot API.
type Bot struct {
	// Token authenticates as the bot. Never logged, never in an error message:
	// an error that quotes the credential it failed with puts it in a log.
	Token string
	// HTTP is the client. Nil means one with a timeout, because a call with no
	// timeout is a goroutine that never comes back.
	HTTP *http.Client
	// BaseURL is the API root, overridable for tests. Empty means Telegram's.
	BaseURL string
}

func (b *Bot) client() *http.Client {
	if b.HTTP != nil {
		return b.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (b *Bot) base() string {
	if b.BaseURL != "" {
		return strings.TrimSuffix(b.BaseURL, "/")
	}
	return "https://api.telegram.org"
}

// Identity is what getMe answers.
type Identity struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Name     string `json:"first_name"`
}

// Me confirms the token and says which bot it belongs to.
//
// Worth its own method because "the token is wrong" and "the Mini App URL is
// wrong" produce the same symptom — nothing happens — and this separates them
// before anybody spends an afternoon on the other one.
func (b *Bot) Me(ctx context.Context) (Identity, error) {
	var out Identity
	if err := b.call(ctx, "getMe", nil, &out); err != nil {
		return Identity{}, err
	}
	return out, nil
}

// SendLink sends a chat a button that opens the Mini App.
//
// The button is a web_app button rather than a plain link, because that is what
// makes Telegram open it inside the client with its own theme and back
// behaviour instead of handing it to a browser. The URL carries the single-use
// credential; see link.go.
func (b *Bot) SendLink(ctx context.Context, chatID int64, text, label, appURL string) error {
	if !strings.HasPrefix(appURL, "https://") {
		return fmt.Errorf(
			"Telegram will only open a Mini App over https, and this one is at "+
				"%q. In development, put a tunnel in front of it rather than "+
				"sending a link that silently does nothing", appURL)
	}
	payload := map[string]any{
		"chat_id": chatID,
		"text":    text,
		// Plain text. Telegram's markdown parsers have their own escaping
		// rules, and a message assembled from a user's own name is exactly
		// where a parse mode turns a display name into formatting.
		"reply_markup": map[string]any{
			"inline_keyboard": [][]map[string]any{{{
				"text":    label,
				"web_app": map[string]string{"url": appURL},
			}}},
		},
	}
	return b.call(ctx, "sendMessage", payload, nil)
}

// Say sends a chat plain text, for the answers that are not a button.
func (b *Bot) Say(ctx context.Context, chatID int64, text string) error {
	return b.call(ctx, "sendMessage",
		map[string]any{"chat_id": chatID, "text": text}, nil)
}

// call is the one place a request is made, so the token handling, the bound and
// the error shape are decided once.
func (b *Bot) call(ctx context.Context, method string, payload any, into any) error {
	if strings.TrimSpace(b.Token) == "" {
		return fmt.Errorf("no bot token, so there is nobody to call as")
	}

	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	// The token is in the path because that is the API's design. It is
	// deliberately not put anywhere else — not a header this code logs, not an
	// error message below.
	endpoint := b.base() + "/bot" + b.Token + "/" + method

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return fmt.Errorf("%s could not be prepared", method)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := b.client().Do(req)
	if err != nil {
		// Wrapped rather than returned, because a transport error can contain
		// the URL — and the URL contains the token.
		return fmt.Errorf("%s could not be sent: %s", method, scrub(err.Error(), b.Token))
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("%s gave an unreadable answer", method)
	}
	var envelope struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("%s answered with something that is not the Bot API "+
			"(HTTP %d)", method, resp.StatusCode)
	}
	if !envelope.OK {
		return fmt.Errorf("Telegram refused %s: %s", method,
			scrub(envelope.Description, b.Token))
	}
	if into == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, into)
}

// scrub removes the token from anything about to be shown or logged.
//
// Belt and braces: nothing here should be putting the token in a message, and
// this is the function that makes that true even when something does. A
// credential leaks once and then it has leaked.
func scrub(text, token string) string {
	if token == "" {
		return text
	}
	return strings.ReplaceAll(text, token, "[token]")
}
