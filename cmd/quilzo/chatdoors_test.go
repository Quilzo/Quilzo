// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/chat"
	"github.com/quilzo/quilzo/internal/telegram"
)

// A signed slash command comes back with a link into the editor.
//
// internal/slack was complete and imported by nothing: a verifier with a real
// test suite that had never answered a request. Its own tests proved the
// signature check; nothing proved there was a door behind it. This drives the
// whole path — sign as Slack signs, post it, read the reply — because "the
// verifier works" and "somebody can publish from Slack" turned out to be very
// different claims.
func TestASignedSlashCommandAnswersWithALink(t *testing.T) {
	const secret = "8f742231b10e8888abcd99yyyzzz85a5"
	app := &telegram.App{
		BotToken: secret,
		Platform: chat.Slack,
		Spender:  chat.NewMemory(),
	}
	h := slashCommand(app, secret, "https://pages.example.test")

	body := "team_id=T0001&user_id=U0001&user_name=ada&command=%2Fquilzo&text="
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, slackRequest(t, secret, body, time.Now()))

	if rec.Code != http.StatusOK {
		t.Fatalf("a correctly signed command was refused with %d: %s",
			rec.Code, rec.Body.String())
	}
	var reply map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("the reply is not JSON Slack can read: %v", err)
	}
	// Ephemeral, because a link in a channel is a link everybody in the
	// channel can use until somebody spends it — and the person who spends it
	// is whoever clicks first.
	if reply["response_type"] != "ephemeral" {
		t.Errorf("the reply is %q, so a credential is posted to the whole "+
			"channel", reply["response_type"])
	}
	if !strings.Contains(reply["text"], "https://pages.example.test?") {
		t.Errorf("the reply carries no link into the editor: %q", reply["text"])
	}
	// The platform travels in the credential. That is what stops a link minted
	// here verifying as a Telegram one where an operator has configured the
	// same secret for both, which is the cross-replay internal/chat exists to
	// prevent.
	if !strings.Contains(reply["text"], "m=slack") {
		t.Errorf("the link does not name its platform, so it is not bound to "+
			"one: %q", reply["text"])
	}
}

// An unsigned or wrongly signed command is refused, and told nothing.
func TestAnUnsignedSlashCommandIsRefused(t *testing.T) {
	const secret = "8f742231b10e8888abcd99yyyzzz85a5"
	app := &telegram.App{BotToken: secret, Platform: chat.Slack, Spender: chat.NewMemory()}
	h := slashCommand(app, secret, "https://pages.example.test")
	body := "team_id=T0001&user_id=U0001&user_name=ada"

	for _, c := range []struct {
		name string
		req  *http.Request
	}{
		{"no signature at all", httptest.NewRequest("POST", "/command",
			strings.NewReader(body))},
		{"signed with the wrong secret", slackRequest(t, "not-the-secret",
			body, time.Now())},
		// The timestamp is inside the signed string, which is what makes this
		// check mean anything: a captured request replayed tomorrow still
		// carries yesterday's stamp and cannot be re-signed without the
		// secret.
		{"correctly signed yesterday", slackRequest(t, secret, body,
			time.Now().Add(-24*time.Hour))},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, c.req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: answered %d, want 403", c.name, rec.Code)
		}
		// The reason belongs in the operator's log, not in the reply. A
		// verifier that says which part of a signature failed helps somebody
		// forge the next one.
		if strings.Contains(strings.ToLower(rec.Body.String()), "signature") ||
			strings.Contains(rec.Body.String(), "timestamp") {
			t.Errorf("%s: the refusal explains itself to the caller: %s",
				c.name, rec.Body.String())
		}
	}
}

// Discord's ping is answered with a pong, and only after the signature holds.
//
// Discord will not accept an endpoint until it pings one and gets a pong, so
// this is the first thing that ever runs. An endpoint that pongs
// unconditionally is an endpoint anybody can confirm, which is why the check
// comes first.
func TestDiscordPongsOnlyAfterCheckingTheSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	app := &telegram.App{BotToken: "editor-secret", Platform: chat.Discord,
		Spender: chat.NewMemory()}
	h := interactions(app, hex.EncodeToString(pub), "https://pages.example.test")

	ping := `{"type":1}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, discordRequest(priv, ping, time.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("a correctly signed ping was refused with %d: %s",
			rec.Code, rec.Body.String())
	}
	var reply map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("the pong is not JSON: %v", err)
	}
	if reply["type"] != float64(1) {
		t.Errorf("answered type %v, and Discord accepts an endpoint only on a "+
			"type 1 pong", reply["type"])
	}

	// The same ping, signed by somebody else.
	_, other, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, discordRequest(other, ping, time.Now()))
	if rec2.Code != http.StatusForbidden {
		t.Errorf("a ping signed with the wrong key was answered %d; an "+
			"endpoint that pongs unconditionally is one anybody can confirm",
			rec2.Code)
	}
}

// Two people with the same numeric id on two messengers do not share a page.
//
// The editor stored pages under "tg" + id with the prefix written in, which
// was correct while Telegram was the only door. A second door makes it a
// collision, and the symptom is one person editing another's page rather than
// an error anybody sees.
func TestTheSameIDOnTwoMessengersIsTwoPeople(t *testing.T) {
	const id = 4212
	handles := map[chat.Platform]string{}
	for _, p := range []chat.Platform{chat.Telegram, chat.Slack, chat.Discord} {
		u := telegram.User{ID: id, Platform: p}
		h := u.Handle()
		for other, seen := range handles {
			if seen == h {
				t.Fatalf("%s and %s both store id %d under %q, so one person "+
					"edits the other's page", p, other, id, h)
			}
		}
		handles[p] = h
	}
	// And Telegram keeps the spelling it has always written, because a handle
	// is a content path and changing it moves everybody's pages.
	if got := (telegram.User{ID: id}).Handle(); got != "tg"+strconv.Itoa(id) {
		t.Errorf("a Telegram handle is now %q; every page published from the "+
			"bot before this lives at tg%d", got, id)
	}
}

// slackRequest signs a body the way Slack does: HMAC-SHA256 over
// "v0:timestamp:body", hex, prefixed "v0=".
func slackRequest(t *testing.T, secret, body string, at time.Time) *http.Request {
	t.Helper()
	stamp := strconv.FormatInt(at.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "v0:%s:%s", stamp, body)

	r := httptest.NewRequest("POST", "/command", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Slack-Request-Timestamp", stamp)
	r.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	return r
}

// discordRequest signs a body the way Discord does: Ed25519 over
// timestamp + body.
func discordRequest(priv ed25519.PrivateKey, body string, at time.Time) *http.Request {
	stamp := strconv.FormatInt(at.Unix(), 10)
	sig := ed25519.Sign(priv, []byte(stamp+body))

	r := httptest.NewRequest("POST", "/interactions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Signature-Timestamp", stamp)
	r.Header.Set("X-Signature-Ed25519", hex.EncodeToString(sig))
	return r
}
