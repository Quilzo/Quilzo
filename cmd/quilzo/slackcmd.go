// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/chat"
	"github.com/quilzo/quilzo/internal/discord"
	"github.com/quilzo/quilzo/internal/slack"
	"github.com/quilzo/quilzo/internal/telegram"
)

// Publishing from Slack and from Discord.
//
// # What was wrong
//
// internal/slack and internal/discord were complete, correct, tested, and
// imported by nothing. About six hundred lines of signature verification that
// had never run outside a test: no command, no route, nothing calling Verify.
// internal/chat was written as the layer beneath all three messengers and only
// Telegram ever arrived there.
//
// Nothing failed, which is why it lasted. Both packages compile and are
// covered, and `go vet` has no opinion about a package nobody imports — so the
// project's own inventory listed two integrations it did not have.
// TestEveryPackageIsReachedBySomething is what stops that recurring.
//
// # What they now reach
//
// The editor. internal/telegram's editor was always the generic half of that
// package — 845 lines with two mentions of Telegram in them — and these two
// mount it with their own verifier and their own platform. The platform
// travels into every signature check, so a credential minted for Slack does
// not verify as a Telegram one even where an operator has configured the same
// secret for both, and into the handle, so two people who happen to share a
// numeric id across two messengers do not share a page.
//
// # Why a link, and not an editor inside the chat
//
// Slack's modals and Discord's components are JSON a server returns, so either
// could in principle host an editor. Neither gets one, for the reason
// internal/telegram/link.go gives about initData: the editing surface is where
// this program's central property is worth the most, and a second
// implementation of it — in somebody else's component vocabulary, kept in step
// with the first — is two editors that can disagree about what is safe to
// publish.
//
// So the command answers with a signed single-use link into the one editor.
// One editor, three doors.
//
// # Why the reply is ephemeral
//
// A link in a channel is a link everybody in the channel can use until it is
// spent, and the person who spends it is whoever clicks first. `ephemeral`
// shows it only to whoever typed the command. The link is single-use and
// short-lived regardless — that is internal/chat's job and it does not depend
// on this — but posting a credential to a room of people is not something to
// rely on a nonce to make acceptable.

func cmdSlack(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"serve"}
	}
	switch args[0] {
	case "serve":
		return slackServe(root, args[1:])
	case "check":
		return slackCheck()
	default:
		return fmt.Errorf("unknown slack command %q; try serve or check", args[0])
	}
}

func cmdDiscord(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"serve"}
	}
	switch args[0] {
	case "serve":
		return discordServe(root, args[1:])
	case "check":
		return discordCheck()
	default:
		return fmt.Errorf("unknown discord command %q; try serve or check", args[0])
	}
}

// The environment variables the two secrets come from.
//
// Not flags, for the reason telegramServe gives about --token: a secret in an
// argument is already in the shell history, and in the process list of every
// other user on the machine.
const (
	slackSecretEnv   = "QUILZO_SLACK_SIGNING_SECRET"
	discordKeyEnv    = "QUILZO_DISCORD_PUBLIC_KEY"
	chatSecretEnvHow = "  Put it in %s. It is not a flag: a secret in an " +
		"argument is already in your shell history."
)

func slackCheck() error {
	secret := strings.TrimSpace(os.Getenv(slackSecretEnv))
	if secret == "" {
		return fmt.Errorf("no Slack signing secret.\n"+chatSecretEnvHow,
			slackSecretEnv)
	}
	w.Human("  %ssigning secret present (%d characters)%s\n", dim, len(secret), reset)
	w.Human("  %sthis checks the secret is readable, not that Slack accepts "+
		"it — that needs a request from Slack%s\n", dim, reset)
	return nil
}

func discordCheck() error {
	key := strings.TrimSpace(os.Getenv(discordKeyEnv))
	if key == "" {
		return fmt.Errorf("no Discord public key.\n"+chatSecretEnvHow, discordKeyEnv)
	}
	// Parsed rather than measured. A public key is a fixed shape and an
	// operator who pasted the application id instead should be told now
	// rather than by every interaction failing.
	if _, err := discord.ParseKey(key); err != nil {
		return fmt.Errorf("the Discord public key is not usable: %w", err)
	}
	w.Human("  %spublic key parses as an Ed25519 key%s\n", dim, reset)
	return nil
}

// chatApp builds the editor for a messenger other than Telegram.
//
// Everything past the identity is shared: the same publisher, the same drafts,
// the same media library, the same design. That is the point of the split, and
// it is why these two commands are short.
func chatApp(root, tplDir, design, siteURL, secret string,
	p chat.Platform, shared bool) (*telegram.App, error) {

	s, err := open(root)
	if err != nil {
		return nil, err
	}
	d, err := loadDesign(tplDir)
	if err != nil {
		return nil, err
	}
	lib, lerr := openMedia(root)
	if lerr != nil {
		return nil, fmt.Errorf("the media library could not be opened: %w", lerr)
	}
	publisher := &chatPublisher{root: root, store: s, tplDir: tplDir, design: design}
	library := &chatMedia{root: root, lib: lib, cfg: mustConfig(root), shared: shared}

	return &telegram.App{
		BotToken:   secret,
		Platform:   p,
		Spender:    chat.NewMemory(),
		Stylesheet: d.Stylesheet,
		SiteURL:    strings.TrimSpace(siteURL),
		Publisher:  publisher,
		Drafts:     publisher,
		Media:      library,
	}, nil
}

func slackServe(root string, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8083", "listen address")
	tplDir := fs.String("templates", "templates", "where the layouts live")
	siteURL := fs.String("site-url", "",
		"where published pages can be read, e.g. https://example.com")
	appURL := fs.String("app-url", "",
		"the public https address this is served at, as given to Slack")
	design := fs.String("design", "sections",
		"which shipped design a new page is published with")
	sharedMedia := fs.Bool("shared-media", false,
		"show the whole media library in the editor, not only what each "+
			"person sent; for a single-operator installation")
	if err := fs.Parse(args); err != nil {
		return err
	}

	secret := strings.TrimSpace(os.Getenv(slackSecretEnv))
	if secret == "" {
		return fmt.Errorf("no Slack signing secret.\n"+chatSecretEnvHow,
			slackSecretEnv)
	}
	if strings.TrimSpace(*appURL) == "" {
		return fmt.Errorf(
			"--app-url is required: it is the address that goes in the link " +
				"this answers with, and this program will not guess it from a " +
				"request header — that is how a link ends up pointing at " +
				"somebody else's host")
	}

	app, err := chatApp(root, *tplDir, *design, *siteURL, secret,
		chat.Slack, *sharedMedia)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/command", slashCommand(app, secret, strings.TrimSpace(*appURL)))
	mux.Handle("/", app.Handler())

	// Recorded before the listener opens, for the reason telegramServe gives:
	// this is the moment a writable surface reachable from a workspace came
	// into existence, and a record written at shutdown is missing from every
	// process that was killed rather than stopped.
	record(root, resolveCaller(root, "").auditRecord("slack.serve", "/",
		audit.Success, map[string]string{"addr": *addr, "design": *design}))

	w.Human("slack on http://%s\n", *addr)
	w.Human("  %sslash command endpoint: %s/command%s\n", dim,
		strings.TrimSuffix(*appURL, "/"), reset)
	w.Human("  %sit answers with a single-use link into the editor, shown "+
		"only to whoever typed it%s\n", dim, reset)
	srv := &http.Server{
		Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

// slashCommand answers a verified slash command with a link into the editor.
func slashCommand(app *telegram.App, secret, appURL string) http.Handler {
	return http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(wr, "POST only", http.StatusMethodNotAllowed)
			return
		}
		req, err := slack.Verify(r, secret, time.Now())
		if err != nil {
			// The reason goes to the operator's log and not to the caller. A
			// verifier that explains which part of a signature failed is a
			// verifier that helps somebody forge the next one.
			fmt.Fprintf(os.Stderr, "  %sslack: %v%s\n", dim, err, reset)
			http.Error(wr, "forbidden", http.StatusForbidden)
			return
		}
		user := telegram.User{
			ID: req.Account.ID, Username: req.Account.Username,
			FirstName: req.Account.FirstName, AuthDate: req.Account.At,
			Platform: chat.Slack,
		}
		link, err := app.LinkFor(user, appURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %sslack: %v%s\n", dim, err, reset)
			http.Error(wr, "the link could not be made", http.StatusInternalServerError)
			return
		}
		ephemeral(wr, "Open your page: "+link+
			"\n\nIt works once and lasts a quarter of an hour.")
	})
}

// ephemeral answers Slack with a message only the caller sees.
func ephemeral(wr http.ResponseWriter, text string) {
	wr.Header().Set("Content-Type", "application/json")
	// Written with the encoder rather than by hand: the text carries a URL
	// and a newline, and a hand-built JSON string is where an escaping bug
	// lives.
	_ = json.NewEncoder(wr).Encode(map[string]string{
		"response_type": "ephemeral",
		"text":          text,
	})
}

func discordServe(root string, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8086", "listen address")
	tplDir := fs.String("templates", "templates", "where the layouts live")
	siteURL := fs.String("site-url", "",
		"where published pages can be read, e.g. https://example.com")
	appURL := fs.String("app-url", "",
		"the public https address this is served at, as given to Discord")
	design := fs.String("design", "sections",
		"which shipped design a new page is published with")
	sharedMedia := fs.Bool("shared-media", false,
		"show the whole media library in the editor, not only what each "+
			"person sent; for a single-operator installation")
	if err := fs.Parse(args); err != nil {
		return err
	}

	key := strings.TrimSpace(os.Getenv(discordKeyEnv))
	if key == "" {
		return fmt.Errorf("no Discord public key.\n"+chatSecretEnvHow, discordKeyEnv)
	}
	if _, err := discord.ParseKey(key); err != nil {
		return fmt.Errorf("the Discord public key is not usable: %w", err)
	}
	if strings.TrimSpace(*appURL) == "" {
		return fmt.Errorf(
			"--app-url is required: it is the address that goes in the link " +
				"this answers with, and this program will not guess it from a " +
				"request header")
	}

	// The editor's own credentials are keyed on a secret this process holds.
	// Discord gives out a public key, which verifies their requests and cannot
	// sign ours — so the editor is keyed separately. Required rather than
	// generated, because a secret invented at startup logs everybody out on
	// every restart and cannot be shared by two processes.
	editorSecret := strings.TrimSpace(os.Getenv("QUILZO_DISCORD_LINK_SECRET"))
	if editorSecret == "" {
		return fmt.Errorf(
			"no link secret.\n" +
				"  Discord's public key verifies their requests and cannot sign " +
				"ours, so the editor needs a secret of its own.\n" +
				"  Put one in QUILZO_DISCORD_LINK_SECRET — any long random " +
				"string, the same one on every process serving this")
	}

	app, err := chatApp(root, *tplDir, *design, *siteURL, editorSecret,
		chat.Discord, *sharedMedia)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/interactions", interactions(app, key, strings.TrimSpace(*appURL)))
	mux.Handle("/", app.Handler())

	record(root, resolveCaller(root, "").auditRecord("discord.serve", "/",
		audit.Success, map[string]string{"addr": *addr, "design": *design}))

	w.Human("discord on http://%s\n", *addr)
	w.Human("  %sinteractions endpoint: %s/interactions%s\n", dim,
		strings.TrimSuffix(*appURL, "/"), reset)
	srv := &http.Server{
		Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

// interactions answers a verified Discord interaction.
func interactions(app *telegram.App, publicKey, appURL string) http.Handler {
	return http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(wr, "POST only", http.StatusMethodNotAllowed)
			return
		}
		req, err := discord.Verify(r, publicKey, time.Now())
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %sdiscord: %v%s\n", dim, err, reset)
			http.Error(wr, "forbidden", http.StatusForbidden)
			return
		}
		// Discord verifies an endpoint by sending a ping that must be answered
		// with a pong, and it sends one before it will accept any command at
		// all. Answering it only after the signature check is what makes the
		// check meaningful: an endpoint that pongs unconditionally is an
		// endpoint anybody can confirm.
		if req.IsPing() {
			reply(wr, map[string]any{"type": 1})
			return
		}
		user := telegram.User{
			ID: req.Account.ID, Username: req.Account.Username,
			FirstName: req.Account.FirstName, AuthDate: req.Account.At,
			Platform: chat.Discord,
		}
		link, err := app.LinkFor(user, appURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %sdiscord: %v%s\n", dim, err, reset)
			http.Error(wr, "the link could not be made", http.StatusInternalServerError)
			return
		}
		// Type 4 is a channel message; flag 64 is ephemeral, which is the same
		// decision as Slack's response_type and for the same reason.
		reply(wr, map[string]any{
			"type": 4,
			"data": map[string]any{
				"flags": 64,
				"content": "Open your page: " + link +
					"\n\nIt works once and lasts a quarter of an hour.",
			},
		})
	})
}

func reply(wr http.ResponseWriter, body map[string]any) {
	wr.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(wr).Encode(body)
}
