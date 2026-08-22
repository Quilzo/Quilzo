package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/starter"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/telegram"
)

// Publishing from a Telegram chat.
//
// # Why this is a separate process
//
// Three processes now, and the reason is the same one that separated the admin
// from the site: different exposure needs a different policy. The admin is
// loopback and holds credentials. The public site is anonymous, read-only, and
// the thing pointed at the internet. This one is authenticated, writable, framed
// by somebody else's client, and reachable from a billion accounts — so it gets
// its own port, its own policy, and its own audit action.
//
// # Where the token comes from
//
// The environment or a file, never a flag. A bot token is a bearer credential
// for an identity a billion people can message, and a flag puts it in shell
// history and in `ps` output for every user on the machine. The command refuses
// a flag rather than accepting one with a warning, because a warning about a
// credential that has already been written to history is a warning about
// something that already happened.

// tokenEnv is where the bot token is read from.
const tokenEnv = "QUILZO_TELEGRAM_TOKEN"

func cmdTelegram(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"serve"}
	}
	switch args[0] {
	case "serve":
		return telegramServe(root, args[1:])
	case "check":
		return telegramCheck(args[1:])
	case "link":
		return telegramLink(args[1:])
	default:
		return fmt.Errorf("unknown telegram command %q; try serve, check or link",
			args[0])
	}
}

// botToken reads the credential, and explains the rule when it is missing.
func botToken(fromFile string) (string, error) {
	if path := strings.TrimSpace(fromFile); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if info, serr := os.Stat(path); serr == nil && info.Mode().Perm()&0o077 != 0 {
			// Said rather than fixed. Changing the mode of somebody's file
			// without asking is its own surprise, and the operator is the one
			// who knows who else is on the machine.
			w.Human("  %s%s is readable by other users on this machine (mode "+
				"%04o)%s\n", dim, path, info.Mode().Perm(), reset)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if t := strings.TrimSpace(os.Getenv(tokenEnv)); t != "" {
		return t, nil
	}
	return "", fmt.Errorf(
		"no bot token. Set %s, or pass --token-file with a path to one.\n"+
			"  There is deliberately no --token flag: a token passed as an "+
			"argument is in your shell history and in `ps` output for every "+
			"other user on this machine, and neither can be taken back",
		tokenEnv)
}

func telegramServe(root string, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8082", "listen address")
	tplDir := fs.String("templates", "templates", "where the layouts live")
	tokenFile := fs.String("token-file", "", "a file holding the bot token")
	siteURL := fs.String("site-url", "",
		"where published pages can be read, e.g. https://example.com")
	appURL := fs.String("app-url", "",
		"the public https address of this Mini App, as given to @BotFather")
	webhook := fs.String("webhook", "",
		"serve updates at this path instead of polling; needs --webhook-secret")
	webhookSecret := fs.String("webhook-secret-env", "",
		"environment variable holding the webhook secret")
	noBot := fs.Bool("no-bot", false,
		"serve the Mini App without answering messages")
	design := fs.String("design", "sections",
		"which shipped design a new page is published with")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Guard against the flag somebody will reach for anyway.
	for _, a := range args {
		if strings.HasPrefix(a, "--token=") || strings.HasPrefix(a, "-token=") {
			return fmt.Errorf(
				"there is no --token flag, on purpose. Use %s or --token-file; "+
					"a token in an argument is already in your shell history",
				tokenEnv)
		}
	}

	token, err := botToken(*tokenFile)
	if err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	d, err := loadDesign(*tplDir)
	if err != nil {
		return err
	}

	// The library files sent to the bot go into, opened before anything is
	// served so a build that cannot open it says so rather than accepting a
	// photograph and dropping it.
	lib, lerr := openMedia(root)
	if lerr != nil {
		return fmt.Errorf("the media library could not be opened: %w", lerr)
	}
	publisher := &chatPublisher{
		root: root, store: s, tplDir: *tplDir, design: *design,
	}
	// Named library rather than media, which is the package.
	library := &chatMedia{root: root, lib: lib, cfg: mustConfig(root)}

	app := &telegram.App{
		BotToken:   token,
		Spender:    telegram.NewMemory(),
		Stylesheet: d.Stylesheet,
		SiteURL:    strings.TrimSpace(*siteURL),
		Publisher:  publisher,
		Drafts:     publisher,
		Media:      library,
	}

	// Recorded before the listener opens, not after it closes. This is the
	// moment a writable surface reachable from a billion accounts came into
	// existence, and a record written at shutdown is a record missing from
	// every process that was killed rather than stopped.
	record(root, resolveCaller(root, "").auditRecord("telegram.serve", "/",
		audit.Success, map[string]string{"addr": *addr, "design": *design}))

	// The bot half. Without it the only way to reach the Mini App is a link
	// minted in a terminal, which is not a way in for anybody this is for.
	router := &telegram.Router{
		Bot:      &telegram.Bot{Token: token},
		AppURL:   strings.TrimSpace(*appURL),
		BotToken: token,
		Media:    library,
	}
	handler := app.Handler()

	switch {
	case *noBot:
		w.Human("  %s--no-bot: nothing answers /start, so links have to come "+
			"from%s\n", dim, reset)
		w.Human("  %s`quilzo telegram link`%s\n\n", dim, reset)
	case *appURL == "":
		return fmt.Errorf(
			"--app-url is required: it is the address the bot puts in the " +
				"button, and this program will not guess it from a request " +
				"header — that is how a link ends up pointing at somebody " +
				"else's host.\n" +
				"  Pass --no-bot to serve the Mini App without answering messages")
	case *webhook != "":
		secret := strings.TrimSpace(os.Getenv(strings.TrimSpace(*webhookSecret)))
		if *webhookSecret == "" || secret == "" {
			return fmt.Errorf(
				"a webhook needs a secret. Put one in an environment variable " +
					"and name it with --webhook-secret-env.\n" +
					"  Without it the endpoint acts on whatever is posted to " +
					"it by anybody who finds the path")
		}
		path := "/" + strings.TrimPrefix(*webhook, "/")
		mux := http.NewServeMux()
		mux.Handle(path, router.WebhookHandler(secret))
		mux.Handle("/", handler)
		handler = mux

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		endpoint := strings.TrimSuffix(*appURL, "/") + path
		err := router.Bot.SetWebhook(ctx, endpoint, secret)
		cancel()
		if err != nil {
			return err
		}
		w.Human("  %swebhook registered at %s%s\n\n", dim, endpoint, reset)
	default:
		// Polling, which needs no inbound reachability for the bot itself.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		derr := router.Bot.DeleteWebhook(ctx)
		cancel()
		if derr != nil {
			// Reported and not fatal: a token with no webhook set answers this
			// happily, and a transient failure here should not stop the server.
			w.Human("  %scould not clear an existing webhook: %v%s\n", dim, derr, reset)
		}
		go func() {
			perr := router.Poll(context.Background(), func(e error) {
				fmt.Fprintf(os.Stderr, "  %stelegram: %v%s\n", dim, e, reset)
			})
			if perr != nil {
				fmt.Fprintf(os.Stderr, "  %stelegram polling stopped: %v%s\n",
					dim, perr, reset)
			}
		}()
		w.Human("  %sanswering /start by long polling%s\n\n", dim, reset)
	}

	w.Human("%sthe Telegram Mini App%s is on %shttp://%s%s\n",
		bold, reset, bold, *addr, reset)
	w.Human("  %sit publishes through the same gates as everything else: a page%s\n", dim, reset)
	w.Human("  %sthat fails one is refused and the reason is shown to whoever%s\n", dim, reset)
	w.Human("  %scaused it%s\n\n", dim, reset)
	w.Human("  %spolicy: script-src 'none', framed only by Telegram's own origins%s\n",
		dim, reset)
	w.Human("  %sTelegram will only open this over https — put a tunnel or a%s\n", dim, reset)
	w.Human("  %sreverse proxy in front of it, then set the Mini App URL with%s\n", dim, reset)
	w.Human("  %s@BotFather%s\n\n", dim, reset)
	if *siteURL == "" {
		w.Human("  %sno --site-url, so a published page is shown as a path rather%s\n", dim, reset)
		w.Human("  %sthan a full address. Guessing it from a request header is how%s\n", dim, reset)
		w.Human("  %sa link ends up pointing at somebody else's host%s\n\n", dim, reset)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

// telegramCheck confirms the token before anybody spends an afternoon on the
// other possible cause.
func telegramCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	tokenFile := fs.String("token-file", "", "a file holding the bot token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	token, err := botToken(*tokenFile)
	if err != nil {
		return err
	}
	bot := &telegram.Bot{Token: token}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	me, err := bot.Me(ctx)
	if err != nil {
		return err
	}
	if w.JSON(me) {
		return nil
	}
	w.Human("the token belongs to %s@%s%s (%s, id %d)\n",
		bold, me.Username, reset, me.Name, me.ID)
	w.Human("\n  %snext: set the Mini App URL with @BotFather, then%s\n", dim, reset)
	w.Human("    quilzo telegram serve --site-url https://your.site\n")
	return nil
}

// telegramLink mints a link by hand, so the surface can be opened without a bot.
//
// Present because the alternative is that nobody can try this without first
// registering a bot, configuring a Mini App URL and putting an https tunnel in
// front of a local process. This is the same credential the bot would send.
func telegramLink(args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("link", flag.ContinueOnError)
	tokenFile := fs.String("token-file", "", "a file holding the bot token")
	at := fs.String("app-url", "http://127.0.0.1:8082/",
		"where the Mini App is served")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo telegram link <telegram-user-id>")
	}
	id, err := strconv.ParseInt(pos[0], 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("%q is not a Telegram user id", pos[0])
	}
	token, err := botToken(*tokenFile)
	if err != nil {
		return err
	}
	app := &telegram.App{BotToken: token}
	link, err := app.LinkFor(telegram.User{ID: id}, *at)
	if err != nil {
		return err
	}
	if w.JSON(map[string]string{"link": link}) {
		return nil
	}
	w.Human("%s\n", link)
	w.Human("\n  %sit works once and lasts %s%s\n",
		dim, telegram.LinkLifetime, reset)
	return nil
}

// chatPublisher is the write path the Mini App is given.
//
// # Why it publishes rather than saving a draft
//
// Because the person doing it has no other interface. Somebody publishing from a
// chat cannot open a review screen, so leaving the page in a draft nobody can
// reach would be a button that appears to work and does nothing.
//
// What it does not do is skip anything. The type gate and the accessibility gate
// both run, in the same order and with the same code as `quilzo publish`, and a
// refusal comes back with the gate's own words so the person reads which check
// said no rather than "could not publish".
type chatPublisher struct {
	root   string
	store  *store.Store
	tplDir string
	design string
}

func (c *chatPublisher) Designs() []telegram.Design {
	out := []telegram.Design{}
	for _, st := range starter.All() {
		out = append(out, telegram.Design{Name: st.Name, Look: st.Look})
	}
	return out
}

func (c *chatPublisher) Page(handle string) (map[string]any, bool, error) {
	pages, err := site.PagesAt(c.store, site.RefLive)
	if err != nil {
		// No live ref yet is not an error here: it is a store nobody has
		// published from, which is exactly the state the first page is written
		// in.
		return nil, false, nil
	}
	body, found := pages[handle].(map[string]any)
	return body, found, nil
}

func (c *chatPublisher) Save(handle string, body map[string]any,
	author, message string) (string, error) {

	pages, err := site.PagesAt(c.store, site.RefDraft)
	if err != nil {
		if c.store.GetRef(site.RefDraft) != "" {
			// A draft ref that will not load is a corrupt store, and starting
			// from empty here would commit a one-page draft over it.
			return "", fmt.Errorf("the draft could not be read")
		}
		pages = map[string]any{}
	}
	pages[handle] = body

	// The same gate as every other write surface.
	types, err := gateWrite(c.root, pages)
	if err != nil {
		return "", err
	}
	commit, err := site.SaveDraftFrom(c.store, pages, message, author,
		c.store.GetRef(site.RefDraft))
	if err != nil {
		return "", err
	}
	if err := types.Save(); err != nil {
		return "", err
	}

	// The accessibility gate, over the whole draft, rendered the way readers
	// see it. Refusing here is the point of the feature: this is the surface
	// where nobody reviewed the page before it went out.
	reports, err := checkAccessibility(c.root, c.store, commit, c.tplDir)
	if err != nil {
		return "", err
	}
	var blocking []string
	for _, report := range reports {
		for _, f := range report.Findings {
			if f.Severity == "blocking" {
				blocking = append(blocking, report.Page+": "+f.Detail)
			}
		}
	}
	if len(blocking) > 0 {
		return "", fmt.Errorf("%s", strings.Join(blocking, " · "))
	}

	if _, err := site.Publish(c.store, commit); err != nil {
		return "", err
	}
	record(c.root, audit.Record{
		Action: "telegram.publish", Resource: "/" + handle,
		Outcome: audit.Success, Principal: author, Kind: audit.KindHuman,
	})

	if handle == "index" {
		return "/", nil
	}
	return "/" + handle, nil
}

// chatMedia is the library, wired for the bot.
//
// # Why an owner is carried and then mostly ignored
//
// The library is content-addressed and shared: the same photograph sent by two
// people is one file, because its name is the hash of its bytes. So there is no
// per-person directory to put anything in, and `Recent` filters by who uploaded
// rather than by where it lives.
//
// That is a real design consequence worth stating rather than hiding. Two people
// who send the same image share it, and either of them describing it describes
// it for both. For a single-operator installation — which is what this is —
// that is deduplication working. For a multi-tenant one it would be a leak of
// the fact that somebody else has the same file, and this is not that yet.
type chatMedia struct {
	root string
	lib  *medialib.Library
	cfg  *config.Config
}

func (m *chatMedia) Save(owner, name string, body []byte,
	alt string) (string, string, error) {

	// Accepted the same way an upload is: the bytes decide the format, the
	// pixel count is bounded, and a refusal explains itself. A file that
	// arrived over the network is still a file.
	file, err := media.Accept(name, body, time.Now())
	if err != nil {
		return "", "", err
	}
	file.Alt = strings.TrimSpace(alt)
	file.Source = "telegram:" + owner

	// The same optimisation an uploaded image gets, from the same settings.
	// A photograph out of a phone is several megabytes and a page does not
	// need it.
	if file.Kind == media.Image {
		opt, oerr := media.Optimise(file.Format, body, media.Options{
			MaxWidth:    m.cfg.Int("media.max_width"),
			MaxHeight:   m.cfg.Int("media.max_height"),
			JPEGQuality: m.cfg.Int("media.jpeg_quality"),
			WebP:        m.cfg.Bool("media.webp"),
		})
		if oerr == nil && len(opt.Body) > 0 && len(opt.Body) < len(body) {
			// Re-accepted, because optimising produced different bytes and the
			// id is the hash of the bytes. Trusting the first record would
			// store one file under another file's name.
			reaccepted, rerr := media.Accept(name, opt.Body, time.Now())
			if rerr == nil {
				reaccepted.Alt = file.Alt
				reaccepted.Source = file.Source
				file, body = reaccepted, opt.Body
			}
		}
	}

	if err := m.lib.Put(file, body); err != nil {
		return "", "", err
	}
	record(m.root, audit.Record{
		Action: "telegram.media", Resource: "/" + file.ID,
		Outcome: audit.Success, Principal: owner, Kind: audit.KindHuman,
	})
	return file.ID, string(file.Kind), nil
}

func (m *chatMedia) Describe(id, alt string) error {
	file, body, err := m.lib.Get(id)
	if err != nil {
		return err
	}
	if strings.TrimSpace(alt) == "" {
		return fmt.Errorf("a description cannot be empty")
	}
	file.Alt = strings.TrimSpace(alt)
	// Put again with the same bytes. The id is the hash of the content, so this
	// rewrites the record beside it rather than storing a second copy.
	return m.lib.Put(file, body)
}

func (m *chatMedia) Recent(owner string, limit int) []telegram.StoredFile {
	all, err := m.lib.List()
	if err != nil {
		return nil
	}
	want := "telegram:" + owner
	out := []telegram.StoredFile{}
	for _, f := range all {
		if f.Source != want {
			continue
		}
		out = append(out, telegram.StoredFile{
			ID: f.ID, Kind: string(f.Kind), Name: f.Name, Alt: f.Alt,
			Width: f.Width, Height: f.Height,
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// Draft returns the working copy and the commit it was read at.
//
// The base travels out and back because the draft ref is one ref for the whole
// store: two people editing their own pages at the same time are two writers
// with the same parent, and without it the second write silently discards the
// first. Found by the source-walking test that refuses a write surface which
// does not compare and swap.
func (c *chatPublisher) Draft(handle string) (map[string]any, string, error) {
	base := c.store.GetRef(site.RefDraft)
	pages, err := site.PagesAt(c.store, site.RefDraft)
	if err != nil {
		if base != "" {
			return nil, "", fmt.Errorf("the draft could not be read")
		}
		// No draft ref at all is the state a first page is written in.
		return map[string]any{}, "", nil
	}
	body, found := pages[handle].(map[string]any)
	if !found {
		return map[string]any{}, base, nil
	}
	// A copy, because this is the decoded tree other requests are reading and
	// the editor is about to write into what it gets back.
	out := make(map[string]any, len(body))
	for k, v := range body {
		out[k] = v
	}
	return out, base, nil
}

// Keep writes the working copy, gated and compare-and-swapped.
//
// Not published. Somebody editing wants their unfinished sentence in a draft,
// and somebody visiting the site wants the last thing that was finished — so
// this moves the draft ref and nothing else.
func (c *chatPublisher) Keep(handle string, body map[string]any,
	author, message, base string) error {

	pages, err := site.PagesAt(c.store, site.RefDraft)
	if err != nil {
		if c.store.GetRef(site.RefDraft) != "" {
			return fmt.Errorf("the draft could not be read")
		}
		pages = map[string]any{}
	}
	pages[handle] = body

	// The same gate as every other write surface. Sections are content, and
	// content is typed.
	types, err := gateWrite(c.root, pages)
	if err != nil {
		return err
	}
	if _, err := site.SaveDraftFrom(c.store, pages, message, author, base); err != nil {
		var conflict *site.Conflict
		if errors.As(err, &conflict) {
			return fmt.Errorf(
				"somebody else wrote to this store while you were editing, so " +
					"this was not saved rather than quietly replacing what they " +
					"did. Open the editor again — your page is as they left it, " +
					"and you can redo your change on top")
		}
		return err
	}
	return types.Save()
}
