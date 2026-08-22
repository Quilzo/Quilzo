package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
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

	app := &telegram.App{
		BotToken:   token,
		Spender:    telegram.NewMemory(),
		Stylesheet: d.Stylesheet,
		SiteURL:    strings.TrimSpace(*siteURL),
		Publisher: &chatPublisher{
			root: root, store: s, tplDir: *tplDir, design: *design,
		},
	}

	// Recorded before the listener opens, not after it closes. This is the
	// moment a writable surface reachable from a billion accounts came into
	// existence, and a record written at shutdown is a record missing from
	// every process that was killed rather than stopped.
	record(root, resolveCaller(root, "").auditRecord("telegram.serve", "/",
		audit.Success, map[string]string{"addr": *addr, "design": *design}))

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
		Handler:           app.Handler(),
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
