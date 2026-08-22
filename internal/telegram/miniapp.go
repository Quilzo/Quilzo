package telegram

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The Mini App: publishing a page from inside a Telegram chat.
//
// # Why this surface exists separately
//
// Telegram is building a publishing route for a billion accounts, where a prompt
// produces markup and the platform serves it. The half that is not solved there
// is what happens to the markup in between, and this is that half offered as
// something a person can actually open: tap a button in a chat, get a page,
// published through the same gates as everything else in this program.
//
// It is its own server rather than a route on the admin or the public site,
// because it has a different exposure and therefore needs a different policy.
// The admin is loopback and script-free. The public site is anonymous and
// read-only. This is authenticated, writable, and framed by somebody else's
// client — three properties none of the others have, and mixing it into either
// would mean widening that one's policy to cover this one's needs.
//
// # Why it has no script either
//
// Telegram's own SDK is optional. Everything here is a form, so the page works
// with script-src 'none' — on the one surface in this program where a stranger's
// content is being composed, which is exactly where that property is worth most.
// See link.go for how the credential arrives without JavaScript reading a URL
// fragment.
//
// # What it will not do
//
// It does not accept HTML. A field is text and lands in a template that cannot
// execute, which is the whole point: this is the surface a hostile user reaches,
// and the answer to "what if they paste a script tag" should be structural
// rather than a filter somebody has to maintain.

// draft is what somebody typed, carried back to them when a gate refuses.
//
// # Why this exists
//
// It did not, and the omission was the worst thing about this surface. A gate
// refusing is the *likeliest* outcome for somebody's first page — that is what
// the gate is for — and the form was rendered fresh each time, so being refused
// meant retyping everything. A checker that costs you your work is a checker
// people learn to route around, which is the one outcome the gate exists to
// prevent.
//
// So the values come back. Found by trying to photograph the refusal screen for
// a submission and noticing there was nothing in it.
type draft struct {
	Title  string
	Lead   string
	Body   string
	Design string
}

// draftFrom reads what was submitted, whether or not it was accepted.
func draftFrom(r *http.Request) draft {
	return draft{
		Title:  strings.TrimSpace(r.FormValue("title")),
		Lead:   strings.TrimSpace(r.FormValue("lead")),
		Body:   r.FormValue("body"),
		Design: strings.TrimSpace(r.FormValue("design")),
	}
}

// Design is a look somebody can choose, in the terms they would choose it in.
type Design struct {
	Name string
	// Look is a sentence about the appearance, because "landing" says what the
	// page does and nothing about what it looks like.
	Look string
}

// Publisher is everything this surface needs from the rest of the program.
//
// An interface, so this package does not reach into the store, the schema, the
// gates or the publish path — and so the whole surface is testable without any
// of them. The host wires it, which is also where the authority to publish is
// decided rather than assumed here.
type Publisher interface {
	// Page returns what this handle has published, if anything, so somebody
	// arriving a second time edits rather than starts again.
	Page(handle string) (map[string]any, bool, error)
	// Save writes the page and publishes it, returning the path a reader can
	// use. It runs the same gates as every other write: if it refuses, the
	// reason is shown to the person who caused it.
	Save(handle string, body map[string]any, author, message string) (string, error)
	// Designs lists what may be chosen.
	Designs() []Design
}

// App serves the Mini App.
type App struct {
	// BotToken keys every signature. Empty means nothing verifies, and every
	// request is refused rather than waved through.
	BotToken string
	// Spender records single-use links. Nil means links are refused; see
	// Memory, and read its comment about running more than one process.
	Spender Spender
	// Publisher is the write path. Nil means the surface is read-only and says
	// so, rather than offering a button that fails.
	Publisher Publisher
	// Stylesheet is served at /app.css so this looks like the sites it makes.
	Stylesheet string
	// SiteURL is where published pages can be read, used to show somebody
	// their own page afterwards. Empty means the path is shown without an
	// origin, which is honest rather than guessed from a request header.
	SiteURL string
	// Now is the clock, injectable for tests.
	Now func() time.Time
}

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Handler routes the Mini App.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/app.css", a.stylesheet)
	mux.HandleFunc("/terms", a.terms)
	mux.HandleFunc("/privacy", a.privacy)
	mux.HandleFunc("/health", a.health)
	mux.HandleFunc("/launch", a.launch)
	mux.HandleFunc("/publish", a.publish)
	mux.HandleFunc("/", a.open)
	return a.headers(mux)
}

// headers sets this surface's policy.
//
// # Why frame-ancestors is not 'none' here
//
// Everywhere else in this program it is, and that is right: a page nobody should
// frame should say so. A Mini App is framed by definition — Telegram's web
// client loads it in an iframe — so 'none' would mean the feature does not work
// in a browser at all. The answer is not to drop the directive but to name the
// two origins that may do it, which is a narrower policy than most sites manage
// and much narrower than leaving it out.
func (a *App) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", strings.Join([]string{
			"default-src 'none'",
			// No script, on the surface where it would matter most.
			"script-src 'none'",
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data:",
			"form-action 'self'",
			"base-uri 'none'",
			"frame-ancestors https://web.telegram.org https://telegram.org",
		}, "; "))
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// A credential travels in this URL, so it must not be cached by
		// anything between here and the reader.
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (a *App) stylesheet(w http.ResponseWriter, r *http.Request) {
	if a.Stylesheet == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(a.Stylesheet))
}

// open is the arrival: a signed link in the query string, verified and spent.
func (a *App) open(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	user, err := VerifyLink(r.URL.Query(), a.BotToken, a.Spender, a.now())
	if err != nil {
		a.refuse(w, http.StatusForbidden, "This link cannot be used", err.Error(),
			"Open the bot and tap the button again. A link works once and "+
				"lasts a quarter of an hour, because a link in a chat is a "+
				"link that gets forwarded.")
		return
	}
	a.form(w, user, "", "", draft{})
}

// launch is the other arrival: initData posted by Telegram's SDK.
//
// Offered for anybody running this as a conventional Mini App with the SDK on
// the page. It is a POST because initData is a credential and a credential in a
// query string ends up in logs.
func (a *App) launch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.refuse(w, http.StatusMethodNotAllowed, "This address takes a post",
			"initData is a credential, and a credential in a URL ends up in "+
				"a log or a referrer header.", "")
		return
	}
	if err := r.ParseForm(); err != nil {
		a.refuse(w, http.StatusBadRequest, "That form could not be read", err.Error(), "")
		return
	}
	user, err := VerifyInitData(r.FormValue("initData"), a.BotToken, a.now())
	if err != nil {
		a.refuse(w, http.StatusForbidden, "This launch cannot be verified",
			err.Error(), "")
		return
	}
	a.form(w, user, "", "", draft{})
}

// publish writes the page.
func (a *App) publish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.refuse(w, http.StatusMethodNotAllowed, "This address takes a post", "", "")
		return
	}
	if err := r.ParseForm(); err != nil {
		a.refuse(w, http.StatusBadRequest, "That form could not be read", err.Error(), "")
		return
	}
	user, err := VerifyGrant(r.FormValue("grant"), a.BotToken, a.now())
	if err != nil {
		a.refuse(w, http.StatusForbidden, "This form cannot be accepted",
			err.Error(), "Open the bot and tap the button again.")
		return
	}
	if a.Publisher == nil {
		a.refuse(w, http.StatusServiceUnavailable, "Publishing is not wired up",
			"This build has no write path configured.", "")
		return
	}

	typed := draftFrom(r)
	if typed.Title == "" {
		a.form(w, user, "", "A page needs a title. It is the first thing a "+
			"screen reader announces, and this refuses to publish a page "+
			"without one.", typed)
		return
	}
	title := typed.Title

	body := map[string]any{
		"title":  title,
		"layout": "page",
		"footer": "Published from Telegram by " + user.Label() + ".",
	}
	if lead := strings.TrimSpace(r.FormValue("lead")); lead != "" {
		body["hero"] = map[string]any{"style": "center", "lead": lead}
	} else {
		body["hero"] = map[string]any{"style": "center"}
	}
	if paragraphs := paragraphsOf(r.FormValue("body")); len(paragraphs) > 0 {
		body["sections"] = []any{
			map[string]any{"prose": map[string]any{"paragraphs": paragraphs}},
		}
	}
	if design := strings.TrimSpace(r.FormValue("design")); design != "" {
		body["design"] = design
	}

	where, err := a.Publisher.Save(user.Handle(), body, user.Label(),
		"publish "+user.Handle()+" from Telegram")
	if err != nil {
		// The gate's own words, not a summary of them — and everything they
		// typed, back in the form. Somebody refused for a missing alt
		// attribute needs to read that and then fix it, not retype the page.
		a.form(w, user, "", err.Error(), typed)
		return
	}
	a.published(w, user, where)
}

// paragraphsOf splits a textarea into paragraphs.
//
// A list rather than one rich-text field, because a single field would have to
// be emitted unescaped to render as markup — and this is the surface a hostile
// user reaches. Paragraphs are text, escaped, and nothing in them can become an
// element.
func paragraphsOf(raw string) []any {
	var out []any
	for _, block := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n\n") {
		if trimmed := strings.TrimSpace(block); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// -- the pages, which are small enough to be written out ---------------------

func (a *App) form(w http.ResponseWriter, user User, notice, problem string, d draft) {
	grant, err := NewGrant(user, a.BotToken, a.now())
	if err != nil {
		a.refuse(w, http.StatusInternalServerError, "This form cannot be issued",
			err.Error(), "")
		return
	}

	existing := ""
	if a.Publisher != nil {
		if body, found, perr := a.Publisher.Page(user.Handle()); perr == nil && found {
			if t, ok := body["title"].(string); ok {
				existing = t
			}
		}
	}

	var b strings.Builder
	b.WriteString(`<main class="wrap"><div class="section">`)
	fmt.Fprintf(&b, `<div class="section-head"><p class="eyebrow">%s</p><h1>Publish a page</h1>`,
		esc(user.Label()))
	if existing != "" {
		fmt.Fprintf(&b, `<p class="lead">You already have a page called %s. `+
			`Publishing again replaces it, and the previous version stays `+
			`addressable — nothing here is overwritten.</p>`, esc(existing))
	} else {
		b.WriteString(`<p class="lead">Text only. There is no markup field, ` +
			`because the template this renders through cannot execute anything ` +
			`and a field that accepted HTML would be the one exception.</p>`)
	}
	b.WriteString(`</div>`)

	if problem != "" {
		fmt.Fprintf(&b, `<div class="notice notice-critical"><p><strong>`+
			`Not published.</strong></p><p>%s</p></div>`, esc(problem))
	}
	if notice != "" {
		fmt.Fprintf(&b, `<div class="notice"><p>%s</p></div>`, esc(notice))
	}

	fmt.Fprintf(&b, `<form class="stacked" method="post" action="/publish">`+
		`<input type="hidden" name="grant" value="%s">`, esc(grant))

	fmt.Fprintf(&b, `<p class="field"><label for="f-title">Title</label>`+
		`<input id="f-title" name="title" type="text" required maxlength="120" `+
		`value="%s"></p>`, esc(d.Title))
	fmt.Fprintf(&b, `<p class="field"><label for="f-lead">One line about it</label>`+
		`<input id="f-lead" name="lead" type="text" maxlength="240" value="%s">`+
		`<span class="hint">Optional. Appears under the title.</span></p>`,
		esc(d.Lead))
	fmt.Fprintf(&b, `<p class="field"><label for="f-body">The page</label>`+
		`<textarea id="f-body" name="body" rows="8">%s</textarea>`+
		`<span class="hint">A blank line starts a new paragraph.</span></p>`,
		esc(d.Body))

	if a.Publisher != nil {
		if designs := a.Publisher.Designs(); len(designs) > 0 {
			b.WriteString(`<p class="field"><label for="f-design">Design</label>` +
				`<select id="f-design" name="design">`)
			// `look` rather than `d`, which is the draft this function was
			// given — a loop variable that shadows it would have silently
			// compared a design against itself.
			for _, look := range designs {
				selected := ""
				if look.Name == d.Design {
					selected = ` selected`
				}
				fmt.Fprintf(&b, `<option value="%s"%s>%s — %s</option>`,
					esc(look.Name), selected, esc(look.Name), esc(look.Look))
			}
			b.WriteString(`</select></p>`)
		}
	}

	b.WriteString(`<p><button class="btn" type="submit">Publish</button></p></form>`)
	b.WriteString(`<p class="muted">Before this appears anywhere it is checked: ` +
		`a page with an unlabelled image, a skipped heading level or a colour ` +
		`pair below the readable ratio is refused rather than published with a ` +
		`warning. If yours is refused you will see exactly which check said so.</p>`)
	b.WriteString(`<p class="muted"><a href="/terms">Terms of use</a> · ` +
		`<a href="/privacy">What is stored</a></p>`)
	b.WriteString(`</div></main>`)

	a.page(w, http.StatusOK, "Publish a page", b.String())
}

func (a *App) published(w http.ResponseWriter, user User, where string) {
	full := where
	if a.SiteURL != "" {
		full = strings.TrimSuffix(a.SiteURL, "/") + where
	}
	var b strings.Builder
	b.WriteString(`<main class="wrap"><div class="section">`)
	b.WriteString(`<div class="section-head"><p class="eyebrow">Published</p>` +
		`<h1>It is live</h1>`)
	fmt.Fprintf(&b, `<p class="lead">Your page is at <a href="%s">%s</a>.</p></div>`,
		esc(full), esc(full))
	b.WriteString(`<div class="notice"><p>Publishing moved one pointer. ` +
		`Every previous version is still addressable by its own hash, so ` +
		`taking this down or putting it back is a pointer move rather than a ` +
		`restore.</p></div>`)
	b.WriteString(`<p class="muted">To publish again, tap the button in the bot ` +
		`for a new link. The one you arrived with has been spent, which is what ` +
		`stops a forwarded message being a way in.</p>`)
	b.WriteString(`</div></main>`)
	a.page(w, http.StatusOK, "Published", b.String())
}

func (a *App) refuse(w http.ResponseWriter, code int, heading, detail, next string) {
	var b strings.Builder
	b.WriteString(`<main class="wrap"><div class="section">`)
	fmt.Fprintf(&b, `<div class="section-head"><h1>%s</h1>`, esc(heading))
	if detail != "" {
		fmt.Fprintf(&b, `<p class="lead">%s</p>`, esc(detail))
	}
	b.WriteString(`</div>`)
	if next != "" {
		fmt.Fprintf(&b, `<div class="notice"><p>%s</p></div>`, esc(next))
	}
	b.WriteString(`</div></main>`)
	a.page(w, code, heading, b.String())
}

// page wraps a body in the document every response shares.
//
// Written out rather than templated because there is one of them, and a template
// engine for one document is a dependency on indirection. It carries the same
// things every page in this program carries: a language, a title, a skip link
// and a stylesheet from this origin.
func (a *App) page(w http.ResponseWriter, code int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>%s — Quilzo</title>
<link rel="stylesheet" href="/app.css">
</head>
<body>
<a class="skip" href="#main">Skip to main content</a>
%s
</body>
</html>
`, esc(title), body)
}

// esc escapes for HTML text and attribute contexts.
//
// One function, applied to everything, including values that "cannot" contain
// anything dangerous. A first name comes from Telegram and Telegram does not
// promise it is not markup.
func esc(s string) string { return html.EscapeString(s) }

// LinkFor builds the URL a bot should send, given where this app is served.
//
// Here rather than in the bot client because the app knows what its own query
// string means, and a bot that assembled it would be a second place that has to
// agree about the parameter names.
func (a *App) LinkFor(user User, appURL string) (string, error) {
	query, err := NewLink(user, a.BotToken, a.now())
	if err != nil {
		return "", err
	}
	base, err := url.Parse(appURL)
	if err != nil {
		return "", fmt.Errorf("%q is not a usable address for the Mini App: %w",
			appURL, err)
	}
	if base.Scheme != "https" && base.Hostname() != "127.0.0.1" && base.Hostname() != "localhost" {
		return "", fmt.Errorf(
			"a Mini App has to be served over https; %q is not. Telegram will "+
				"not open it and the credential in the link would travel in "+
				"clear", appURL)
	}
	base.RawQuery = query
	return base.String(), nil
}

// -- the pages a listing requires -------------------------------------------

// The Telegram Apps Center asks for terms of use and a privacy policy before it
// will list an app, and the request is a reasonable one: a surface that accepts
// somebody's words and puts them on the public internet should say what it does
// with them before they type.
//
// They are written out here rather than linked to a document somebody hosts
// separately, so they cannot go missing from a deployment, and so they describe
// this program rather than a template. Both are short because the honest version
// is short: this stores a user id and what somebody typed, and it has nothing
// else to disclose.

func (a *App) terms(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	b.WriteString(`<main id="main" class="wrap"><div class="section">`)
	b.WriteString(`<div class="section-head"><p class="eyebrow">Terms of use</p>` +
		`<h1>What you are agreeing to</h1>` +
		`<p class="lead">Three things, and none of them are unusual.</p></div>`)
	b.WriteString(`<ol class="steps">` +
		`<li><div class="step-body"><h2>Publish what you have the right to publish</h2>` +
		`<p>Your words, or words you are allowed to use. Not somebody else's ` +
		`writing, not impersonation of a person or an organisation, and nothing ` +
		`unlawful where it is read.</p></div></li>` +
		`<li><div class="step-body"><h2>What you publish is public</h2>` +
		`<p>That is what publishing a page means. It can be read by anyone with ` +
		`the address, indexed by search engines, and archived by services that ` +
		`do that. None of this is reversible once it has happened, whatever ` +
		`happens to the page afterwards.</p></div></li>` +
		`<li><div class="step-body"><h2>It can be taken down</h2>` +
		`<p>By you, and by whoever runs this installation — including without ` +
		`notice where something is unlawful or is being used to deceive people. ` +
		`Taking a page down moves a pointer; earlier versions remain stored and ` +
		`addressable, which is how a removal can be shown to have happened.</p>` +
		`</div></li></ol>`)
	b.WriteString(`<div class="notice"><p>There is no warranty. This is ` +
		`software offered as it is, under the AGPL-3.0-or-later licence, and the people ` +
		`running it are not liable for what it does. If that is not acceptable ` +
		`for what you are publishing, publish it somewhere with a contract.</p>` +
		`</div>`)
	b.WriteString(`<p class="muted">Whoever operates this installation is the ` +
		`party you are dealing with. Quilzo is the software they are running.</p>`)
	b.WriteString(`</div></main>`)
	a.page(w, http.StatusOK, "Terms of use", b.String())
}

func (a *App) privacy(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	b.WriteString(`<main id="main" class="wrap"><div class="section">`)
	b.WriteString(`<div class="section-head"><p class="eyebrow">Privacy</p>` +
		`<h1>What is stored</h1>` +
		`<p class="lead">Your Telegram user id, and whatever you typed into the ` +
		`page. That is the whole list.</p></div>`)

	b.WriteString(`<div class="section-head"><h2>Why the id and not the ` +
		`username</h2></div><div class="prose narrow">` +
		`<p>A username can be released and taken by somebody else. A store keyed ` +
		`on one would hand a stranger your pages the day you renamed, so pages ` +
		`are keyed on the numeric id, which does not move.</p></div>`)

	b.WriteString(`<div class="section-head"><h2>What is not stored</h2></div>` +
		`<ul class="chips"><li class="chip">no phone number</li>` +
		`<li class="chip">no contacts</li><li class="chip">no message history</li>` +
		`<li class="chip">no location</li><li class="chip">no cookies</li>` +
		`<li class="chip">no analytics</li><li class="chip">no advertising</li></ul>` +
		`<div class="prose narrow"><p>Nothing is shared with anyone. There is no ` +
		`third party to share it with: a published page loads no script and ` +
		`fetches nothing from another origin, so reading one does not tell ` +
		`anybody but this server that you did.</p></div>`)

	b.WriteString(`<div class="section-head"><h2>How long</h2></div>` +
		`<div class="prose narrow">` +
		`<p>Content here is immutable and addressed by the hash of its own bytes, ` +
		`so publishing a change writes a new version rather than replacing one. ` +
		`Taking a page down stops it being served; earlier versions stay stored ` +
		`until whoever runs this installation removes them. That is the honest ` +
		`answer, and it is a longer one than "deleted immediately" — which is ` +
		`what a system with backups would be saying if it claimed otherwise.</p>` +
		`<p>Ask whoever runs this installation to remove your pages and they ` +
		`can. There is no automated route to it, because a system that could ` +
		`delete on request without a person deciding is a system somebody else ` +
		`can aim at your pages.</p></div>`)

	b.WriteString(`<div class="notice"><p>Telegram's own handling of your ` +
		`account is Telegram's, and is covered by their privacy policy rather ` +
		`than by this one. This app sees only what Telegram signs and sends: an ` +
		`id, a first name, and a username if you have one.</p></div>`)
	b.WriteString(`</div></main>`)
	a.page(w, http.StatusOK, "Privacy", b.String())
}

// health answers a monitor without answering a stranger's questions.
//
// Static, and deliberately says nothing about the store, the version, the
// configuration or whether a token is present. A health endpoint is a public
// URL, and every fact on it is a fact somebody probing has for free.
func (a *App) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}
