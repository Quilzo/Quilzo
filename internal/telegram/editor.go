package telegram

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/section"
)

// The editor: a whole page, not one form.
//
// # What changed and why
//
// The first version of this surface was a single form that replaced the page
// each time. That is the right shape for a first page and the wrong shape for
// anything somebody comes back to: it cannot hold a gallery, it cannot reorder
// anything, and it throws away what was there.
//
// So the page is a draft now, edited over as many visits as somebody likes and
// published when they say. The moves are the ones internal/section already
// implements, which is why this file is mostly screens — the arithmetic of
// inserting at an index and the rule that only existing leaves may be written
// are decided once, in one package, for the browser and the terminal and this.
//
// # Why colour is a choice from a palette rather than a colour picker
//
// The obvious feature is a hex field per section. It is also how you get a site
// with unreadable text, and this program refuses to publish one — so the field
// would mostly produce a refusal somebody cannot act on, because the ratio that
// failed involves a token they never saw.
//
// What is offered instead is the palette: the tones the operator's theme
// defines, every pair of which has already been checked in both colour schemes.
// A person picks *quiet*, *raised*, *accent* rather than #8a8a8a, and every
// combination they can reach is one that publishes. That is a smaller freedom
// and a real one, which is the trade this whole program keeps making.
//
// # Why there is still no markup field
//
// Because this is the surface a stranger reaches. Everything typed here is text
// landing in a template that cannot execute, and adding one field that accepted
// HTML would be the single exception that makes the property untrue.

// The section catalogue, the moves and the field walk all come from
// internal/section — the same code the browser admin and the terminal use. That
// is deliberate: three surfaces performing "insert at index" three ways is three
// chances for one of them to be subtly wrong, and this is the surface where the
// person doing it has no other way to check.

// Draft is the working copy the editor reads and writes.
//
// Separate from Publisher's Page, which is what is live: somebody editing wants
// to see what they last typed, and somebody visiting the site wants to see what
// was last published. Conflating those means an unfinished sentence is on the
// internet.
// # Why Keep takes a base and Draft returns one
//
// The draft ref is one ref for the whole store, so two people editing their own
// pages at the same time are two writers with the same parent. Without the base
// travelling out and back, the second write takes whatever the draft is *now* as
// its parent and the first person's edit disappears with no error anywhere.
//
// That was a real bug, found by the source-walking test in cmd/quilzo that
// refuses a write surface which does not compare and swap. It is the reason this
// interface is shaped awkwardly: the commit somebody read has to be the commit
// they write against, and an interface that hid it would hide the race.
//
// The method is not called SaveDraft, because it is not the store's SaveDraft —
// it is a request to the host, which does the type gate and the compare-and-swap
// where those belong.
type Drafts interface {
	// Draft returns the working copy and the commit it was read at. An empty
	// base means there is no draft yet, which is the state a first page is
	// written in.
	Draft(handle string) (body map[string]any, base string, err error)
	// Keep writes the working copy without publishing it, against the base the
	// caller read. A base that is no longer current is a conflict rather than
	// an overwrite.
	Keep(handle string, body map[string]any, author, message, base string) error
}

// tones are the section backgrounds somebody may choose.
//
// The list is closed and every entry is a class the shipped stylesheet defines
// from theme tokens — so each one has already been through the contrast check in
// both colour schemes. A free-form colour could not make that promise.
var tones = []struct{ Value, Label string }{
	{"", "Plain"},
	{"tone-raised", "Raised"},
	{"tone-contrast", "Contrast"},
	{"tone-accent", "Accent"},
	{"tone-primary", "Bold"},
}

// heroStyles are the shapes the top of a page can take.
var heroStyles = []struct{ Value, Label string }{
	{"center", "Centred"},
	{"plain", "Plain, no panel"},
	{"bold", "Filled panel"},
}

// heroSurfaces are the drawn backgrounds, none of which is an image.
//
// Both are CSS over the theme's own tokens, so they cost no bytes, need no
// upload, and recolour with the palette instead of fighting it.
var heroSurfaces = []struct{ Value, Label string }{
	{"", "Flat"},
	{"surface-wash", "Washed"},
	{"surface-grid", "Grid"},
}

// editor is the home screen: what the page is, what is on it, and what to do.
func (a *App) editor(w http.ResponseWriter, user User, notice, problem string) {
	grant, err := NewGrant(user, a.BotToken, a.now())
	if err != nil {
		a.refuse(w, http.StatusInternalServerError, "This form cannot be issued",
			err.Error(), "")
		return
	}
	body, base := a.draftOf(user)

	var b strings.Builder
	b.WriteString(`<main id="main" class="wrap"><div class="section">`)
	fmt.Fprintf(&b, `<div class="section-head"><p class="eyebrow">%s</p>`+
		`<h1>Your page</h1></div>`, esc(user.Label()))

	if problem != "" {
		fmt.Fprintf(&b, `<div class="notice notice-critical"><p><strong>`+
			`Not published.</strong></p><p>%s</p></div>`, esc(problem))
	}
	if notice != "" {
		fmt.Fprintf(&b, `<div class="notice"><p>%s</p></div>`, esc(notice))
	}

	// The top of the page.
	fmt.Fprintf(&b, `<form class="stacked" method="post" action="/save">`+
		`<input type="hidden" name="grant" value="%s">`+
		`<input type="hidden" name="base" value="%s">`+
		`<input type="hidden" name="do" value="head">`, esc(grant), esc(base))
	fmt.Fprintf(&b, `<p class="field"><label for="f-title">Title</label>`+
		`<input id="f-title" name="title" type="text" required maxlength="120" `+
		`value="%s"></p>`, esc(text(body, "title")))

	hero := mapOf(body, "hero")
	fmt.Fprintf(&b, `<p class="field"><label for="f-lead">One line about it</label>`+
		`<input id="f-lead" name="lead" type="text" maxlength="240" value="%s">`+
		`<span class="hint">Appears under the title.</span></p>`,
		esc(text(hero, "lead")))
	b.WriteString(`<div class="grid grid-2">`)
	b.WriteString(choice("f-style", "style", "Shape", heroStyles, text(hero, "style")))
	b.WriteString(choice("f-surface", "surface", "Background", heroSurfaces,
		text(hero, "surface")))
	b.WriteString(`</div>`)
	b.WriteString(`<p><button class="btn btn-tonal" type="submit">Save the top</button></p></form>`)

	// The sections.
	b.WriteString(`<div class="section-head" style="margin-top:var(--space-7)">` +
		`<h2>Sections</h2><p class="lead">The order here is the order on the ` +
		`page.</p></div>`)
	a.sectionList(&b, grant, base, body)

	// What to do with it.
	fmt.Fprintf(&b, `<div class="actions" style="margin-top:var(--space-6)">`+
		`<a class="btn btn-outlined" href="/add?g=%s">Add a section</a>`+
		`<a class="btn btn-outlined" href="/media?g=%s">Your files</a>`+
		`<a class="btn btn-outlined" href="/look?g=%s">How it looks</a>`+
		`</div>`, esc(grant), esc(grant), esc(grant))

	fmt.Fprintf(&b, `<form method="post" action="/publish" `+
		`style="margin-top:var(--space-6)">`+
		`<input type="hidden" name="grant" value="%s">`+
		`<p><button class="btn btn-lg" type="submit">Publish</button></p></form>`,
		esc(grant))
	b.WriteString(`<p class="muted">Nothing is public until you press that. ` +
		`Before it goes out it is checked — an image with no description, a ` +
		`heading that skips a level, text too faint to read against its ` +
		`background — and refused rather than published with a warning.</p>`)
	b.WriteString(`<p class="muted"><a href="/terms">Terms of use</a> · ` +
		`<a href="/privacy">What is stored</a></p>`)
	b.WriteString(`</div></main>`)
	a.page(w, http.StatusOK, "Your page", b.String())
}

// draftOf returns the working copy and the commit it was read at.
func (a *App) draftOf(user User) (map[string]any, string) {
	if a.Drafts == nil {
		return map[string]any{}, ""
	}
	body, base, err := a.Drafts.Draft(user.Handle())
	if err != nil || body == nil {
		return map[string]any{}, base
	}
	return body, base
}

// sectionsOf reads what is on a page, in order.
func (a *App) sectionsOf(body map[string]any) []section.Placed {
	return section.On(body)
}

// sectionList draws what is on the page, with the moves.
func (a *App) sectionList(b *strings.Builder, grant, base string, body map[string]any) {
	placed := a.sectionsOf(body)
	if len(placed) == 0 {
		b.WriteString(`<div class="notice"><p>Nothing on the page yet. ` +
			`Adding a section writes a small piece of real content rather than ` +
			`an empty block, so you can see it and then replace what it ` +
			`says.</p></div>`)
		return
	}
	b.WriteString(`<div class="table-wrap"><table><thead><tr>` +
		`<th scope="col">Section</th><th scope="col">Order</th>` +
		`<th scope="col"></th></tr></thead><tbody>`)
	for i, s := range placed {
		b.WriteString(`<tr><th scope="row">`)
		fmt.Fprintf(b, `<code>%s</code>`, esc(s.Kind))
		if s.Label != "" {
			fmt.Fprintf(b, `<div class="hint">%s</div>`, esc(s.Label))
		}
		b.WriteString(`</th><td>`)
		if i > 0 {
			b.WriteString(move(grant, base, i, "up", "Up"))
		}
		if i < len(placed)-1 {
			b.WriteString(move(grant, base, i, "down", "Down"))
		}
		b.WriteString(`</td><td>`)
		fmt.Fprintf(b, `<a class="btn btn-quiet" href="/section?g=%s&amp;at=%d">Edit</a>`,
			esc(grant), i)
		b.WriteString(move(grant, base, i, "remove", "Remove"))
		b.WriteString(`</td></tr>`)
	}
	b.WriteString(`</tbody></table></div>`)
}

func move(grant, base string, at int, verb, label string) string {
	return fmt.Sprintf(`<form method="post" action="/arrange" class="inline">`+
		`<input type="hidden" name="grant" value="%s">`+
		`<input type="hidden" name="base" value="%s">`+
		`<input type="hidden" name="at" value="%d">`+
		`<input type="hidden" name="do" value="%s">`+
		`<button type="submit">%s</button></form>`,
		esc(grant), esc(base), at, esc(verb), esc(label))
}

// choice renders a select from a closed list.
func choice(id, name, label string, options []struct{ Value, Label string },
	current string) string {

	var b strings.Builder
	fmt.Fprintf(&b, `<p class="field"><label for="%s">%s</label>`+
		`<select id="%s" name="%s">`, esc(id), esc(label), esc(id), esc(name))
	for _, o := range options {
		selected := ""
		if o.Value == current {
			selected = ` selected`
		}
		fmt.Fprintf(&b, `<option value="%s"%s>%s</option>`,
			esc(o.Value), selected, esc(o.Label))
	}
	b.WriteString(`</select></p>`)
	return b.String()
}

// text reads a string field, and is the one place a missing key is not a panic.
func text(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func mapOf(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	out, _ := m[key].(map[string]any)
	return out
}

// -- the handlers ------------------------------------------------------------

// firstNonEmpty returns the first argument with something in it.
//
// The editor is several screens, so a value arrives as a form field on a post
// and as a query parameter on a link between them. One helper rather than the
// same two-line check in five handlers.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// grantOf verifies whichever way the grant arrived: a hidden field on a post, or
// a query parameter on a link between screens.
//
// The query form exists because this is a multi-screen editor and a link cannot
// carry a hidden field. It is the same signed, expiring credential either way,
// and it is never the single-use arrival link — see VerifyGrant for why those
// are distinguished rather than sharing a signature.
func (a *App) grantOf(r *http.Request) (User, string, error) {
	raw := r.FormValue("grant")
	if raw == "" {
		raw = r.URL.Query().Get("g")
	}
	user, err := VerifyGrant(raw, a.BotToken, a.now())
	return user, raw, err
}

// requireGrant is the guard every editor screen starts with.
func (a *App) requireGrant(w http.ResponseWriter, r *http.Request) (User, string, bool) {
	if err := r.ParseForm(); err != nil {
		a.refuse(w, http.StatusBadRequest, "That form could not be read",
			err.Error(), "")
		return User{}, "", false
	}
	user, grant, err := a.grantOf(r)
	if err != nil {
		a.refuse(w, http.StatusForbidden, "This session has ended", err.Error(),
			"Open the bot and tap the button again.")
		return User{}, "", false
	}
	if a.Drafts == nil {
		a.refuse(w, http.StatusServiceUnavailable, "Editing is not wired up",
			"This build has no working copy to edit.", "")
		return User{}, "", false
	}
	return user, grant, true
}

// keep hands the working copy to the host and returns to the editor.
//
// The base is whatever the form was drawn from, so a second editor working from
// a stale copy is told rather than silently winning. The host does the type gate
// and the compare-and-swap; this is the screen, not the write.
func (a *App) keep(w http.ResponseWriter, r *http.Request, user User,
	body map[string]any, message, notice string) {

	base := r.FormValue("base")
	if err := a.Drafts.Keep(user.Handle(), body, user.Label(), message, base); err != nil {
		a.editor(w, user, "", err.Error())
		return
	}
	a.editor(w, user, notice, "")
}

// save writes the top of the page.
func (a *App) save(w http.ResponseWriter, r *http.Request) {
	user, _, ok := a.requireGrant(w, r)
	if !ok {
		return
	}
	body, _ := a.draftOf(user)
	body["title"] = strings.TrimSpace(r.FormValue("title"))
	body["layout"] = "page"

	hero := mapOf(body, "hero")
	if hero == nil {
		hero = map[string]any{}
	}
	hero["lead"] = strings.TrimSpace(r.FormValue("lead"))
	hero["style"] = pick(r.FormValue("style"), heroStyles)
	hero["surface"] = pick(r.FormValue("surface"), heroSurfaces)
	body["hero"] = hero
	body["footer"] = "Published from Telegram by " + user.Label() + "."

	a.keep(w, r, user, body, "edit the top of "+user.Handle(), "Saved.")
}

// arrange moves or removes a section.
func (a *App) arrange(w http.ResponseWriter, r *http.Request) {
	user, _, ok := a.requireGrant(w, r)
	if !ok {
		return
	}
	body, _ := a.draftOf(user)
	at, _ := strconv.Atoi(r.FormValue("at"))

	var next map[string]any
	var err error
	switch r.FormValue("do") {
	case "up":
		next, err = section.Move(body, at, -1)
	case "down":
		next, err = section.Move(body, at, 1)
	case "remove":
		next, err = section.Remove(body, at)
	default:
		a.editor(w, user, "", "That is not something to do to a section.")
		return
	}
	if err != nil {
		a.editor(w, user, "", err.Error())
		return
	}
	a.keep(w, r, user, next, "rearrange "+user.Handle(), "Moved.")
}

// add offers the catalogue, then inserts.
func (a *App) add(w http.ResponseWriter, r *http.Request) {
	user, grant, ok := a.requireGrant(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		body, _ := a.draftOf(user)
		kind := strings.TrimSpace(r.FormValue("kind"))
		next, err := section.Insert(body, kind, len(section.On(body)))
		if err != nil {
			a.editor(w, user, "", err.Error())
			return
		}
		a.keep(w, r, user, next, "add a "+kind+" section to "+user.Handle(),
			"Added a "+kind+" section, with content in it so you can see where "+
				"it is. Edit it to say what you mean.")
		return
	}

	var b strings.Builder
	b.WriteString(`<main id="main" class="wrap"><div class="section">`)
	b.WriteString(`<div class="section-head"><p class="eyebrow">Add</p>` +
		`<h1>What goes on the page</h1>` +
		`<p class="lead">Each one arrives with real content rather than an ` +
		`empty block, so you can see where it landed and then replace what it ` +
		`says.</p></div>`)

	group := ""
	for _, k := range section.Kinds() {
		if k.Group != group {
			group = k.Group
			fmt.Fprintf(&b, `<h2 style="margin-top:var(--space-6)">%s</h2>`,
				esc(groupLabel(group)))
		}
		fmt.Fprintf(&b, `<div class="card"><h3>%s</h3><p>%s</p>`+
			`<form method="post" action="/add" class="inline">`+
			`<input type="hidden" name="grant" value="%s">`+
			`<input type="hidden" name="kind" value="%s">`+
			`<button class="btn btn-tonal" type="submit">Add %s</button>`+
			`</form></div>`,
			esc(k.Name), esc(k.Summary), esc(grant), esc(k.Name), esc(k.Name))
	}
	fmt.Fprintf(&b, `<p class="muted" style="margin-top:var(--space-6)">`+
		`<a href="/?g=%s">Back to your page</a></p>`, esc(grant))
	b.WriteString(`</div></main>`)
	a.page(w, http.StatusOK, "Add a section", b.String())
}

// groupLabel turns a catalogue group into a heading somebody reads.
func groupLabel(group string) string {
	switch group {
	case "telling":
		return "Saying something"
	case "data":
		return "Numbers and tables"
	case "media":
		return "Pictures, video and sound"
	case "closing":
		return "Finishing"
	}
	return group
}

// editSection is one section's fields, with a picker wherever a file belongs.
func (a *App) editSection(w http.ResponseWriter, r *http.Request) {
	user, grant, ok := a.requireGrant(w, r)
	if !ok {
		return
	}
	body, base := a.draftOf(user)
	at, _ := strconv.Atoi(firstNonEmpty(r.FormValue("at"), r.URL.Query().Get("at")))

	if r.Method == http.MethodPost {
		var next map[string]any
		var err error
		switch r.FormValue("do") {
		case "additem":
			next, err = section.AddItem(body, at, r.FormValue("list"))
		case "removeitem":
			i, _ := strconv.Atoi(r.FormValue("index"))
			next, err = section.RemoveItem(body, at, r.FormValue("list"), i)
		default:
			values := map[string]string{}
			for key, submitted := range r.Form {
				path, isValue := strings.CutPrefix(key, "v.")
				if !isValue || len(submitted) == 0 {
					continue
				}
				values[path] = submitted[0]
			}
			next, err = section.Apply(body, at, values)
		}
		if err != nil {
			a.editor(w, user, "", err.Error())
			return
		}
		if serr := a.Drafts.Keep(user.Handle(), next, user.Label(),
			"edit a section on "+user.Handle(), r.FormValue("base")); serr != nil {
			a.editor(w, user, "", serr.Error())
			return
		}
		// Back to the same section, because somebody editing one card is
		// usually about to edit the next.
		http.Redirect(w, r, fmt.Sprintf("/section?g=%s&at=%d",
			urlEscape(grant), at), http.StatusSeeOther)
		return
	}

	fields, err := section.Fields(body, at)
	if err != nil {
		a.editor(w, user, "", err.Error())
		return
	}
	kind, _ := section.KindAt(body, at)

	var b strings.Builder
	b.WriteString(`<main id="main" class="wrap"><div class="section">`)
	fmt.Fprintf(&b, `<div class="section-head"><p class="eyebrow">Section %d</p>`+
		`<h1>%s</h1></div>`, at, esc(kind))

	fmt.Fprintf(&b, `<form class="stacked" method="post" action="/section">`+
		`<input type="hidden" name="grant" value="%s">`+
		`<input type="hidden" name="base" value="%s">`+
		`<input type="hidden" name="at" value="%d">`, esc(grant), esc(base), at)

	files := a.libraryOf(user)
	group := ""
	for _, f := range fields {
		if f.Group != group {
			group = f.Group
			if group != "" {
				fmt.Fprintf(&b, `<h2 style="margin-top:var(--space-5)">%s</h2>`,
					esc(labelOfGroup(group)))
			}
		}
		b.WriteString(a.fieldInput(f, files))
	}
	b.WriteString(`<p><button class="btn" type="submit">Save this section</button></p></form>`)

	// Adding and removing entries are separate actions, so a mis-click cannot
	// take one out while you were editing another.
	if lists := section.Lists(body, at); len(lists) > 0 {
		b.WriteString(`<div class="section-head" style="margin-top:var(--space-6)">` +
			`<h2>Entries</h2></div><div class="actions">`)
		for _, list := range lists {
			fmt.Fprintf(&b, `<form method="post" action="/section" class="inline">`+
				`<input type="hidden" name="grant" value="%s">`+
				`<input type="hidden" name="base" value="%s">`+
				`<input type="hidden" name="at" value="%d">`+
				`<input type="hidden" name="do" value="additem">`+
				`<input type="hidden" name="list" value="%s">`+
				`<button class="btn btn-outlined" type="submit">Add to %s</button>`+
				`</form>`, esc(grant), esc(base), at, esc(list), esc(list))
		}
		b.WriteString(`</div>`)
	}

	fmt.Fprintf(&b, `<p class="muted" style="margin-top:var(--space-6)">`+
		`<a href="/?g=%s">Back to your page</a></p>`, esc(grant))
	b.WriteString(`</div></main>`)
	a.page(w, http.StatusOK, kind, b.String())
}

// fieldInput draws one value, choosing the control from what the value is.
//
// The interesting case is a file. A field called image, video or audio gets the
// library rather than a text box, because the alternative is asking somebody to
// type a sixty-four character hash — and the picker can also refuse to offer an
// image nobody has described yet, which is the check that would otherwise stop
// them at publish.
func (a *App) fieldInput(f section.Editable, files []StoredFile) string {
	id := "f-" + strings.ReplaceAll(f.Path, ".", "-")
	name := "v." + f.Path
	leaf := f.Path
	if i := strings.LastIndex(leaf, "."); i >= 0 {
		leaf = leaf[i+1:]
	}

	if kind, isFile := fileField(leaf); isFile {
		var b strings.Builder
		fmt.Fprintf(&b, `<p class="field"><label for="%s">%s</label>`+
			`<select id="%s" name="%s">`, esc(id), esc(f.Label), esc(id), esc(name))
		fmt.Fprintf(&b, `<option value="">nothing</option>`)
		offered := 0
		for _, file := range files {
			if file.Kind != kind {
				continue
			}
			selected := ""
			if "/media/"+file.ID == f.Value || file.ID == f.Value {
				selected = ` selected`
			}
			label := file.Name
			if file.NeedsDescription() {
				label += " — needs a description first"
			}
			fmt.Fprintf(&b, `<option value="/media/%s"%s>%s</option>`,
				esc(file.ID), selected, esc(label))
			offered++
		}
		b.WriteString(`</select>`)
		if offered == 0 {
			fmt.Fprintf(&b, `<span class="hint">No %s in your library yet. `+
				`Send one to the bot and it appears here.</span>`, esc(kind))
		}
		b.WriteString(`</p>`)
		return b.String()
	}

	if leaf == "tone" {
		return choice(id, name, f.Label, tones, f.Value)
	}
	if f.Long {
		return fmt.Sprintf(`<p class="field"><label for="%s">%s</label>`+
			`<textarea id="%s" name="%s" rows="5">%s</textarea></p>`,
			esc(id), esc(f.Label), esc(id), esc(name), esc(f.Value))
	}
	numeric := ""
	if f.Number {
		numeric = ` inputmode="numeric"`
	}
	return fmt.Sprintf(`<p class="field"><label for="%s">%s</label>`+
		`<input id="%s" name="%s" value="%s"%s></p>`,
		esc(id), esc(f.Label), esc(id), esc(name), esc(f.Value), numeric)
}

// fileField says whether a field name refers to a stored file, and which kind.
func fileField(leaf string) (string, bool) {
	switch leaf {
	case "image", "poster":
		return "image", true
	case "src":
		return "video", true
	case "audio":
		return "audio", true
	}
	return "", false
}

func (a *App) libraryOf(user User) []StoredFile {
	if a.Media == nil {
		return nil
	}
	return a.Media.Recent(user.Handle(), 60)
}

// library lists what somebody has sent the bot.
func (a *App) library(w http.ResponseWriter, r *http.Request) {
	user, grant, ok := a.requireGrant(w, r)
	if !ok {
		return
	}
	files := a.libraryOf(user)

	var b strings.Builder
	b.WriteString(`<main id="main" class="wrap"><div class="section">`)
	b.WriteString(`<div class="section-head"><p class="eyebrow">Your files</p>` +
		`<h1>What you have sent</h1>` +
		`<p class="lead">Send the bot a photograph, a video, an audio file or ` +
		`a voice note and it arrives here, ready to put on a page.</p></div>`)

	if len(files) == 0 {
		b.WriteString(`<div class="notice"><p>Nothing yet. Anything you send ` +
			`the bot in a chat shows up here — a caption becomes the ` +
			`description, and without one the bot will ask, because an image ` +
			`nobody has described does not publish.</p></div>`)
	} else {
		b.WriteString(`<div class="gallery gallery-square">`)
		for _, f := range files {
			b.WriteString(`<figure>`)
			if f.Kind == "image" {
				fmt.Fprintf(&b, `<img src="/media/%s" alt="%s" loading="lazy">`,
					esc(f.ID), esc(f.Alt))
			}
			fmt.Fprintf(&b, `<figcaption><code>%s</code> %s`,
				esc(f.Short()), esc(f.Kind))
			if f.NeedsDescription() {
				b.WriteString(`<br><strong>No description yet.</strong> Reply ` +
					`to the bot's message about it with one.`)
			} else if f.Alt != "" {
				fmt.Fprintf(&b, `<br>%s`, esc(f.Alt))
			}
			b.WriteString(`</figcaption></figure>`)
		}
		b.WriteString(`</div>`)
	}
	fmt.Fprintf(&b, `<p class="muted" style="margin-top:var(--space-6)">`+
		`<a href="/?g=%s">Back to your page</a></p>`, esc(grant))
	b.WriteString(`</div></main>`)
	a.page(w, http.StatusOK, "Your files", b.String())
}

// look is the design chooser.
func (a *App) look(w http.ResponseWriter, r *http.Request) {
	user, grant, ok := a.requireGrant(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		body, _ := a.draftOf(user)
		body["design"] = strings.TrimSpace(r.FormValue("design"))
		a.keep(w, r, user, body, "change the look of "+user.Handle(), "Saved.")
		return
	}

	body, base := a.draftOf(user)
	current := text(body, "design")

	var b strings.Builder
	b.WriteString(`<main id="main" class="wrap"><div class="section">`)
	b.WriteString(`<div class="section-head"><p class="eyebrow">How it looks</p>` +
		`<h1>Pick a design</h1>` +
		`<p class="lead">Each one is a whole palette and type scale, and every ` +
		`pair of colours in it has been checked for contrast in both light and ` +
		`dark.</p></div>`)

	if a.Publisher != nil {
		fmt.Fprintf(&b, `<form class="stacked" method="post" action="/look">`+
			`<input type="hidden" name="grant" value="%s">`+
			`<input type="hidden" name="base" value="%s">`, esc(grant), esc(base))
		for _, d := range a.Publisher.Designs() {
			checked := ""
			if d.Name == current {
				checked = ` checked`
			}
			fmt.Fprintf(&b, `<div class="card"><p class="field">`+
				`<label for="d-%s"><input type="radio" id="d-%s" name="design" `+
				`value="%s"%s> %s</label>`+
				`<span class="hint">%s</span></p></div>`,
				esc(d.Name), esc(d.Name), esc(d.Name), checked,
				esc(d.Name), esc(d.Look))
		}
		b.WriteString(`<p><button class="btn" type="submit">Use this one</button></p></form>`)
	}

	b.WriteString(`<div class="notice"><p>There is no colour picker here on ` +
		`purpose. A free hex field is how a site ends up with text nobody can ` +
		`read against its background — and this refuses to publish one, so the ` +
		`field would mostly produce a refusal you could not act on. What you ` +
		`get instead is a palette where every combination already passes.</p>` +
		`</div>`)
	fmt.Fprintf(&b, `<p class="muted"><a href="/?g=%s">Back to your page</a></p>`,
		esc(grant))
	b.WriteString(`</div></main>`)
	a.page(w, http.StatusOK, "How it looks", b.String())
}

// pick keeps a submitted value only when it is in the closed list it came from.
func pick(value string, options []struct{ Value, Label string }) string {
	for _, o := range options {
		if o.Value == value {
			return value
		}
	}
	return options[0].Value
}

func labelOfGroup(group string) string {
	list, idx, found := strings.Cut(group, ".")
	if !found {
		return strings.ReplaceAll(list, "_", " ")
	}
	n, err := strconv.Atoi(idx)
	if err != nil {
		return strings.ReplaceAll(list, "_", " ")
	}
	return fmt.Sprintf("%s %d", strings.ReplaceAll(list, "_", " "), n+1)
}
