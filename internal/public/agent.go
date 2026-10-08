// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/assistant"
)

// The site's assistant on its pages: a button in a corner that opens the
// conversation beside the page.
//
// # Built on what is already there
//
// The panel is the conversation page itself, framed from this site, so a
// question asked in it is answered by the same code, with the same
// citations, hand-off and live replies, and keeps nothing the page does not
// keep. The button is a link to that page, so with scripts off — or the
// policy refusing them — it still works: the visitor goes to the
// conversation instead of opening it beside them.
//
// # What it is allowed
//
// The script runs by its hash, on pages that carry the button and on no
// others, and the frame is allowed from this site alone (frame-src 'self').
// Nothing is loaded from anywhere else: no widget vendor, no tracking, and
// what a visitor asks goes where every other question here goes.
//
// # The nudge
//
// Off unless an owner writes one. Shown once a visit, never again for a
// month once dismissed, beside the button rather than over the page, and on
// a small screen only after the first screen has been scrolled past — what
// Google's guidance on intrusive interstitials asks of anything that appears
// uninvited.

//go:embed agent.js
var agentJS string

var agentHash = func() string {
	sum := sha256.Sum256([]byte(agentJS))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

// Material Symbols Rounded (Apache-2.0): chat, filled, and close.
const (
	chatIconPath  = "m240-240-92 92q-19 19-43.5 8.5T80-177v-623q0-33 23.5-56.5T160-880h640q33 0 56.5 23.5T880-800v480q0 33-23.5 56.5T800-240H240Zm40-160h240q17 0 28.5-11.5T560-440q0-17-11.5-28.5T520-480H280q-17 0-28.5 11.5T240-440q0 17 11.5 28.5T280-400Zm0-120h400q17 0 28.5-11.5T720-560q0-17-11.5-28.5T680-600H280q-17 0-28.5 11.5T240-560q0 17 11.5 28.5T280-520Zm0-120h400q17 0 28.5-11.5T720-680q0-17-11.5-28.5T680-720H280q-17 0-28.5 11.5T240-680q0 17 11.5 28.5T280-640Z"
	closeIconPath = "M480-424 284-228q-11 11-28 11t-28-11q-11-11-11-28t11-28l196-196-196-196q-11-11-11-28t11-28q11-11 28-11t28 11l196 196 196-196q11-11 28-11t28 11q11 11 11 28t-11 28L536-480l196 196q11 11 11 28t-11 28q-11 11-28 11t-28-11L480-424Z"
)

// launcherFor is the assistant whose button belongs on the page at path,
// if any. Not on the conversation pages themselves, and not on a static
// copy, which has no server to hold a conversation with.
func (st *Site) launcherFor(r *http.Request, path string) (assistant.Assistant, bool) {
	if st.Assistants == nil || st.Assistants.Set == nil || r.Header.Get(CopyHeader) != "" ||
		strings.HasPrefix(path, "/ask/") {
		return assistant.Assistant{}, false
	}
	set, err := st.Assistants.Set()
	if err != nil || set == nil {
		return assistant.Assistant{}, false
	}
	a, ok := set.Launcher()
	if !ok || !a.Launcher.On(path) {
		return assistant.Assistant{}, false
	}
	return a, true
}

// launcherTag is what the launcher adds to a page's ETag: a page whose
// button changed is not the page a cache holds.
func launcherTag(a assistant.Assistant, path string) string {
	b, _ := json.Marshal(struct {
		L    *assistant.Launcher
		N, T string
		On   bool
	}{a.Launcher, a.Name, a.Title, a.Launcher.NudgeOn(path)})
	sum := sha256.Sum256(append(b, agentJS...))
	return hex.EncodeToString(sum[:6])
}

// launcherMarkup is the button, and the script that makes it open a panel.
func launcherMarkup(a assistant.Assistant, path string) string {
	l := a.Launcher.Normalised()
	e := html.EscapeString
	var b strings.Builder
	b.WriteString(`<div class="qz-launch qz-launch-` + e(l.Side) + ` qz-launch-` + e(l.Style) + `" data-qz-agent="/ask/` +
		url.PathEscape(a.Name) + `?embed=panel" data-name="` + e(a.Name) + `" data-title="` + e(a.Title) +
		`" data-panel="` + e(l.Panel) + `" data-side="` + e(l.Side) + `" data-close-icon="` + closeIconPath + `"`)
	if a.Launcher.NudgeOn(path) {
		b.WriteString(` data-nudge="` + e(strings.TrimSpace(l.Nudge)) + `" data-nudge-after="` + strconv.Itoa(l.NudgeAfter) + `"`)
	}
	b.WriteString(`>`)
	label := e(l.Label)
	b.WriteString(`<a class="qz-launch-btn" href="/ask/` + url.PathEscape(a.Name) + `"`)
	if l.Style == "bubble" {
		b.WriteString(` aria-label="` + label + `: ` + e(a.Title) + `"`)
	}
	b.WriteString(`><svg viewBox="0 -960 960 960" aria-hidden="true" focusable="false"><path d="` + chatIconPath + `"/></svg>`)
	if l.Style != "bubble" {
		b.WriteString(`<span>` + label + `</span>`)
	}
	b.WriteString("</a></div>\n<script>" + agentJS + "</script>\n")
	return b.String()
}

// insertBeforeBodyEnd puts markup at the end of the body, where a
// launcher belongs in the reading order: after everything on the page.
func insertBeforeBodyEnd(page, markup string) string {
	at := strings.LastIndex(strings.ToLower(page), "</body>")
	if at < 0 {
		return page + markup
	}
	return page[:at] + markup + page[at:]
}

// allowFrameSelf lets the page frame this site, and nothing else.
func allowFrameSelf(h http.Header) {
	for _, name := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		cur := h.Get(name)
		if cur == "" {
			continue
		}
		if m := reFrameSrc.FindString(cur); m != "" {
			if !strings.Contains(m, "'self'") {
				var kept []string
				for _, f := range strings.Fields(m) {
					if f != "'none'" {
						kept = append(kept, f)
					}
				}
				cur = reFrameSrc.ReplaceAllString(cur, strings.Join(append(kept, "'self'"), " "))
			}
		} else {
			cur += "; frame-src 'self'"
		}
		h.Set(name, cur)
	}
}

var reFrameSrc = regexp.MustCompile(`frame-src[^;]*`)

// agentCSS is the launcher's stylesheet, served at /agent.css. Every colour,
// radius and motion comes from the site's own tokens, with fallbacks for a
// site with none, so the button looks like the site it is on.
const agentCSS = `.qz-launch,.qz-panel{
 --qz-fill:var(--primary-container,var(--accent,color-mix(in srgb,LinkText 22%,Canvas)));
 --qz-on-fill:var(--on-primary-container,var(--on-accent,CanvasText));
 --qz-surface:var(--surface,var(--ground,Canvas));
 --qz-on-surface:var(--on-surface,var(--ink,CanvasText));
 --qz-raised:var(--surface-container-high,var(--raised,color-mix(in srgb,CanvasText 7%,Canvas)));
 --qz-line:var(--outline-variant,var(--line,color-mix(in srgb,CanvasText 22%,Canvas)));
 --qz-focus:var(--focus-ring,var(--primary,var(--accent,Highlight)));
 --qz-r:var(--radius-lg,var(--radius,16px));--qz-r-xl:var(--radius-xl,calc(var(--radius,16px)*1.75))}
.qz-launch{position:fixed;z-index:2147483000;bottom:max(16px,env(safe-area-inset-bottom));display:flex;flex-direction:column;gap:12px}
.qz-launch-right{right:max(16px,env(safe-area-inset-right));align-items:flex-end}
.qz-launch-left{left:max(16px,env(safe-area-inset-left));align-items:flex-start}
.qz-launch-btn{display:inline-flex;align-items:center;justify-content:center;gap:10px;min-height:56px;min-width:56px;padding:0 20px 0 16px;box-sizing:border-box;
 border-radius:var(--qz-r);background:var(--qz-fill);color:var(--qz-on-fill);
 font:600 1rem/1 inherit;text-decoration:none;box-shadow:0 3px 8px rgb(0 0 0/.18),0 1px 3px rgb(0 0 0/.12);
 transition:transform var(--dur,300ms) var(--spring,ease),box-shadow var(--dur,300ms) var(--ease,ease)}
.qz-launch-btn svg{width:24px;height:24px;fill:currentColor;flex:none}
.qz-launch-btn:hover{box-shadow:0 6px 14px rgb(0 0 0/.2),0 2px 4px rgb(0 0 0/.14)}
.qz-launch-btn:active{transform:scale(.96)}
.qz-launch-btn:focus-visible{outline:3px solid var(--qz-focus);outline-offset:2px}
.qz-launch-bubble .qz-launch-btn{padding:0;width:56px}
.qz-launch-tab{bottom:auto;top:50%;transform:translateY(-50%)}
.qz-launch-tab.qz-launch-right{right:0}.qz-launch-tab.qz-launch-left{left:0}
.qz-launch-tab .qz-launch-btn{writing-mode:vertical-rl;min-height:120px;min-width:44px;padding:16px 10px}
.qz-launch-tab.qz-launch-right .qz-launch-btn{border-radius:var(--qz-r) 0 0 var(--qz-r)}
.qz-launch-tab.qz-launch-left .qz-launch-btn{border-radius:0 var(--qz-r) var(--qz-r) 0;transform:rotate(180deg)}
.qz-launch-tab .qz-launch-btn svg{transform:rotate(90deg)}
.qz-nudge{order:-1;display:flex;align-items:flex-start;gap:4px;max-width:min(320px,calc(100vw - 32px));padding:4px 4px 4px 16px;border-radius:var(--qz-r);
 background:var(--qz-raised);color:var(--qz-on-surface);box-shadow:0 3px 8px rgb(0 0 0/.18);animation:qz-in var(--dur,300ms) var(--spring,ease)}
.qz-nudge button{font:inherit;color:inherit;background:none;border:0;cursor:pointer}
.qz-nudge-text{text-align:start;padding:10px 0;flex:1}
.qz-nudge-close{width:44px;height:44px;display:grid;place-items:center;border-radius:50%}
.qz-nudge-close svg,.qz-panel-close svg{width:20px;height:20px;fill:currentColor}
.qz-nudge button:focus-visible,.qz-panel-close:focus-visible{outline:3px solid var(--qz-focus);outline-offset:2px}
.qz-panel{position:fixed;z-index:2147483001;display:flex;flex-direction:column;box-sizing:border-box;background:var(--qz-surface);color:var(--qz-on-surface);
 box-shadow:0 8px 28px rgb(0 0 0/.24);overflow:hidden}
.qz-panel[hidden]{display:none}
.qz-panel-float{bottom:calc(max(16px,env(safe-area-inset-bottom)) + 72px);width:min(400px,calc(100vw - 32px));height:min(640px,calc(100vh - 120px));
 border-radius:var(--qz-r-xl);animation:qz-in var(--dur,300ms) var(--spring,ease)}
.qz-panel-float.qz-panel-right{right:max(16px,env(safe-area-inset-right))}.qz-panel-float.qz-panel-left{left:max(16px,env(safe-area-inset-left))}
.qz-panel-side{top:0;bottom:0;width:min(420px,100vw);border-radius:0}
.qz-panel-side.qz-panel-right{right:0;border-left:1px solid var(--qz-line)}
.qz-panel-side.qz-panel-left{left:0;border-right:1px solid var(--qz-line)}
.qz-panel-head{display:flex;align-items:center;gap:8px;padding:8px 8px 8px 20px;background:var(--qz-raised)}
.qz-panel-head h2{flex:1;margin:0;font-size:1rem;font-weight:600}
.qz-panel-close{width:48px;height:48px;display:grid;place-items:center;border:0;border-radius:50%;background:none;color:inherit;cursor:pointer}
.qz-panel-close:hover{background:color-mix(in srgb,currentColor 8%,transparent)}
.qz-panel-frame{flex:1;width:100%;border:0;background:var(--qz-surface)}
@media (min-width:900px){html.qz-agent-side:has(.qz-panel-side.qz-panel-right:not([hidden])) body{margin-right:min(420px,40vw)}
 html.qz-agent-side:has(.qz-panel-side.qz-panel-left:not([hidden])) body{margin-left:min(420px,40vw)}
 .qz-panel-side{width:min(420px,40vw)}}
@media (max-width:599px){.qz-panel.qz-panel-float,.qz-panel.qz-panel-side,.qz-panel.qz-panel-right,.qz-panel.qz-panel-left{inset:0;width:auto;height:auto;border-radius:0;border:0}}
@keyframes qz-in{from{opacity:0;transform:translateY(12px) scale(.98)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion:reduce){.qz-panel,.qz-nudge,.qz-launch-btn{animation:none;transition:none}}
@media print{.qz-launch,.qz-panel{display:none}}
`

func (st *Site) agentStylesheet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(agentCSS))
}
