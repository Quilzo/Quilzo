// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"html"
	"html/template"
	"strings"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/icons"
)

// Speaking, listening and translating for a site's assistant. See
// askvoice.js: everything happens on the visitor's device, and a feature
// the device cannot do on its own is not offered. The server's part is
// small on purpose: it says which features the owner turned on, in which
// language the site answers, and lets this one script run by its hash on
// the conversation page and nowhere else.

//go:embed askvoice.js
var askVoiceJS string

// askVoiceHash is the script's source expression for script-src.
var askVoiceHash = func() string {
	sum := sha256.Sum256([]byte(askVoiceJS))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

// wantsVoice reports whether a conversation page carries the script.
func wantsVoice(a assistant.Assistant) bool { return a.Voice || a.Translate }

// siteLang is the language the site's pages are in: the default locale, or
// English when the site has declared none.
func (st *Site) siteLang() string {
	if st.Locales != nil && st.Locales.Default != "" {
		return strings.ToLower(string(st.Locales.Default))
	}
	return "en"
}

// voiceSnippet is the script and what it reads, for the end of the body.
// Every value is the server's own: a validated assistant name, a language
// tag from the site's configuration, and icon path data from the built-in
// set, each escaped for an attribute regardless.
func (st *Site) voiceSnippet(a assistant.Assistant) string {
	if !wantsVoice(a) {
		return ""
	}
	flag := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	e := html.EscapeString
	var b strings.Builder
	b.WriteString(`<div id="qz-voice" hidden data-name="` + e(a.Name) + `" data-lang="` + e(st.siteLang()) +
		`" data-voice="` + flag(a.Voice) + `" data-translate="` + flag(a.Translate) +
		`" data-mic="` + e(icons.Path("mic", st.IconStyle)) +
		`" data-speak="` + e(icons.Path("volume_up", st.IconStyle)) +
		`" data-translate-icon="` + e(icons.Path("translate", st.IconStyle)) + `"></div>` + "\n")
	b.WriteString(`<p id="qz-voice-status" class="qz-small qz-voice-status" role="status"></p>` + "\n")
	b.WriteString("<script>" + askVoiceJS + "</script>\n")
	return b.String()
}

// voiceHTML is the snippet for the built-in page's template.
func (st *Site) voiceHTML(a assistant.Assistant) template.HTML {
	return template.HTML(st.voiceSnippet(a))
}
