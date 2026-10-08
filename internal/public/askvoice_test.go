// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/i18n"
)

var scriptRe = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

// The script is on the conversation page, allowed by exactly its hash, only
// when the owner turned voice or translation on.
func TestVoiceIsOfferedOnlyWhenTurnedOnAndRunsByItsHash(t *testing.T) {
	on := shopBot
	on.Voice, on.Translate = true, true
	st, _ := askSite(t, on)
	w := get(st, "/ask/help", nil)
	body, csp := w.Body.String(), w.Header().Get("Content-Security-Policy")
	if !strings.Contains(body, `id="qz-voice"`) || !strings.Contains(body, `data-voice="1"`) ||
		!strings.Contains(body, `data-translate="1"`) || !strings.Contains(body, `data-lang="en"`) {
		t.Fatalf("the voice settings are not on the page")
	}
	var found bool
	for _, m := range scriptRe.FindAllStringSubmatch(body, -1) {
		sum := sha256.Sum256([]byte(m[1]))
		h := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if h == askVoiceHash {
			found = true
		}
	}
	if !found {
		t.Fatal("the script on the page is not the one whose hash is allowed")
	}
	if csp != "" && !strings.Contains(csp, askVoiceHash) {
		t.Errorf("the policy does not allow the script: %s", csp)
	}
	// The answer page carries it too, where it is needed to read aloud.
	if a := askPost(st, "help", "can I return opened ink?").Body.String(); !strings.Contains(a, `id="qz-voice"`) {
		t.Error("the answer page does not carry the script")
	}

	off, _ := askSite(t, shopBot)
	w = get(off, "/ask/help", nil)
	if strings.Contains(w.Body.String(), "qz-voice") || strings.Contains(w.Header().Get("Content-Security-Policy"), askVoiceHash) {
		t.Error("a chatbot without voice or translation carries the script or its hash")
	}
}

func TestThePageSaysTheSitesLanguage(t *testing.T) {
	on := shopBot
	on.Voice = true
	st, _ := askSite(t, on)
	st.Locales = &i18n.Config{Default: "fr"}
	body := get(st, "/ask/help", nil).Body.String()
	if !strings.Contains(body, `<html lang="fr">`) || !strings.Contains(body, `data-lang="fr"`) {
		t.Errorf("the page does not say the site is in French")
	}
}

// What the script promises, checked in its text: on-device recognition
// only, local voices only, the on-device translator only, and translated
// text placed as text.
func TestTheScriptKeepsEverythingOnTheDevice(t *testing.T) {
	for _, must := range []string{"processLocally: true", "rec.processLocally = true", "v.localService",
		"Translator.availability", "LanguageDetector", ".textContent = text"} {
		if !strings.Contains(askVoiceJS, must) {
			t.Errorf("the script no longer says %q", must)
		}
	}
	for _, never := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "fetch(", "XMLHttpRequest", "eval(", "new Function"} {
		if strings.Contains(askVoiceJS, never) {
			t.Errorf("the script uses %s", never)
		}
	}
	_ = assistant.Assistant{}
}

// Translating before sending has a deadline: an on-device model that is
// still downloading, or never answers, must not swallow the question.
func TestAQuestionIsSentEvenIfTranslatingStalls(t *testing.T) {
	at := strings.Index(askVoiceJS, "Detector.create()")
	if at < 0 {
		t.Fatal("the script no longer detects the question's language")
	}
	before := askVoiceJS[:at]
	start := strings.LastIndex(before, "e.preventDefault();")
	if start < 0 {
		t.Fatal("the submit handler no longer holds the question back")
	}
	held := before[start:]
	if !strings.Contains(held, "setTimeout(") || !strings.Contains(held, "go();") {
		t.Errorf("the question waits on translation with no deadline:\n%s", held)
	}
	if !strings.Contains(askVoiceJS, "if (sent) return;") {
		t.Errorf("a translation finishing after the deadline could send the question twice")
	}
}
