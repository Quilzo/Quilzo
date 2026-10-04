// Speaking, listening and translating, for a site's assistant, all on the
// visitor's own device. Allowed by its hash on conversation pages whose
// assistant has voice or translation turned on, and on no other page.
//
// What it will not do is the point. It offers the microphone only when the
// browser says it recognises speech on the device; it reads aloud only with
// voices the device has; it translates only with the browser's on-device
// translator. When any of those is missing, that feature is simply not
// offered, and the page works as typed text, as it does without script.
// Translated text is put on the page as text, never as markup.
(function () {
  "use strict";
  var cfg = document.getElementById("qz-voice");
  if (!cfg) return;
  var name = cfg.getAttribute("data-name") || "";
  var site = (cfg.getAttribute("data-lang") || "en").toLowerCase();
  var wantVoice = cfg.getAttribute("data-voice") === "1";
  var wantTranslate = cfg.getAttribute("data-translate") === "1";
  var form = document.querySelector('form[action$="/ask/' + name + '"]');
  var box = form && form.querySelector('textarea[name="q"]');
  var status = document.getElementById("qz-voice-status");
  var trKey = "qz-tr:" + name, spokeKey = "qz-spoke:" + name;

  function base(tag) { return String(tag || "").toLowerCase().split("-")[0]; }
  function get(k) { try { return JSON.parse(sessionStorage.getItem(k) || "null"); } catch (e) { return null; } }
  function put(k, v) { try { if (v === null) sessionStorage.removeItem(k); else sessionStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }
  function say(text) { if (status) status.textContent = text; }
  function icon(path) {
    var ns = "http://www.w3.org/2000/svg";
    var s = document.createElementNS(ns, "svg");
    s.setAttribute("viewBox", "0 -960 960 960");
    s.setAttribute("aria-hidden", "true");
    s.setAttribute("focusable", "false");
    s.setAttribute("class", "qz-icon");
    var p = document.createElementNS(ns, "path");
    p.setAttribute("d", path || "");
    s.appendChild(p);
    return s;
  }
  function button(label, path, cls) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "qz-voice-btn " + (cls || "");
    if (path) b.appendChild(icon(path));
    var t = document.createElement("span");
    t.textContent = label;
    b.appendChild(t);
    return b;
  }
  function labelOf(b, text) { b.lastChild.textContent = text; }

  // -- the visitor's language ----------------------------------------------
  var visitor = base(navigator.language);
  var Translator = self.Translator, Detector = self.LanguageDetector;
  var canTranslate = wantTranslate && Translator && Detector;
  function languageName(tag) {
    try { return new Intl.DisplayNames([navigator.language], { type: "language" }).of(tag) || tag; } catch (e) { return tag; }
  }

  // -- asking by voice -------------------------------------------------------
  var SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  function offerMic(lang, state) {
    var mic = button("Speak", cfg.getAttribute("data-mic"), "qz-mic");
    mic.setAttribute("aria-pressed", "false");
    // Beside the Ask button, in one row.
    var submit = form.querySelector('button[type="submit"]');
    var row = document.createElement("div");
    row.className = "qz-ask-row";
    submit.parentNode.insertBefore(row, submit);
    row.appendChild(submit);
    row.appendChild(mic);
    var note = document.createElement("p");
    note.className = "qz-small qz-voice-note";
    note.textContent = "Speaking is recognised on this device; what you say does not leave it.";
    form.appendChild(note);
    var rec = null;
    function stop() { if (rec) { try { rec.stop(); } catch (e) {} } }
    mic.addEventListener("click", function () {
      if (rec) { stop(); return; }
      var begin = function () {
        rec = new SR();
        rec.lang = lang;
        rec.processLocally = true;
        rec.interimResults = true;
        rec.continuous = false;
        mic.setAttribute("aria-pressed", "true");
        labelOf(mic, "Stop");
        say("Listening…");
        rec.onresult = function (e) {
          var text = "";
          for (var i = 0; i < e.results.length; i++) text += e.results[i][0].transcript;
          box.value = text;
          if (e.results[e.results.length - 1].isFinal && text.trim()) {
            put(spokeKey, true);
            stop();
            say("Asking…");
            send();
          }
        };
        rec.onerror = function (e) {
          say(e.error === "not-allowed" ? "The microphone was not allowed. You can type the question instead."
            : e.error === "no-speech" ? "Nothing was heard. Try again, or type the question."
            : "Speech could not be recognised here. You can type the question instead.");
        };
        rec.onend = function () {
          rec = null;
          mic.setAttribute("aria-pressed", "false");
          labelOf(mic, "Speak");
        };
        try { rec.start(); } catch (e) { rec = null; say("Speech could not be started here."); }
      };
      if (state === "available") { begin(); return; }
      // Once, with the visitor's click: the language for recognising
      // speech on the device.
      say("Getting " + languageName(lang) + " speech recognition for this device, once…");
      SR.install({ langs: [lang], processLocally: true }).then(function (ok) {
        if (ok) { state = "available"; say(""); begin(); }
        else say("Speech recognition could not be added on this device. You can type the question.");
      }, function () { say("Speech recognition could not be added on this device. You can type the question."); });
    });
  }
  if (wantVoice && form && box && SR && typeof SR.available === "function") {
    // The visitor's language first when the answer will be translated for
    // them, otherwise the site's.
    var tries = [];
    if (canTranslate && visitor !== site) tries.push(navigator.language);
    tries.push(site);
    (function next(i) {
      if (i >= tries.length) return;
      SR.available({ langs: [tries[i]], processLocally: true }).then(function (state) {
        if (state === "available" || state === "downloadable") offerMic(tries[i], state);
        else next(i + 1);
      }, function () { next(i + 1); });
    })(0);
  }

  // -- sending: translated into the site's language first, if need be ------
  var sending = false;
  function send() {
    if (typeof form.requestSubmit === "function") form.requestSubmit(); else form.submit();
  }
  if (canTranslate && form && box) {
    form.addEventListener("submit", function (e) {
      if (sending) return;
      var asked = box.value.trim();
      if (!asked) return;
      e.preventDefault();
      sending = true;
      var go = function () { form.submit(); };
      Detector.create().then(function (d) { return d.detect(asked); }).then(function (found) {
        var top = found && found[0];
        var lang = top && top.confidence >= 0.6 ? base(top.detectedLanguage) : "";
        if (!lang || lang === "und" || lang === site) { put(trKey, null); go(); return; }
        return Translator.availability({ sourceLanguage: lang, targetLanguage: site }).then(function (a) {
          if (a === "unavailable") { put(trKey, null); go(); return; }
          say("Translating your question on this device…");
          return Translator.create({ sourceLanguage: lang, targetLanguage: site }).then(function (t) {
            return t.translate(asked);
          }).then(function (text) {
            put(trKey, { lang: lang, asked: asked });
            box.value = text;
            go();
          });
        });
      }).catch(function () { put(trKey, null); go(); });
    });
  }

  // -- an answer: translated back, and read aloud on request ---------------
  var answer = document.querySelector(".qz-a");
  if (!answer) return;
  var tr = canTranslate ? get(trKey) : null;
  var shownLang = site;

  function paragraphs() {
    return Array.prototype.filter.call(answer.querySelectorAll("p"), function (p) {
      return !p.hidden && !p.closest(".qz-sources") && !p.classList.contains("qz-tr-note");
    });
  }
  function textOf(p) {
    var c = p.cloneNode(true);
    Array.prototype.forEach.call(c.querySelectorAll("sup"), function (s) { s.remove(); });
    return c.textContent.trim();
  }

  function translateBack() {
    if (!tr || !tr.lang || tr.lang === site) return;
    var q = document.querySelector(".qz-q");
    Translator.availability({ sourceLanguage: site, targetLanguage: tr.lang }).then(function (a) {
      if (a === "unavailable") return;
      var run = function () {
        Translator.create({ sourceLanguage: site, targetLanguage: tr.lang }).then(function (t) {
          var ps = paragraphs();
          var done = Promise.all(ps.map(function (p) {
            return t.translate(textOf(p)).then(function (text) {
              var n = document.createElement("p");
              n.className = "qz-translated";
              n.setAttribute("lang", tr.lang);
              n.textContent = text;
              Array.prototype.forEach.call(p.querySelectorAll("sup"), function (s) {
                n.appendChild(document.createTextNode(" "));
                n.appendChild(s.cloneNode(true));
              });
              p.hidden = true;
              p.parentNode.insertBefore(n, p.nextSibling);
            });
          }));
          // The note and its control in the visitor's language too, by
          // the same translator, so the page does not switch language
          // mid-sentence.
          var words = { note: "Translated on your device from " + new Intl.DisplayNames(["en"], { type: "language" }).of(site) + ".",
            original: "Show the original", translation: "Show the translation" };
          var said = Promise.all(Object.keys(words).map(function (k) {
            return t.translate(words[k]).then(function (v) { words[k] = v; }, function () {});
          }));
          return Promise.all([done, said]).then(function () {
            if (q) { q.setAttribute("data-site-text", q.textContent); q.textContent = tr.asked; q.setAttribute("lang", tr.lang); }
            shownLang = tr.lang;
            var note = document.createElement("p");
            note.className = "qz-small qz-tr-note";
            note.setAttribute("lang", tr.lang);
            note.textContent = words.note + " ";
            var toggle = button(words.original, null, "qz-link");
            toggle.addEventListener("click", function () {
              var orig = toggle.getAttribute("aria-pressed") !== "true";
              toggle.setAttribute("aria-pressed", orig ? "true" : "false");
              labelOf(toggle, orig ? words.translation : words.original);
              Array.prototype.forEach.call(answer.querySelectorAll(".qz-translated"), function (n) {
                n.hidden = orig;
                n.previousSibling.hidden = !orig;
              });
              shownLang = orig ? site : tr.lang;
            });
            toggle.setAttribute("aria-pressed", "false");
            note.appendChild(toggle);
            answer.insertBefore(note, answer.firstChild);
          });
        }).catch(function () {});
      };
      if (a === "available") { run(); return; }
      // A download needs the visitor's say-so.
      var offer = button("Translate into " + languageName(tr.lang), cfg.getAttribute("data-translate-icon"), "qz-tr-offer");
      offer.addEventListener("click", function () { offer.remove(); run(); });
      answer.insertBefore(offer, answer.firstChild);
    });
  }
  translateBack();

  if (wantVoice && "speechSynthesis" in window) {
    var synth = window.speechSynthesis;
    var reading = false;
    var readBtn = null;
    function localVoice(lang) {
      var vs = synth.getVoices().filter(function (v) { return v.localService && base(v.lang) === base(lang); });
      return vs[0] || null;
    }
    function stopReading() {
      synth.cancel();
      reading = false;
      Array.prototype.forEach.call(answer.querySelectorAll(".qz-speaking"), function (p) { p.classList.remove("qz-speaking"); });
      if (readBtn) { readBtn.setAttribute("aria-pressed", "false"); labelOf(readBtn, "Read aloud"); }
    }
    function read() {
      var voice = localVoice(shownLang);
      if (!voice) { say("This device has no voice for " + languageName(shownLang) + "."); return; }
      var ps = paragraphs();
      reading = true;
      readBtn.setAttribute("aria-pressed", "true");
      labelOf(readBtn, "Stop reading");
      (function next(i) {
        if (!reading || i >= ps.length) { stopReading(); return; }
        var u = new SpeechSynthesisUtterance(textOf(ps[i]));
        u.voice = voice;
        u.lang = voice.lang;
        ps[i].classList.add("qz-speaking");
        u.onend = u.onerror = function () { ps[i].classList.remove("qz-speaking"); next(i + 1); };
        synth.speak(u);
      })(0);
    }
    function offerRead() {
      if (readBtn || !localVoice(shownLang) && !localVoice(site)) return;
      readBtn = button("Read aloud", cfg.getAttribute("data-speak"), "qz-read");
      readBtn.setAttribute("aria-pressed", "false");
      readBtn.addEventListener("click", function () { if (reading) stopReading(); else read(); });
      var at = answer.querySelector("h2") || null;
      answer.insertBefore(readBtn, at);
      // Asked by voice: answered by voice, if the browser allows speech
      // without a fresh click. If it does not, the button is there.
      if (get(spokeKey)) { put(spokeKey, null); read(); }
    }
    offerRead();
    if (!readBtn) synth.addEventListener("voiceschanged", offerRead, { once: true });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && reading) stopReading(); });
    window.addEventListener("pagehide", stopReading);
  }
})();
