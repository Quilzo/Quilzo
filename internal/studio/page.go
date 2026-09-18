// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package studio

import (
	"fmt"
	"html"
	"net/http"
)

// The one page, and the script on it.
//
// # Why the markup is in Go rather than a template
//
// Because the nonce has to be on the header and on the script tag and they
// have to be the same value, per response. A template makes that a parameter
// somebody can forget to pass; building the document here makes it impossible
// to render the page without one. The API playground reached the same
// conclusion for the same reason.
//
// # What the script is allowed to be
//
// Small, inline, and loading nothing. Fetching a library would mean either a
// CDN in the policy — reopening exactly what the nonce closes — or vendoring
// a dependency this program does not have. No eval, no innerHTML, no
// document.write: the recording is bytes from a media device and the page
// runs in a writable origin, so the sinks that turn a string into markup have
// no business here. A test asserts each of those.
//
// It also does not read document.cookie. The credential is HttpOnly and the
// upload is a same-origin fetch, so the script never needs to see it — which
// is the property that makes an injection here unable to carry the token
// anywhere.

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	n, err := nonce()
	if err != nil {
		http.Error(w, "no entropy", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Security-Policy", policyFor(n))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tok := s.caller(r)
	if !s.mayWrite(tok) {
		// The sign-in form carries no script, so it is served under a policy
		// that permits none. A door that runs code before anybody is through
		// it is a door with a larger attack surface than the room.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self'; form-action 'self'; "+
				"frame-ancestors 'none'; base-uri 'none'")
		fmt.Fprint(w, signInHTML())
		return
	}
	fmt.Fprint(w, recorderHTML(n, tok.Principal))
}

func (s *Server) stylesheet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, studioCSS)
}

func signInHTML() string {
	return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Studio</title><link rel="stylesheet" href="/studio.css">
</head><body>
<main>
<h1>Studio</h1>
<p class="lead">Records the screen and puts the recording in this site's asset
library. Nothing else: there is no editor here and no publish button.</p>
<form method="post" action="/signin">
  <p><label for="t">A token that may edit the draft</label>
    <input id="t" name="token" type="password" autocomplete="off" required>
    <span class="hint">The same credential the admin and the command line
      take. <code>quilzo token issue you --principal you --role author</code>
      makes one; revoking it stops this surface too.</span></p>
  <p><button type="submit">Sign in</button></p>
</form>
<p class="hint">This is a separate server on a separate origin because it runs
  a script, and the admin does not. Keeping them apart is what lets the
  admin's policy stay <code>default-src 'none'</code>.</p>
</main>
</body></html>`
}

func recorderHTML(n, who string) string {
	return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Studio</title><link rel="stylesheet" href="/studio.css">
</head><body>
<main>
<h1>Studio</h1>
<p class="hint">Signed in as ` + html.EscapeString(who) + `.</p>

<div class="controls">
  <button id="start" type="button">Record the screen</button>
  <button id="stop" type="button" disabled>Stop</button>
  <span id="state" role="status" aria-live="polite">Ready.</span>
</div>

<video id="playback" controls hidden></video>

<form id="keep" hidden>
  <p class="field"><label for="name">A name for it</label>
    <input id="name" value="screen-recording.webm"></p>
  <p class="field"><label for="alt">What it shows</label>
    <input id="alt" placeholder="a walkthrough of the checkout page">
    <span class="hint">A recording still needs captions before a page showing
      it will publish. This is the description of the file itself.</span></p>
  <p><button id="send" type="button">Put it in the library</button></p>
  <progress id="sent" max="100" value="0" hidden></progress>
</form>

<p id="done" class="notice" hidden></p>

<p class="hint">Recordings arrive through the same door an upload does: parsed
  before they are stored, filed under the hash of their own bytes, measured,
  and given a poster frame where this machine can take one. A page showing one
  will not publish until it has captions — WCAG 1.2.2, which this program
  refuses rather than warns about.</p>
</main>
<script nonce="` + n + `">
(function () {
  var start = document.getElementById('start');
  var stop = document.getElementById('stop');
  var state = document.getElementById('state');
  var playback = document.getElementById('playback');
  var keep = document.getElementById('keep');
  var send = document.getElementById('send');
  var sent = document.getElementById('sent');
  var done = document.getElementById('done');
  var name = document.getElementById('name');
  var alt = document.getElementById('alt');
  var recorder = null, chunks = [], blob = null, url = null, stream = null;

  function say(text) { state.textContent = text; }

  function release() {
    if (stream) { stream.getTracks().forEach(function (t) { t.stop(); }); stream = null; }
  }

  start.addEventListener('click', function () {
    done.hidden = true;
    if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
      say('This browser cannot record the screen.');
      return;
    }
    navigator.mediaDevices.getDisplayMedia({ video: true, audio: true })
      .then(function (s) {
        stream = s;
        chunks = [];
        recorder = new MediaRecorder(s, { mimeType: 'video/webm' });
        recorder.addEventListener('dataavailable', function (e) {
          if (e.data && e.data.size) { chunks.push(e.data); }
        });
        recorder.addEventListener('stop', function () {});
        recorder.onstop = function () {
          release();
          blob = new Blob(chunks, { type: 'video/webm' });
          if (url) { URL.revokeObjectURL(url); }
          url = URL.createObjectURL(blob);
          playback.src = url;
          playback.hidden = false;
          keep.hidden = false;
          say('Recorded ' + Math.round(blob.size / 1024) + ' kB. Watch it back before you keep it.');
        };
        // Stopping the share from the browser's own bar ends the recording
        // too, or the button and the browser disagree about whether one is
        // still running.
        s.getVideoTracks()[0].addEventListener('ended', function () {
          if (recorder && recorder.state !== 'inactive') { recorder.stop(); }
          stop.disabled = true;
          start.disabled = false;
        });
        recorder.start(1000);
        start.disabled = true;
        stop.disabled = false;
        say('Recording. Nothing has left this page.');
      })
      .catch(function () { say('Nothing was shared.'); });
  });

  stop.addEventListener('click', function () {
    if (recorder && recorder.state !== 'inactive') { recorder.stop(); }
    stop.disabled = true;
    start.disabled = false;
  });

  send.addEventListener('click', function () {
    if (!blob) { return; }
    var form = new FormData();
    form.append('file', blob, (name.value || 'screen-recording.webm'));
    form.append('alt', alt.value || '');
    send.disabled = true;
    sent.hidden = false;
    var req = new XMLHttpRequest();
    req.open('POST', '/upload');
    req.upload.addEventListener('progress', function (e) {
      if (e.lengthComputable) { sent.value = (e.loaded / e.total) * 100; }
    });
    req.addEventListener('load', function () {
      sent.hidden = true;
      send.disabled = false;
      done.hidden = false;
      done.textContent = req.responseText;
      if (req.status === 200) { keep.hidden = true; }
    });
    req.addEventListener('error', function () {
      sent.hidden = true;
      send.disabled = false;
      done.hidden = false;
      done.textContent = 'The upload did not finish.';
    });
    req.send(form);
  });
})();
</script>
</body></html>`
}

const studioCSS = `:root { color-scheme: light dark; --ink: #17211d; --paper: #f4f5f2;
  --rule: #ccd2ce; --quiet: #5a635e; --accent: #1f6b5b; }
@media (prefers-color-scheme: dark) { :root { --ink: #e3e7e4; --paper: #141715;
  --rule: #2c322e; --quiet: #9aa39d; --accent: #6dbda9; } }
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem 1.25rem; background: var(--paper); color: var(--ink);
  font: 16px/1.55 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
main { max-width: 44rem; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .75rem; letter-spacing: -.01em; }
.lead { font-size: 1.05rem; }
.hint { color: var(--quiet); font-size: .9rem; display: block; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .88em; }
label { display: block; font-weight: 600; margin-bottom: .25rem; }
input { font: inherit; padding: .45rem .6rem; border: 1px solid var(--rule);
  border-radius: 4px; background: var(--paper); color: var(--ink); width: 100%;
  max-width: 28rem; }
button { font: inherit; font-weight: 600; padding: .5rem .9rem; border: 0;
  border-radius: 4px; background: var(--accent); color: var(--paper); cursor: pointer; }
button:disabled { opacity: .5; cursor: default; }
.controls { display: flex; gap: .6rem; align-items: center; flex-wrap: wrap;
  margin: 1.25rem 0; }
.field { margin: 0 0 1rem; }
video { display: block; width: 100%; max-height: 24rem; background: #000;
  border-radius: 6px; margin: 1rem 0; }
progress { width: 100%; max-width: 28rem; }
.notice { border-left: 3px solid var(--accent); padding: .5rem .75rem;
  background: color-mix(in srgb, var(--accent) 8%, transparent); }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
`
