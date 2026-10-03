// The site's assistant, opened beside the page. Without this script the
// button is a link to the conversation page, which works everywhere; this
// only keeps the visitor where they were. Allowed by its hash, on the pages
// that carry the button and nowhere else.
(function () {
  "use strict";
  var root = document.querySelector("[data-qz-agent]");
  if (!root) return;
  var button = root.querySelector(".qz-launch-btn");
  var src = root.getAttribute("data-qz-agent");
  var title = root.getAttribute("data-title") || "Assistant";
  var mode = root.getAttribute("data-panel") === "side" ? "side" : "float";
  var name = root.getAttribute("data-name") || "agent";
  var openKey = "qz-agent-open:" + name;
  var seenKey = "qz-nudge-seen:" + name;
  var goneKey = "qz-nudge-gone:" + name;
  var html = document.documentElement;
  var panel = null, frame = null, nudge = null;

  // Storage can be refused (private windows, blocked site data); the
  // launcher works without it, it only forgets more.
  function get(store, key) { try { return window[store].getItem(key); } catch (e) { return null; } }
  function set(store, key, value) {
    try { if (value === null) window[store].removeItem(key); else window[store].setItem(key, value); } catch (e) {}
  }

  function svg(path) {
    var ns = "http://www.w3.org/2000/svg";
    var s = document.createElementNS(ns, "svg");
    s.setAttribute("viewBox", "0 -960 960 960");
    s.setAttribute("aria-hidden", "true");
    s.setAttribute("focusable", "false");
    var p = document.createElementNS(ns, "path");
    p.setAttribute("d", path);
    s.appendChild(p);
    return s;
  }
  var closePath = root.getAttribute("data-close-icon");

  function build() {
    panel = document.createElement("section");
    panel.id = "qz-agent-panel";
    panel.className = "qz-panel qz-panel-" + mode + " qz-panel-" + (root.getAttribute("data-side") || "right");
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-modal", "false");
    panel.setAttribute("aria-labelledby", "qz-agent-title");
    panel.hidden = true;
    var head = document.createElement("div");
    head.className = "qz-panel-head";
    var h = document.createElement("h2");
    h.id = "qz-agent-title";
    h.textContent = title;
    var close = document.createElement("button");
    close.type = "button";
    close.className = "qz-panel-close";
    close.setAttribute("aria-label", "Close " + title);
    if (closePath) close.appendChild(svg(closePath)); else close.textContent = "×";
    close.addEventListener("click", function () { hide(true); });
    head.appendChild(h);
    head.appendChild(close);
    frame = document.createElement("iframe");
    frame.className = "qz-panel-frame";
    frame.title = title;
    frame.src = src;
    panel.appendChild(head);
    panel.appendChild(frame);
    document.body.appendChild(panel);
  }

  function show(focus) {
    if (!panel) build();
    panel.hidden = false;
    button.setAttribute("aria-expanded", "true");
    html.classList.add("qz-agent-open", "qz-agent-" + mode);
    set("sessionStorage", openKey, "1");
    dismissNudge(false);
    if (focus) {
      // Into the conversation, once it is there to receive focus.
      var go = function () { try { frame.focus(); } catch (e) {} };
      if (frame.contentDocument && frame.contentDocument.readyState === "complete") go();
      else frame.addEventListener("load", go, { once: true });
    }
  }

  function hide(focus) {
    if (!panel) return;
    panel.hidden = true;
    button.setAttribute("aria-expanded", "false");
    html.classList.remove("qz-agent-open", "qz-agent-" + mode);
    set("sessionStorage", openKey, null);
    if (focus) button.focus();
  }

  button.setAttribute("role", "button");
  button.setAttribute("aria-expanded", "false");
  button.setAttribute("aria-controls", "qz-agent-panel");
  button.addEventListener("click", function (e) {
    e.preventDefault();
    if (panel && !panel.hidden) hide(false); else show(true);
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && panel && !panel.hidden) hide(true);
  });

  // Open on this page if it was open on the last: the conversation follows
  // the visitor around the site rather than closing on every link.
  if (get("sessionStorage", openKey)) show(false);

  // -- the nudge ---------------------------------------------------------
  // Once a visit, never once dismissed (for thirty days), never as a
  // modal, and on a small screen only after the visitor has scrolled past
  // the first screen: a line beside the button, not a door in the way.
  var text = root.getAttribute("data-nudge");
  var after = parseInt(root.getAttribute("data-nudge-after") || "20", 10) * 1000;
  function dismissNudge(forever) {
    if (nudge) { nudge.remove(); nudge = null; }
    if (forever) set("localStorage", goneKey, String(Date.now()));
  }
  function nudgeAllowed() {
    if (!text || get("sessionStorage", seenKey)) return false;
    var gone = parseInt(get("localStorage", goneKey) || "0", 10);
    return !gone || Date.now() - gone > 30 * 24 * 3600 * 1000;
  }
  function showNudge() {
    if (!nudgeAllowed() || (panel && !panel.hidden) || document.hidden) return;
    if (window.innerWidth < 600 && window.scrollY < window.innerHeight) return;
    set("sessionStorage", seenKey, "1");
    nudge = document.createElement("div");
    nudge.className = "qz-nudge";
    nudge.setAttribute("role", "status");
    var open = document.createElement("button");
    open.type = "button";
    open.className = "qz-nudge-text";
    open.textContent = text;
    open.addEventListener("click", function () { show(true); });
    var x = document.createElement("button");
    x.type = "button";
    x.className = "qz-nudge-close";
    x.setAttribute("aria-label", "Dismiss");
    if (closePath) x.appendChild(svg(closePath)); else x.textContent = "×";
    x.addEventListener("click", function () { dismissNudge(true); button.focus(); });
    nudge.appendChild(open);
    nudge.appendChild(x);
    root.appendChild(nudge);
  }
  if (text && nudgeAllowed()) {
    var due = Date.now() + after;
    var check = function () {
      if (!nudgeAllowed() || nudge) return;
      if (Date.now() >= due) showNudge();
      if (!nudge && nudgeAllowed()) setTimeout(check, 1000);
    };
    setTimeout(check, after);
  }
})();
