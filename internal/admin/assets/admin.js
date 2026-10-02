// Quilzo admin: the one script.
//
// Everything here is an addition. Every screen works with it switched off,
// because a browser that blocks it, a policy that forbids it, or a person who
// disabled scripts should lose speed, not features.
//
// It does three things:
//
//   * a command palette, opened with Ctrl+K (⌘K on a Mac) or the button in
//     the search box, which jumps to any screen in the navigation by typing
//     part of its name, and offers to search for anything else;
//   * "/" moves to the search box, as it does on most sites people use;
//   * the menu control collapses the menu to a rail and back at once,
//     rather than by loading the page again. The form it submits is the
//     same one, so the choice is kept the same way, and without the script
//     it still works;
//   * on the rail, pointing at a section opens its flyout after a moment
//     and moving away closes it, as Gmail's does. Clicking, Enter and
//     Escape work without the script; this only adds the pointer.
//
// The palette is a native <dialog> with the ARIA combobox pattern: the
// input owns a listbox, arrow keys move the active option, Enter opens it,
// Escape closes. It reads the destinations from the navigation already on
// the page, so it can never offer a screen this person may not open.
(function () {
  "use strict";

  var mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

  function destinations() {
    var out = [];
    document.querySelectorAll(".navgroup").forEach(function (group) {
      var heading = group.querySelector("summary h2");
      var section = heading ? heading.textContent.trim() : "";
      group.querySelectorAll(".nav a[href]").forEach(function (a) {
        out.push({ label: a.textContent.trim(), section: section, href: a.getAttribute("href") });
      });
    });
    return out;
  }

  // Letters in order, not necessarily together: "fw" finds Frameworks.
  // A match at the start of a word ranks first, then a match anywhere.
  function score(label, query) {
    var l = label.toLowerCase(), q = query.toLowerCase().trim();
    if (!q) return 1;
    if (l.indexOf(q) === 0) return 4;
    if (l.indexOf(" " + q) >= 0) return 3;
    if (l.indexOf(q) >= 0) return 2;
    var i = 0;
    for (var c = 0; c < l.length && i < q.length; c++) {
      if (l[c] === q[i]) i++;
    }
    return i === q.length ? 1 : 0;
  }

  var dialog, input, list, items = [], active = -1;

  function build() {
    dialog = document.createElement("dialog");
    dialog.className = "palette";
    dialog.setAttribute("aria-label", "Go to a screen");

    var label = document.createElement("label");
    label.className = "visually-hidden";
    label.htmlFor = "palette-input";
    label.textContent = "Go to a screen, or search";

    input = document.createElement("input");
    input.id = "palette-input";
    input.type = "text";
    input.autocomplete = "off";
    input.spellcheck = false;
    input.placeholder = "Go to a screen, or search…";
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-expanded", "true");
    input.setAttribute("aria-controls", "palette-list");
    input.setAttribute("aria-autocomplete", "list");

    list = document.createElement("ul");
    list.id = "palette-list";
    list.setAttribute("role", "listbox");
    list.setAttribute("aria-label", "Screens");

    var hint = document.createElement("p");
    hint.className = "palette-hint";
    hint.textContent = "↑ ↓ to move · Enter to open · Esc to close";

    dialog.appendChild(label);
    dialog.appendChild(input);
    dialog.appendChild(list);
    dialog.appendChild(hint);
    document.body.appendChild(dialog);

    input.addEventListener("input", render);
    input.addEventListener("keydown", keys);
    list.addEventListener("click", function (e) {
      var li = e.target.closest("li[role=option]");
      if (li) go(Number(li.dataset.index));
    });
    dialog.addEventListener("click", function (e) {
      if (e.target === dialog) dialog.close();
    });
  }

  function render() {
    var q = input.value;
    var all = destinations().map(function (d) {
      return { d: d, s: Math.max(score(d.label, q), score(d.section, q) > 2 ? 1 : 0) };
    }).filter(function (x) { return x.s > 0; });
    all.sort(function (a, b) { return b.s - a.s; });
    items = all.slice(0, 12).map(function (x) { return x.d; });
    if (q.trim()) {
      items.push({ label: "Search for “" + q.trim() + "”", section: "Search",
                   href: "/find?q=" + encodeURIComponent(q.trim()) });
    }
    list.textContent = "";
    items.forEach(function (d, i) {
      var li = document.createElement("li");
      li.id = "palette-opt-" + i;
      li.setAttribute("role", "option");
      li.dataset.index = String(i);
      var name = document.createElement("span");
      name.className = "palette-name";
      name.textContent = d.label;
      var where = document.createElement("span");
      where.className = "palette-where";
      where.textContent = d.section;
      li.appendChild(name);
      li.appendChild(where);
      list.appendChild(li);
    });
    move(items.length ? 0 : -1);
  }

  function move(i) {
    active = i;
    list.querySelectorAll("[role=option]").forEach(function (li, n) {
      li.setAttribute("aria-selected", n === i ? "true" : "false");
      if (n === i) li.scrollIntoView({ block: "nearest" });
    });
    if (i >= 0) input.setAttribute("aria-activedescendant", "palette-opt-" + i);
    else input.removeAttribute("aria-activedescendant");
  }

  function keys(e) {
    if (e.key === "ArrowDown") { e.preventDefault(); move(Math.min(active + 1, items.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); move(Math.max(active - 1, 0)); }
    else if (e.key === "Enter" && active >= 0) { e.preventDefault(); go(active); }
  }

  function go(i) {
    var d = items[i];
    if (!d) return;
    // Closed first: a page left with a modal dialog open makes the
    // cross-fade between pages give up, with an error in the console.
    dialog.close();
    window.location.assign(d.href);
  }

  function open() {
    if (!dialog) build();
    input.value = "";
    render();
    dialog.showModal();
    input.focus();
  }

  document.addEventListener("keydown", function (e) {
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) ||
      document.activeElement.isContentEditable;
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "k") {
      e.preventDefault();
      open();
    } else if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey) {
      var find = document.getElementById("findq");
      if (find) { e.preventDefault(); find.focus(); }
    }
  });

  document.querySelectorAll("form.navtoggle").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!window.fetch) return;
      e.preventDefault();
      var to = form.elements.to, button = form.querySelector("button");
      var hide = to.value === "hidden";
      var menu = document.getElementById("sitenav");
      if (menu && menu.matches && menu.matches(":popover-open")) menu.hidePopover();
      fetch(form.action, { method: "POST", body: new URLSearchParams(new FormData(form)),
        credentials: "same-origin", redirect: "manual" }).then(function (r) {
        if (r.type !== "opaqueredirect" && !r.ok) throw new Error(String(r.status));
        document.body.classList.toggle("nav-hidden", hide);
        to.value = hide ? "shown" : "hidden";
        button.setAttribute("aria-expanded", hide ? "false" : "true");
        var tip = (hide ? "Expand" : "Collapse") + " the menu";
        if (button.dataset.tip) button.dataset.tip = tip; else button.title = tip;
      }).catch(function () { form.submit(); });
    });
  });

  // The rail opens the menu beside the button that was used, with that
  // section open and the others closed, so the panel is that section.
  var menu = document.getElementById("sitenav"), from = null;
  function place(btn) {
    var r = menu.getBoundingClientRect(), b = btn.getBoundingClientRect();
    if (Math.abs(r.left - (b.right + 4)) <= 2 && r.top >= 0 && r.bottom <= innerHeight) return;
    menu.style.positionArea = "none";
    menu.style.left = (b.right + 4) + "px";
    menu.style.top = Math.max(8, Math.min(b.top, innerHeight - r.height - 8)) + "px";
  }
  function section(btn) {
    from = btn;
    document.querySelectorAll(".railitem.open").forEach(function (o) { o.classList.remove("open"); });
    btn.classList.add("open");
    menu.querySelectorAll(".navgroup").forEach(function (g) {
      g.open = g.getAttribute("data-section") === btn.getAttribute("data-section");
      // Its heading is a heading here, not a control that would empty the panel.
      g.querySelector("summary").tabIndex = -1;
    });
    menu.classList.add("one-section");
  }
  // While it is one section, its heading does not fold it away.
  if (menu) menu.addEventListener("click", function (e) {
    if (menu.classList.contains("one-section") && e.target.closest("summary")) e.preventDefault();
  });
  if (menu && menu.showPopover) {
    var opening, closing;
    var hovering = function (e) { return e.pointerType === "mouse" && document.body.classList.contains("nav-hidden"); };
    document.querySelectorAll(".railitem").forEach(function (btn) {
      btn.addEventListener("click", function () { section(btn); });
      btn.addEventListener("pointerenter", function (e) {
        if (!hovering(e)) return;
        clearTimeout(closing);
        opening = setTimeout(function () {
          section(btn);
          if (menu.matches(":popover-open")) { menu.style.left = menu.style.top = ""; menu.style.positionArea = ""; menu.hidePopover(); }
          menu.showPopover({ source: btn });
        }, 150);
      });
      btn.addEventListener("pointerleave", function (e) { if (hovering(e)) leave(); });
    });
    menu.addEventListener("pointerenter", function () { clearTimeout(closing); });
    menu.addEventListener("pointerleave", function (e) { if (hovering(e)) leave(); });
    function leave() {
      clearTimeout(opening);
      closing = setTimeout(function () {
        if (menu.matches(":popover-open") && !menu.contains(document.activeElement)) menu.hidePopover();
      }, 300);
    }
    menu.addEventListener("toggle", function (e) {
      if (e.newState === "open" && from && document.body.classList.contains("nav-hidden")) place(from);
      if (e.newState === "closed") {
        menu.style.left = menu.style.top = ""; menu.style.positionArea = "";
        menu.classList.remove("one-section");
        menu.querySelectorAll(".navgroup > summary").forEach(function (s) { s.removeAttribute("tabindex"); });
        document.querySelectorAll(".railitem.open").forEach(function (o) { o.classList.remove("open"); });
      }
    });
  }

  // Plain tooltips, as Material draws them: a control's title shown after
  // a moment of pointing, or at once on keyboard focus, below it (above
  // when there is no room), gone on leaving or Escape. Taken from the
  // title so the browser's own does not appear as well; screen readers
  // already hear each control's name, so the tooltip is hidden from them.
  var tooltip = null, tipping;
  function tipShow(el) {
    if (!tooltip) {
      tooltip = document.createElement("div");
      tooltip.className = "tooltip";
      tooltip.setAttribute("popover", "manual");
      tooltip.setAttribute("aria-hidden", "true");
      document.body.appendChild(tooltip);
    }
    if (!tooltip.showPopover) return;
    tooltip.textContent = el.dataset.tip;
    if (!tooltip.matches(":popover-open")) tooltip.showPopover();
    var r = el.getBoundingClientRect(), t = tooltip.getBoundingClientRect();
    var left = Math.max(8, Math.min(r.left + r.width / 2 - t.width / 2, innerWidth - t.width - 8));
    var top = r.bottom + 4;
    if (top + t.height > innerHeight - 8) top = r.top - t.height - 4;
    tooltip.style.left = left + "px";
    tooltip.style.top = top + "px";
  }
  function tipHide() {
    clearTimeout(tipping);
    if (tooltip && tooltip.matches(":popover-open")) tooltip.hidePopover();
  }
  document.querySelectorAll("header.bar [title], .iconbutton[title], .rowmenu-open[title]").forEach(function (el) {
    el.dataset.tip = el.title;
    el.removeAttribute("title");
    el.addEventListener("pointerenter", function (e) {
      if (e.pointerType !== "mouse") return;
      clearTimeout(tipping);
      tipping = setTimeout(function () { tipShow(el); }, 500);
    });
    el.addEventListener("pointerleave", tipHide);
    el.addEventListener("focus", function () { if (el.matches(":focus-visible")) tipShow(el); });
    el.addEventListener("blur", tipHide);
    el.addEventListener("click", tipHide);
  });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") tipHide(); });

  // The shortcut, shown where people look for search, in their platform's
  // spelling. Only once the script is running, since it is what makes it work.
  document.querySelectorAll("[data-palette]").forEach(function (b) {
    b.hidden = false;
    var k = b.querySelector("kbd");
    if (k) k.textContent = mac ? "⌘K" : "Ctrl K";
    b.addEventListener("click", open);
  });
})();
