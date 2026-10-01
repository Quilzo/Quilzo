// Quilzo admin: the one script.
//
// Everything here is an addition. Every screen works with it switched off,
// because a browser that blocks it, a policy that forbids it, or a person who
// disabled scripts should lose speed, not features.
//
// It does two things:
//
//   * a command palette, opened with Ctrl+K (⌘K on a Mac) or the button in
//     the search box, which jumps to any screen in the navigation by typing
//     part of its name, and offers to search for anything else;
//   * "/" moves to the search box, as it does on most sites people use.
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

  // The shortcut, shown where people look for search, in their platform's
  // spelling. Only once the script is running, since it is what makes it work.
  document.querySelectorAll("[data-palette]").forEach(function (b) {
    b.hidden = false;
    var k = b.querySelector("kbd");
    if (k) k.textContent = mac ? "⌘K" : "Ctrl K";
    b.addEventListener("click", open);
  });
})();
