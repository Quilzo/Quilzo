// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial
//
// New posts under a page, as they arrive. Each list marked data-live opens
// one event stream; when the stream says the thread changed, the page is
// fetched again and only that list is swapped for the fresh one, so a
// comment somebody is halfway through writing is never touched. Without
// this script a reload shows the same thing.
(function () {
  "use strict";
  if (!window.EventSource || !window.DOMParser) {
    return;
  }
  // Placed in the head, so it waits for the lists it looks for.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
  function start() {
  document.querySelectorAll("[data-live]").forEach(function (list) {
    var id = list.id;
    var status = document.createElement("p");
    status.className = "visually-hidden";
    status.setAttribute("role", "status");
    list.parentNode.insertBefore(status, list.nextSibling);
    var stream = new EventSource(list.getAttribute("data-live"));
    stream.addEventListener("changed", function () {
      fetch(location.pathname + location.search, { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.text() : null; })
        .then(function (html) {
          if (!html) {
            return;
          }
          var fresh = new DOMParser().parseFromString(html, "text/html").getElementById(id);
          var current = document.getElementById(id);
          if (!fresh || !current) {
            return;
          }
          var before = current.children.length;
          fresh.setAttribute("data-live", current.getAttribute("data-live"));
          current.replaceWith(document.importNode(fresh, true));
          var added = fresh.children.length - before;
          status.textContent = added > 0 ? (added === 1 ? "A new post." : added + " new posts.") : "";
        })
        .catch(function () {});
    });
    // A stream the server refuses or a page from a static host closes for
    // good rather than retrying forever.
    stream.addEventListener("error", function () {
      if (stream.readyState === EventSource.CLOSED) {
        stream.close();
      }
    });
  });
  }
})();
