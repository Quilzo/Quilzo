// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial
//
// A site's chatbot, answering in the visitor's browser on a static copy.
//
// The answer engine below is a port of internal/assistant's extractive mode:
// the same tokeniser, the same two rankers fused the same way, the same floor
// and the same quoting. The passages arrive with their term counts already
// worked out by the Go code, so only the question is tokenised here, and
// TestTheBrowserAnswersAsTheServerDoes runs this file against the Go answers.
//
// Every string reaches the page through textContent. Nothing is stored and
// nothing is sent: the one request this makes is for the passages.
(function () {
  "use strict";

  var reWord = /[\p{L}\p{Nd}]/u;
  var reSpace = /[\t\n\v\f\r \u0085 \p{Z}]/u;
  var reControl = /\p{Cc}/u;

  function utf8Length(s) {
    var n = 0;
    for (var ch of s) {
      var cp = ch.codePointAt(0);
      n += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    }
    return n;
  }

  // search.Tokenise.
  function tokenise(text, maxTerm) {
    var out = [];
    var cur = [];
    function flush() {
      if (cur.length > 1 && cur.length <= maxTerm) {
        out.push(cur.join(""));
      }
      cur = [];
    }
    for (var ch of text) {
      if (reWord.test(ch)) {
        // unicode.ToLower maps one rune to one rune; toLowerCase can give
        // two, and the first of them is the simple mapping.
        var lower = Array.from(ch.toLowerCase())[0];
        cur.push(lower);
      } else if (ch === "'" && cur.length > 0) {
        // Inside a word, an apostrophe is part of it: dropped, not a split.
      } else {
        flush();
      }
    }
    flush();
    return out;
  }

  // assistant.fold. Lengths are in bytes, as Go's len is.
  function fold(t) {
    var n = utf8Length(t);
    if (n >= 7 && t.endsWith("ing")) {
      return t.slice(0, -3);
    }
    if (n >= 6 && t.endsWith("ed") && !t.endsWith("eed")) {
      return t.slice(0, -2);
    }
    if (n < 4 || t[t.length - 1] !== "s") {
      return t;
    }
    var before = t[t.length - 2];
    if (before === "s" || before === "u" || before === "i") {
      return t;
    }
    return t.slice(0, -1);
  }

  function isSpace(ch) {
    return reSpace.test(ch);
  }

  // strings.Fields.
  function fields(s) {
    var out = [];
    var cur = "";
    for (var ch of s) {
      if (isSpace(ch)) {
        if (cur !== "") {
          out.push(cur);
        }
        cur = "";
      } else {
        cur += ch;
      }
    }
    if (cur !== "") {
      out.push(cur);
    }
    return out;
  }

  // assistant.oneLine.
  function oneLine(s) {
    var kept = "";
    for (var ch of s) {
      if (reControl.test(ch) && ch !== "\n" && ch !== "\t") {
        continue;
      }
      kept += ch;
    }
    return fields(kept).join(" ");
  }

  // Cut at a byte length, never inside a character.
  function cutBytes(s, max) {
    var out = "";
    var n = 0;
    for (var ch of s) {
      var w = utf8Length(ch);
      if (n + w > max) {
        break;
      }
      out += ch;
      n += w;
    }
    return out;
  }

  // assistant.sentences.
  function sentences(text) {
    var out = [];
    var chars = Array.from(text);
    var cur = "";
    for (var i = 0; i < chars.length; i++) {
      var ch = chars[i];
      cur += ch;
      if (ch === "." || ch === "?" || ch === "!") {
        if (i + 1 === chars.length || isSpace(chars[i + 1])) {
          var done = cur.trim();
          if (done !== "") {
            out.push(done);
          }
          cur = "";
        }
      }
    }
    var rest = cur.trim();
    if (rest !== "") {
      out.push(rest);
    }
    return out;
  }

  function byteCompare(a, b) {
    // Go compares strings byte by byte; for the ASCII identifiers this is
    // used on, code unit order is the same thing.
    return a < b ? -1 : a > b ? 1 : 0;
  }

  // Engine is the index over one knowledge file.
  function Engine(k) {
    this.k = k;
    this.stop = new Set(k.stopwords);
    this.df = new Map();
    this.docs = 0;
    var total = 0;
    var self = this;
    k.passages.forEach(function (p) {
      total += p.len;
      var terms = Object.keys(p.tf);
      if (terms.length > 0) {
        self.docs++;
      }
      terms.forEach(function (t) {
        self.df.set(t, (self.df.get(t) || 0) + 1);
      });
    });
    this.avgLen = k.passages.length > 0 ? total / k.passages.length : 0;
    // The vector leg's keys and weights, as internal/vector builds them.
    this.vectors = k.passages.map(function (p, i) {
      return {
        key: String.fromCharCode(97 + (i % 26)) + String(i),
        i: i,
        w: self.weigh(p.tf),
      };
    }).filter(function (v) {
      return v.w.size > 0;
    });
  }

  Engine.prototype.tokens = function (s) {
    return tokenise(s, this.k.max_term).map(fold);
  };

  // vector.weigh.
  Engine.prototype.weigh = function (tf) {
    var w = new Map();
    var norm = 0;
    var docs = this.docs;
    var df = this.df;
    Object.keys(tf).forEach(function (t) {
      var x = (1 + Math.log(tf[t])) *
        (Math.log((docs + 1) / ((df.get(t) || 0) + 1)) + 1);
      w.set(t, x);
      norm += x * x;
    });
    if (norm > 0) {
      norm = Math.sqrt(norm);
      w.forEach(function (x, t) {
        w.set(t, x / norm);
      });
    }
    return w;
  };

  // assistant.informative.
  Engine.prototype.informative = function (ts) {
    var seen = new Set();
    var out = [];
    var n = this.k.passages.length;
    for (var t of ts) {
      if (seen.has(t)) {
        continue;
      }
      seen.add(t);
      if (n >= 6 && (this.df.get(t) || 0) > 0.5 * n) {
        continue;
      }
      if (this.stop.has(t)) {
        continue;
      }
      out.push(t);
    }
    return out;
  };

  // Index.Retrieve.
  Engine.prototype.retrieve = function (question, depth) {
    var k = this.k;
    var ps = k.passages;
    if (ps.length === 0 || depth <= 0) {
      return [];
    }
    var q = this.informative(this.tokens(question));
    if (q.length === 0) {
      return [];
    }
    var n = ps.length;
    var bm = [];
    for (var i = 0; i < n; i++) {
      var tf = ps[i].tf;
      var s = 0;
      for (var t of q) {
        var f = tf[t] || 0;
        if (f === 0) {
          continue;
        }
        var df = this.df.get(t) || 0;
        var idf = Math.log(1 + (n - df + 0.5) / (df + 0.5));
        s += idf * (f * (k.k1 + 1) /
          (f + k.k1 * (1 - k.b + k.b * ps[i].len / this.avgLen)));
      }
      if (s > 0) {
        bm.push({ i: i, s: s });
      }
    }
    bm.sort(function (a, b) {
      return a.s !== b.s ? b.s - a.s : a.i - b.i;
    });

    var fused = new Map();
    function get(i) {
      var h = fused.get(i);
      if (!h) {
        h = { i: i, score: 0, matched: [] };
        fused.set(i, h);
      }
      return h;
    }
    var limit = 50;
    for (var r = 0; r < bm.length && r < limit; r++) {
      get(bm[r].i).score += 1 / (k.rrf + r + 1);
    }

    // The question's vector, against every passage's.
    var qtf = {};
    for (var tok of this.tokens(question)) {
      qtf[tok] = (qtf[tok] || 0) + 1;
    }
    var qv = this.weigh(qtf);
    var near = [];
    for (var v of this.vectors) {
      var small = qv.size <= v.w.size ? qv : v.w;
      var big = small === qv ? v.w : qv;
      var dot = 0;
      small.forEach(function (x, term) {
        var y = big.get(term);
        if (y !== undefined) {
          dot += x * y;
        }
      });
      if (dot > 0) {
        near.push({ key: v.key, i: v.i, s: dot });
      }
    }
    near.sort(function (a, b) {
      return a.s !== b.s ? b.s - a.s : byteCompare(a.key, b.key);
    });
    for (var r2 = 0; r2 < near.length && r2 < limit; r2++) {
      get(near[r2].i).score += 1 / (k.rrf + r2 + 1);
    }

    // The third leg: passages whose heading covers the whole question,
    // tighter headings first.
    var heads = [];
    for (var j = 0; j < n; j++) {
      var ht = ps[j].ht || [];
      if (ht.length === 0) {
        continue;
      }
      var set = new Set(ht);
      if (q.every(function (t) { return set.has(t); })) {
        heads.push({ i: j, size: set.size });
      }
    }
    heads.sort(function (a, b) {
      return a.size !== b.size ? a.size - b.size : a.i - b.i;
    });
    for (var r3 = 0; r3 < heads.length && r3 < limit; r3++) {
      get(heads[r3].i).score += 1 / (k.rrf + r3 + 1);
    }

    var out = [];
    fused.forEach(function (h) {
      for (var t of q) {
        if ((ps[h.i].tf[t] || 0) > 0) {
          h.matched.push(t);
        }
      }
      if (h.matched.length === 0 || h.matched.length < k.coverage * q.length) {
        return;
      }
      out.push(h);
    });
    out.sort(function (a, b) {
      if (a.score !== b.score) {
        return b.score - a.score;
      }
      return byteCompare(ps[a.i].id, ps[b.i].id);
    });
    return out.slice(0, depth);
  };

  // assistant.extract.
  Engine.prototype.extract = function (question, hits) {
    if (hits.length === 0) {
      return [];
    }
    var text = this.k.passages[hits[0].i].text;
    var all = sentences(text);
    if (fields(text).length <= this.k.short) {
      return all;
    }
    var q = new Set();
    for (var t of this.tokens(question)) {
      if (!this.stop.has(t)) {
        q.add(t);
      }
    }
    var cs = [];
    var self = this;
    all.forEach(function (s, i) {
      var n = 0;
      for (var w of self.tokens(s)) {
        if (q.has(w)) {
          n++;
        }
      }
      if (n > 0) {
        cs.push({ i: i, score: n });
      }
    });
    // Array.prototype.sort is stable, as sort.SliceStable is.
    cs.sort(function (a, b) {
      return b.score - a.score;
    });
    var keep = new Set();
    for (var c of cs) {
      if (keep.size >= 4) {
        break;
      }
      keep.add(c.i);
      if (c.i + 1 < all.length) {
        keep.add(c.i + 1);
      }
    }
    return all.filter(function (_, i) {
      return keep.has(i);
    });
  };

  // assistant.RespondTo, without a model.
  Engine.prototype.respond = function (question, previous) {
    var k = this.k;
    question = oneLine(question || "");
    if (question === "") {
      return { problem: "Ask a question." };
    }
    if (utf8Length(question) > k.max_question) {
      return { problem: "That is over " + k.max_question +
        " characters; ask it more briefly." };
    }
    previous = cutBytes(oneLine(previous || ""), k.max_question);
    var asked = question;
    var hits = this.retrieve(question, k.depth);
    if (hits.length === 0 && previous !== "") {
      asked = previous + " " + question;
      hits = this.retrieve(asked, k.depth);
    }
    var ans = { question: question, hits: hits, sentences: [], refused: false };
    if (hits.length === 0) {
      ans.refused = true;
      ans.why = "nothing on this site is about that";
      return ans;
    }
    ans.sentences = this.extract(asked, hits);
    if (ans.sentences.length === 0) {
      ans.refused = true;
      ans.why = "the passages found do not contain an answer";
    }
    return ans;
  };

  var engine = { Engine: Engine, tokenise: tokenise, fold: fold,
    sentences: sentences, oneLine: oneLine };

  // A test harness defines this and receives the engine; a browser never
  // does, and gets the page below.
  if (typeof globalThis.__quilzoAskHarness === "function") {
    globalThis.__quilzoAskHarness(engine);
    return;
  }
  if (typeof document === "undefined") {
    return;
  }

  // -- the page --------------------------------------------------------------

  var form = document.getElementById("qz-form");
  var box = document.getElementById("q");
  var log = document.getElementById("qz-log");
  var status = document.getElementById("qz-status");
  if (!form || !box || !log || !status) {
    return;
  }
  // The form's action is the one address the static copy rewrote for the
  // directory it lives in, so everything else is found relative to it.
  var action = new URL(form.getAttribute("action"), document.baseURI);
  var page = action.pathname.replace(/\/+$/, "");
  var root = page.slice(0, page.lastIndexOf("/ask/"));
  var current = null;
  var previous = "";

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) {
      e.className = cls;
    }
    if (text !== undefined) {
      e.textContent = text;
    }
    return e;
  }

  function show(question, ans, k) {
    var turn = el("section", "qz-turn qz-q-turn");
    turn.setAttribute("aria-label", "Your question");
    turn.appendChild(el("p", "qz-q", question));
    log.appendChild(turn);

    var reply = el("section", "qz-turn qz-a" + (ans.refused ? " qz-refused" : ""));
    reply.setAttribute("aria-label", "Answer");
    if (ans.refused) {
      reply.appendChild(el("p", "", k.refusal));
    } else {
      var n = log.querySelectorAll(".qz-a").length + 1;
      var id = "src-" + n;
      // One passage is quoted, so one citation, after the quote: a marker on
      // every sentence of it would say the same thing each time.
      var p = el("p", "", ans.sentences.join(" ") + " ");
      var sup = el("sup");
      var a = el("a", "", "[1]");
      a.href = "#" + id;
      sup.appendChild(a);
      p.appendChild(sup);
      reply.appendChild(p);
      var best = k.passages[ans.hits[0].i];
      reply.appendChild(el("h2", "qz-sources-title", "Source"));
      var list = el("ol", "qz-sources");
      var li = el("li");
      li.id = id;
      var link = el("a", "", best.header || best.href);
      link.href = root + best.href;
      li.appendChild(link);
      list.appendChild(li);
      reply.appendChild(list);
    }
    log.appendChild(reply);
    announce(ans.refused ? k.refusal : "Answered from " +
      (k.passages[ans.hits[0].i].header || "this site") + ".");
    reply.scrollIntoView({ block: "nearest" });
  }

  // An answer is announced, for somebody who cannot see it arrive, and not
  // shown twice to somebody who can. A problem is shown.
  function announce(text) {
    status.className = "qz-status qz-sr";
    status.textContent = text;
  }
  function problem(text) {
    status.className = "qz-status";
    status.textContent = text;
  }

  function ask(question) {
    if (!current) {
      return;
    }
    var ans = current.engine.respond(question, previous);
    if (ans.problem) {
      problem(ans.problem);
      return;
    }
    show(ans.question, ans, current.k);
    previous = ans.question;
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var q = box.value;
    ask(q);
    box.value = "";
    box.focus();
  });
  box.addEventListener("keydown", function (e) {
    // Enter asks, Shift+Enter is a new line: what every chat box does.
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      form.requestSubmit();
    }
  });

  announce("Loading what this chatbot answers from.");
  fetch(page + "/knowledge.json", { credentials: "omit" })
    .then(function (r) {
      if (!r.ok) {
        throw new Error(String(r.status));
      }
      return r.json();
    })
    .then(function (k) {
      if (!k || k.v !== 1 || !Array.isArray(k.passages)) {
        throw new Error("version");
      }
      current = { k: k, engine: new Engine(k) };
      form.removeAttribute("aria-busy");
      announce("");
      var q = new URLSearchParams(location.search).get("q");
      if (q) {
        ask(q);
      }
    })
    .catch(function () {
      problem("This chatbot could not load what it answers from. Reload " +
        "the page to try again.");
    });
})();
