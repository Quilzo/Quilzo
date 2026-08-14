#!/usr/bin/env python3
"""Attacking the parts that claim to be safe.

A template engine advertising "no code execution" is a claim, and a claim about
security is worth exactly what its tests are worth. So the payloads below are
the ones that break real engines: sandbox escapes through Python's object graph,
XSS in the contexts people forget, and inputs designed to make rendering never
finish.

The store gets the same treatment. Content addressing is only useful if a
tampered object is actually detected rather than assumed not to happen.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

from scrivet.store import Commit, Store, StoreError, build_tree, commit
from scrivet.template import TemplateError, raw_sites, render

BOLD, DIM, GREEN, RED, RESET = "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[0m"
failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    if not ok:
        failures += 1
    print(f"  {GREEN}pass{RESET}  {label}" if ok else f"  {RED}FAIL{RESET}  {label}")
    if detail:
        print(f"        {DIM}{detail}{RESET}")


def blocked(source: str, data: dict | None = None) -> tuple[bool, str]:
    """True when a payload neither executes nor leaks."""
    try:
        out = render(source, data or {})
    except TemplateError as exc:
        return True, f"refused: {exc}"
    # Rendering to nothing is also a pass: the value was unreachable.
    leaked = any(bad in out for bad in
                 ("root:", "/bin", "posix", "<class", "builtins", "Popen", "os."))
    return (not leaked), (f"rendered {out[:60]!r}" if out else "rendered nothing")


def main() -> int:
    print(f"\n{BOLD}template sandbox: the payloads that break real engines{RESET}\n")

    escapes = [
        ("class hierarchy walk", "{{ page.__class__ }}"),
        ("mro to object subclasses", "{{ page.__class__.__mro__ }}"),
        ("globals via a function", "{{ page.__init__.__globals__ }}"),
        ("subclasses index", "{{ ''.__class__.__base__.__subclasses__ }}"),
        ("builtins reach", "{{ __builtins__ }}"),
        ("import attempt", "{% import os %}x{% end %}"),
        ("method call", "{{ page.title.upper() }}"),
        ("arbitrary expression", "{{ 1+1 }}"),
        ("attribute on a real object", "{{ store.root }}"),
        ("dunder in a loop source", "{% for x in page.__dict__ %}{{ x }}{% end %}"),
    ]
    for label, payload in escapes:
        ok, detail = blocked(payload, {"page": {"title": "hello"}})
        check(label, ok, detail)

    print(f"\n{BOLD}unknown tags are errors, not output{RESET}\n")
    for payload in ("{% exec %}x{% end %}", "{% include /etc/passwd %}",
                    "{% eval page %}"):
        try:
            render(payload, {})
            check(f"{payload[:24]}", False, "was accepted")
        except TemplateError as exc:
            check(f"{payload[:24]}", True, str(exc)[:60])

    print(f"\n{BOLD}escaping, including the contexts people forget{RESET}\n")

    out = render("<p>{{ c.body }}</p>", {"c": {"body": "<script>alert(1)</script>"}})
    check("script tags in text are escaped", "<script>" not in out, out[:56])

    out = render('<div class="{{ c.cls }}">x</div>', {"c": {"cls": '" onload="alert(1)'}})
    check("attribute break-out is escaped", 'onload="alert' not in out, out[:60])

    # The one a lot of engines miss: HTML-escaping does nothing to javascript:
    out = render('<a href="{{ c.url }}">go</a>', {"c": {"url": "javascript:alert(1)"}})
    check("javascript: in href is refused, not merely escaped",
          "javascript:" not in out, out[:60])

    out = render('<a href="{{ c.url }}">go</a>', {"c": {"url": "data:text/html,<script>x</script>"}})
    check("data: URLs are refused too", "data:text/html" not in out, out[:60])

    out = render('<a href="{{ c.url }}">go</a>', {"c": {"url": "https://example.com/a?b=1"}})
    check("an ordinary URL still works", "https://example.com" in out, out[:60])

    out = render("<p>{% raw c.body %}</p>", {"c": {"body": "<em>trusted</em>"}})
    check("raw passes markup through when asked", "<em>trusted</em>" in out)
    check("and every raw site is greppable",
          list(raw_sites("<p>{% raw c.body %}</p>{{ x }}")) == ["c.body"],
          "so extending trust is reviewable in aggregate")

    print(f"\n{BOLD}rendering always terminates{RESET}\n")

    deep = "{% for a in xs %}" * 20 + "x" + "{% end %}" * 20
    try:
        render(deep, {"xs": [1]})
        check("excessive nesting is refused", False, "was accepted")
    except TemplateError as exc:
        check("excessive nesting is refused", True, str(exc)[:50])

    big = {"xs": list(range(400))}
    huge = "{% for a in xs %}{% for b in xs %}{% for c in xs %}x{% end %}{% end %}{% end %}"
    try:
        render(huge, big)
        check("runaway iteration is capped", False, "completed 64M iterations")
    except TemplateError as exc:
        check("runaway iteration is capped", True, str(exc)[:50])

    check("an unclosed block is an error",
          blocked("{% if page.x %}forever")[0])

    print(f"\n{BOLD}missing data degrades, it does not crash{RESET}\n")
    out = render("<p>{{ a.b.c.d }}</p>", {"a": {}})
    check("a missing path renders empty", out == "<p></p>", repr(out))
    out = render("{% for x in nope %}{{ x }}{% end %}ok", {})
    check("looping over nothing is fine", out == "ok", repr(out))

    print(f"\n{BOLD}the store{RESET}\n")

    root = Path(tempfile.mkdtemp())
    try:
        s = Store(root)
        t1 = build_tree(s, {"index": {"title": "Home", "body": "one"},
                            "about": {"title": "About", "body": "two"}})
        c1 = commit(s, t1, message="first", author="rsh1k")
        s.set_ref("live", c1)

        check("the same content gets the same id",
              s.put_blob({"title": "Home", "body": "one"})
              == s.get_tree(t1)["index"],
              "identical content deduplicates rather than duplicating")

        t2 = build_tree(s, {"index": {"title": "Home", "body": "EDITED"},
                            "about": {"title": "About", "body": "two"}})
        c2 = commit(s, t2, message="edit", author="rsh1k", parents=(c1,))
        s.set_ref("live", c2)

        check("editing leaves the old version addressable",
              s.get_blob(s.get_tree(t1)["index"])["body"] == "one",
              "nothing is overwritten, so nothing needs restoring")
        check("the unchanged page is the same object",
              s.get_tree(t1)["about"] == s.get_tree(t2)["about"],
              "a tree shares everything that did not change")

        # Rollback is a pointer moving, which is why it cannot half-fail.
        s.set_ref("live", c1)
        check("rollback is a pointer move", s.get_ref("live") == c1)
        check("and the rolled-forward commit still exists", s.has(c2),
              "so it can be rolled forward again")

        hist = list(s.history(c2))
        check("history walks parents", [h[1].message for h in hist] == ["edit", "first"])

        ok, note = s.verify()
        check("every object verifies against its own id", ok, note)

        # Tampering must be detected, or content addressing is decoration.
        victim = s.get_tree(t1)["index"]
        path = root / "objects" / victim[:2] / victim[2:]
        path.write_bytes(b"blob\x00" + b'{"title":"Home","body":"TAMPERED"}')
        ok, note = s.verify()
        check("a tampered object is detected", not ok, note)
        try:
            s.get_blob(victim)
            check("and reading it fails rather than returning it", False,
                  "the altered content was served")
        except StoreError as exc:
            check("and reading it fails rather than returning it", True, str(exc)[:60])

        # Ids become paths, so traversal has to be impossible by construction.
        for bad in ("../../etc/passwd", "..", "a" * 63, "ZZ" + "a" * 62):
            try:
                s.get_blob(bad)
                check(f"path traversal via {bad[:18]!r} is refused", False, "accepted")
            except StoreError:
                check(f"path traversal via {bad[:18]!r} is refused", True)

        try:
            s.put_tree({"../evil": s.put_blob({"x": 1})})
            check("a traversing tree entry is refused", False, "accepted")
        except StoreError as exc:
            check("a traversing tree entry is refused", True, str(exc)[:50])

        try:
            s.set_ref("live", "0" * 64)
            check("a ref cannot point at a missing object", False, "accepted")
        except StoreError as exc:
            check("a ref cannot point at a missing object", True, str(exc)[:50])
    finally:
        shutil.rmtree(root, ignore_errors=True)

    print(f"\n{'all checks passed' if not failures else str(failures) + ' FAILED'}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
