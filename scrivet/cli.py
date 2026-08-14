"""The command line. Everything the CMS does is here first.

There is no admin panel yet, and that ordering is deliberate rather than a
shortcut. A CMS whose primitives only exist behind a web UI cannot be scripted,
reviewed in a pull request, or driven by an assistant without pretending to be a
browser. Building the UI on top of a complete CLI keeps every action available
to a person, a script and an agent on equal terms.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .site import DRAFT, LIVE, diff, pages_at, publish, rollback, save_draft
from .store import Store, StoreError
from .template import TemplateError, raw_sites, render

BOLD, DIM, GREEN, YELLOW, RED, RESET = (
    "\033[1m", "\033[2m", "\033[32m", "\033[33m", "\033[31m", "\033[0m")

DEFAULT_ROOT = ".scrivet"


def _store(args: argparse.Namespace) -> Store:
    return Store(args.root)


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.root)
    existed = root.exists()
    Store(root)
    print(f"{'reusing' if existed else 'created'} {root}")
    if not existed:
        print(f"  {DIM}content is immutable and addressed by hash; "
              f"publishing moves a pointer{RESET}")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    """Stage pages into a new draft commit."""
    store = _store(args)
    parent = store.get_ref(DRAFT) or store.get_ref(LIVE)
    pages = pages_at(store, parent) if parent else {}

    for spec in args.page:
        name, _, path = spec.partition("=")
        if not path:
            print(f"expected name=file.json, got {spec!r}", file=sys.stderr)
            return 2
        try:
            pages[name] = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"cannot read {path}: {exc}", file=sys.stderr)
            return 1

    for name in args.remove or ():
        pages.pop(name, None)

    cid = save_draft(store, pages, message=args.message, author=args.author)
    print(f"draft {cid[:12]}  {len(pages)} page(s)")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    store = _store(args)
    live, draft = store.get_ref(LIVE), store.get_ref(DRAFT)
    if not draft:
        print("no draft")
        return 0
    if live == draft:
        print("draft matches live")
        return 0

    changes = diff(store, live, draft)
    if not changes:
        print("no content differences")
        return 0
    colour = {"added": GREEN, "removed": RED, "modified": YELLOW}
    for c in changes:
        print(f"  {colour[c.kind]}{c.kind:<9}{RESET} {c.path}")
    print(f"\n  {len(changes)} change(s) between live and draft")
    return 0


def cmd_publish(args: argparse.Namespace) -> int:
    store = _store(args)
    try:
        pub = publish(store, commit_id=args.commit)
    except (ValueError, StoreError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 1

    if not pub.changes and pub.previous == pub.published:
        print("already live")
        return 0
    print(f"live is now {pub.published[:12]}  ({len(pub.changes)} change(s))")
    if pub.previous:
        print(f"  {DIM}previous {pub.previous[:12]} is still stored; "
              f"`scrivet rollback` moves the pointer back{RESET}")
    # Said plainly because it is the one thing a pointer cannot fix.
    print(f"  {DIM}rolling back restores the content, not the fact that it "
          f"was published{RESET}")
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    store = _store(args)
    try:
        pub = rollback(store, steps=args.steps)
    except (ValueError, StoreError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 1
    print(f"live is now {pub.published[:12]}  ({len(pub.changes)} change(s) reverted)")
    print(f"  {DIM}rolled back from {(pub.previous or '')[:12]}, which is still "
          f"stored and can be published again{RESET}")
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    store = _store(args)
    head = store.get_ref(args.ref)
    if not head:
        print(f"no ref {args.ref!r}")
        return 1
    live = store.get_ref(LIVE)
    for cid, c in store.history(head, limit=args.limit):
        mark = f"{GREEN} ← live{RESET}" if cid == live else ""
        print(f"  {cid[:12]}  {c.author:<10} {c.message}{mark}")
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    store = _store(args)
    ref = args.ref or LIVE
    try:
        pages = pages_at(store, ref)
    except StoreError as exc:
        print(f"{exc}", file=sys.stderr)
        return 1
    if args.page not in pages:
        print(f"no page {args.page!r}; have {', '.join(sorted(pages))}", file=sys.stderr)
        return 1

    template = Path(args.template).read_text(encoding="utf-8")
    try:
        out = render(template, {"page": pages[args.page], "site": {"pages": sorted(pages)}})
    except TemplateError as exc:
        print(f"template: {exc}", file=sys.stderr)
        return 1

    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(out)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Every place a template opts out of escaping, in one list."""
    total = 0
    for path in sorted(Path(args.dir).rglob("*.html")):
        sites = list(raw_sites(path.read_text(encoding="utf-8")))
        if sites:
            print(f"  {path}")
            for s in sites:
                print(f"      {YELLOW}raw{RESET} {s}")
            total += len(sites)
    if total:
        print(f"\n  {total} place(s) where escaping is switched off. Each one is "
              f"a decision to trust that content.")
    else:
        print("  no template opts out of escaping")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    store = _store(args)
    ok, note = store.verify()
    print(f"  {note}" if ok else f"  {RED}{note}{RESET}")
    if ok:
        print(f"  {DIM}every object re-hashed to the id it is filed under{RESET}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="scrivet",
        description="A CMS where content is immutable and publishing is a pointer.")
    p.add_argument("--root", default=DEFAULT_ROOT, help=f"store location (default {DEFAULT_ROOT})")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create a content store")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("add", help="stage pages into a draft")
    s.add_argument("page", nargs="*", metavar="NAME=FILE.json")
    s.add_argument("--remove", nargs="*", metavar="NAME")
    s.add_argument("-m", "--message", default="edit")
    s.add_argument("--author", default="cli")
    s.set_defaults(func=cmd_add)

    s = sub.add_parser("diff", help="what differs between live and draft")
    s.set_defaults(func=cmd_diff)

    s = sub.add_parser("publish", help="move live to the draft")
    s.add_argument("--commit", help="publish this commit instead of the draft")
    s.set_defaults(func=cmd_publish)

    s = sub.add_parser("rollback", help="move live back along its history")
    s.add_argument("--steps", type=int, default=1)
    s.set_defaults(func=cmd_rollback)

    s = sub.add_parser("log", help="commit history")
    s.add_argument("--ref", default=DRAFT)
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(func=cmd_log)

    s = sub.add_parser("render", help="render a page through a template")
    s.add_argument("page")
    s.add_argument("template")
    s.add_argument("--ref", help=f"default {LIVE}")
    s.add_argument("-o", "--out")
    s.set_defaults(func=cmd_render)

    s = sub.add_parser("audit", help="list every template that disables escaping")
    s.add_argument("dir", nargs="?", default="templates")
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("verify", help="re-hash every object")
    s.set_defaults(func=cmd_verify)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
