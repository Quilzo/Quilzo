"""Content that cannot be edited, only added to.

Every CMS breach worth reading about follows the same shape. WordPress's
wp2shell chained a REST batch-route confusion with SQL injection to reach an
admin account and then uploaded a plugin, achieving pre-auth remote code
execution on a stock install with no plugins present. Drupal's 2026 disclosure
was SQL injection in the database abstraction layer itself.

Both chains need the same two links: a query the attacker can influence, and a
place where writing data means writing something that later executes. This
module removes the first, and `template.py` removes the second.

The model
---------
It is git's, applied to content rather than files. Three object kinds, all
immutable, all addressed by the SHA-256 of their own bytes:

    blob     a piece of content, structured or raw
    tree     a named mapping from path to object id
    commit   a tree, its parents, and who did it and why

Nothing is ever modified. Editing a page writes a new blob, a new tree pointing
at it, and a new commit; the old objects are still there, still addressable,
still exactly what they were. There is no UPDATE and no DELETE, so there is no
statement for an injection to alter, and the read path is a hash lookup rather
than a query.

Why this shape rather than a database
-------------------------------------
Publishing becomes moving a pointer, which is atomic and instantly reversible.
That matters more than it sounds: the reason rolling back a conventional CMS is
frightening is that the previous state was overwritten and has to be
reconstructed from a backup taken at some other time. Here the previous state
was never touched. Rollback is a pointer moving back, and it cannot fail
halfway.

It also gives an AI assistant somewhere safe to work. An agent proposing a
change produces a commit that nobody is serving yet; reviewing it is a diff, and
rejecting it costs nothing because publishing never happened.

The git-based CMS trade, avoided
--------------------------------
Git-backed CMSes get integrity and version history but are usually limited to
static sites, because serving means a build. This keeps the object model and
drops the working tree: a ref move is visible on the next request, so content
stays dynamic without giving up the property that made git worth copying.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

BLOB = "blob"
TREE = "tree"
COMMIT = "commit"

# Object ids are lowercase hex sha-256. Anything else is rejected before it can
# reach the filesystem, because an id is used to build a path.
_ID = re.compile(r"^[0-9a-f]{64}$")

# Path components allowed in a tree. Deliberately narrow: no traversal, no
# separators, no leading dots. A path is content addressing, not a filename, but
# it does become one on disk in some deployments and the two must not diverge.
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class StoreError(RuntimeError):
    """Something was asked of the store that would break its invariants."""


def object_id(kind: str, payload: bytes) -> str:
    """The address of an object, which is a fact about its bytes.

    The kind is folded into the hash so a blob and a tree with identical bytes
    get different ids. Without that, an attacker who controls blob content could
    craft bytes that also parse as a tree and have one object stand in for the
    other — the same domain-separation reasoning that puts a prefix byte on
    Merkle leaves.
    """
    h = hashlib.sha256()
    h.update(kind.encode("ascii"))
    h.update(b"\x00")
    h.update(payload)
    return h.hexdigest()


def canonical(data: Any) -> bytes:
    """Bytes for a structure, stable across machines and runs.

    Sorted keys and no incidental whitespace, so the same content always lands
    on the same id. If that were not true, deduplication would silently stop
    working and two identical pages would look like a change.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class Commit:
    tree: str
    parents: tuple[str, ...]
    message: str
    author: str
    at: float
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"tree": self.tree, "parents": list(self.parents),
                "message": self.message, "author": self.author,
                "at": self.at, "meta": self.meta}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> Commit:
        return Commit(tree=d["tree"], parents=tuple(d.get("parents", ())),
                      message=d.get("message", ""), author=d.get("author", ""),
                      at=float(d.get("at", 0.0)), meta=d.get("meta") or {})


class Store:
    """An append-only object store on a plain filesystem.

    Objects live under `objects/aa/bbbb…` and refs under `refs/`. There is no
    index and no database; a read is a file open on a path derived from a hash,
    so there is no query for anything to be injected into.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.refs = self.root / "refs"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.refs.mkdir(parents=True, exist_ok=True)

    # -- addressing -------------------------------------------------------
    def _path(self, oid: str) -> Path:
        if not _ID.match(oid):
            # An id becomes a path, so an unchecked one is a traversal waiting
            # to happen. Validate at the boundary, once, rather than trusting
            # every caller to have done it.
            raise StoreError(f"not an object id: {oid!r}")
        return self.objects / oid[:2] / oid[2:]

    def has(self, oid: str) -> bool:
        return self._path(oid).exists()

    # -- writing ----------------------------------------------------------
    def _write(self, kind: str, payload: bytes) -> str:
        oid = object_id(kind, payload)
        target = self._path(oid)
        if target.exists():
            # Already stored, and by construction it has identical bytes.
            # Rewriting would be pointless and would open a window where the
            # object is briefly absent.
            return oid
        target.parent.mkdir(parents=True, exist_ok=True)
        body = kind.encode("ascii") + b"\x00" + payload
        # Write to a temporary file and rename. A reader must never observe a
        # half-written object, and rename within a directory is atomic on POSIX.
        fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(body)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return oid

    def put_blob(self, data: Any) -> str:
        """Store a piece of content."""
        return self._write(BLOB, canonical(data))

    def put_tree(self, entries: dict[str, str]) -> str:
        """Store a named mapping from path segment to object id."""
        for name, oid in entries.items():
            if not _SEGMENT.match(name):
                raise StoreError(
                    f"{name!r} is not a usable path segment. Letters, digits, "
                    f"dot, dash and underscore, starting with a letter or digit.")
            if not _ID.match(oid):
                raise StoreError(f"{name!r} points at {oid!r}, which is not an object id")
        return self._write(TREE, canonical(entries))

    def put_commit(self, commit: Commit) -> str:
        if not _ID.match(commit.tree):
            raise StoreError(f"commit tree {commit.tree!r} is not an object id")
        for p in commit.parents:
            if not _ID.match(p):
                raise StoreError(f"commit parent {p!r} is not an object id")
        return self._write(COMMIT, canonical(commit.to_dict()))

    # -- reading ----------------------------------------------------------
    def _read(self, oid: str, expect: str) -> Any:
        path = self._path(oid)
        if not path.exists():
            raise StoreError(f"no object {oid}")
        body = path.read_bytes()
        kind, _, payload = body.partition(b"\x00")
        kind_s = kind.decode("ascii", "replace")
        if kind_s != expect:
            raise StoreError(f"object {oid} is a {kind_s}, not a {expect}")
        # Verify the bytes still hash to the name they are filed under. Disk
        # corruption and tampering look identical from here, and both should
        # stop a read rather than return content that is not what was written.
        if object_id(kind_s, payload) != oid:
            raise StoreError(
                f"object {oid} does not hash to its own id; the store has been "
                f"corrupted or altered")
        return json.loads(payload.decode("utf-8"))

    def get_blob(self, oid: str) -> Any:
        return self._read(oid, BLOB)

    def get_tree(self, oid: str) -> dict[str, str]:
        return self._read(oid, TREE)

    def get_commit(self, oid: str) -> Commit:
        return Commit.from_dict(self._read(oid, COMMIT))

    # -- refs -------------------------------------------------------------
    def _ref_path(self, name: str) -> Path:
        if not _SEGMENT.match(name):
            raise StoreError(f"{name!r} is not a usable ref name")
        return self.refs / name

    def set_ref(self, name: str, oid: str) -> None:
        """Point a ref at a commit. This is what publishing is."""
        if not _ID.match(oid):
            raise StoreError(f"{oid!r} is not an object id")
        if not self.has(oid):
            raise StoreError(f"refusing to point {name} at {oid}, which is not stored")
        path = self._ref_path(name)
        fd, tmp = tempfile.mkstemp(dir=str(self.refs), prefix=".tmp-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(oid)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def get_ref(self, name: str) -> str | None:
        path = self._ref_path(name)
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8").strip()

    def refs_list(self) -> dict[str, str]:
        return {p.name: p.read_text(encoding="utf-8").strip()
                for p in sorted(self.refs.iterdir()) if p.is_file()
                and not p.name.startswith(".")}

    # -- history ----------------------------------------------------------
    def history(self, oid: str, limit: int = 50) -> Iterator[tuple[str, Commit]]:
        """Walk back along first parents."""
        seen: set[str] = set()
        current: str | None = oid
        while current and len(seen) < limit:
            if current in seen:
                break
            seen.add(current)
            commit = self.get_commit(current)
            yield current, commit
            current = commit.parents[0] if commit.parents else None

    def verify(self) -> tuple[bool, str]:
        """Re-hash every object.

        The point of content addressing is that this check exists and is cheap.
        A conventional CMS cannot answer "has anything in here been altered
        outside the application" at all.
        """
        checked = 0
        for shard in sorted(self.objects.iterdir()):
            if not shard.is_dir():
                continue
            for path in sorted(shard.iterdir()):
                oid = shard.name + path.name
                body = path.read_bytes()
                kind, _, payload = body.partition(b"\x00")
                if object_id(kind.decode("ascii", "replace"), payload) != oid:
                    return False, f"object {oid} does not match its contents"
                checked += 1
        return True, f"{checked} object(s) intact"


def build_tree(store: Store, pages: dict[str, Any]) -> str:
    """Convenience: store each page as a blob and gather them into one tree."""
    return store.put_tree({name: store.put_blob(body) for name, body in pages.items()})


def commit(store: Store, tree: str, *, message: str, author: str,
           parents: tuple[str, ...] = (), meta: dict[str, Any] | None = None) -> str:
    return store.put_commit(Commit(
        tree=tree, parents=parents, message=message, author=author,
        at=time.time(), meta=meta or {}))
