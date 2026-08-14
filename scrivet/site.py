"""Working on a site: draft, review, publish, roll back.

The workflow is the point, not a wrapper over the store. Conventional CMSes
treat publishing as saving, so a bad edit is live the moment it is made and
getting back is a restore from whatever the backup happened to catch. Here
draft and live are two refs over the same immutable objects, so:

    editing      writes new objects; live is untouched and still serving
    reviewing    is a diff between two commits, both of which exist
    publishing   moves one pointer
    rolling back moves it back

None of those can half-complete, and none of them destroys the alternative. That
is what makes it safe to let an assistant work here: an agent that produces a
terrible draft has produced an object nobody is serving, and discarding it costs
a pointer that was never moved.

Publishing is still the moment that matters. It is the one action with an
outside observer — a reader, a crawler, a cache — and undoing it restores the
bytes without unsending what was seen. That is exactly the compensable-not-
reversible distinction, so it is the action worth gating.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .store import Store, build_tree, commit

DRAFT = "draft"
LIVE = "live"


@dataclass
class Change:
    path: str
    kind: str        # added | removed | modified
    before: str = ""
    after: str = ""


def diff(store: Store, old_commit: str | None, new_commit: str) -> list[Change]:
    """What changed between two commits, by object id rather than by content.

    Comparing ids is exact and cheap: identical content has an identical id, so
    an unchanged page is provably unchanged without reading it. This is why the
    review step stays fast on a large site — only what actually moved is looked
    at.
    """
    new_tree = store.get_tree(store.get_commit(new_commit).tree)
    old_tree: dict[str, str] = {}
    if old_commit:
        old_tree = store.get_tree(store.get_commit(old_commit).tree)

    changes: list[Change] = []
    for path in sorted(set(old_tree) | set(new_tree)):
        before, after = old_tree.get(path), new_tree.get(path)
        if before == after:
            continue
        if before is None:
            changes.append(Change(path, "added", after=after or ""))
        elif after is None:
            changes.append(Change(path, "removed", before=before))
        else:
            changes.append(Change(path, "modified", before=before, after=after))
    return changes


def save_draft(store: Store, pages: dict[str, Any], *, message: str,
               author: str, meta: dict[str, Any] | None = None) -> str:
    """Write a new draft commit on top of whatever the draft ref points at."""
    tree = build_tree(store, pages)
    parent = store.get_ref(DRAFT) or store.get_ref(LIVE)
    parents = (parent,) if parent else ()
    cid = commit(store, tree, message=message, author=author,
                 parents=parents, meta=meta or {})
    store.set_ref(DRAFT, cid)
    return cid


def pages_at(store: Store, ref_or_commit: str) -> dict[str, Any]:
    """Every page at a commit, read back as data."""
    cid = store.get_ref(ref_or_commit) or ref_or_commit
    tree = store.get_tree(store.get_commit(cid).tree)
    return {name: store.get_blob(oid) for name, oid in tree.items()}


@dataclass
class Publication:
    published: str
    previous: str | None
    changes: list[Change]

    @property
    def reversible(self) -> bool:
        """Rolling back restores the bytes. It does not unsend what was read.

        Reported honestly rather than as a boolean promise: the content is
        recoverable, the fact of publication is not.
        """
        return self.previous is not None


def publish(store: Store, *, commit_id: str | None = None) -> Publication:
    """Move `live` to a commit. The one action with an outside observer."""
    target = commit_id or store.get_ref(DRAFT)
    if not target:
        raise ValueError("nothing to publish: no draft and no commit given")
    previous = store.get_ref(LIVE)
    if previous == target:
        return Publication(published=target, previous=previous, changes=[])
    changes = diff(store, previous, target)
    store.set_ref(LIVE, target)
    return Publication(published=target, previous=previous, changes=changes)


def rollback(store: Store, *, steps: int = 1) -> Publication:
    """Walk `live` back along its own history.

    Not a restore. The commit being returned to was never removed, so this is
    the pointer going back to an object that has been sitting there the whole
    time. There is no window in which the site is neither one version nor the
    other.
    """
    current = store.get_ref(LIVE)
    if not current:
        raise ValueError("nothing is live")

    walked = [cid for cid, _ in store.history(current, limit=steps + 1)]
    if len(walked) <= steps:
        raise ValueError(
            f"cannot go back {steps}: only {len(walked) - 1} earlier "
            f"commit(s) exist on this line")

    target = walked[steps]
    changes = diff(store, current, target)
    store.set_ref(LIVE, target)
    return Publication(published=target, previous=current, changes=changes)
