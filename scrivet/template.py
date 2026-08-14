"""Templates that cannot execute anything.

Server-side template injection is a whole vulnerability class, and it exists
because the popular template languages are programming languages. Give one an
attacker-influenced string and it will reach a constructor, a class hierarchy,
a filesystem, a subprocess. Every mitigation is a fence around a language that
was never meant to be safe.

So this is not a programming language. It has no functions the author can
define, no arithmetic, no assignment, no imports, no attribute access, no
method calls, no recursion, and no way to reach a Python object at all. What it
has is enough to render a page:

    {{ page.title }}                a value, escaped for its context
    {% if page.subtitle %}…{% end %}    present and truthy
    {% for item in nav %}…{% end %}     bounded iteration
    {% raw page.body_html %}            deliberately unescaped, and auditable

That is the whole language. There is nothing to escape *from*, because there is
nothing underneath: values come out of a plain dictionary and the only
operations are lookup, truthiness and iteration.

Escaping is not optional
------------------------
`{{ }}` always escapes, and it escapes for where the value lands — HTML text,
an attribute, a URL. The usual failure is a language that escapes for HTML and
is then used inside `href`, where `javascript:` is perfectly valid HTML and
perfectly dangerous. The parser tracks which context it is in and picks.

`{% raw %}` exists because real sites have rich text, and pretending otherwise
would push people to disable escaping globally. It is a distinct keyword rather
than a filter, so `grep -rn "{% raw"` lists every place trust was extended,
which is a review the author can actually complete.

Bounded on purpose
------------------
Loops iterate over data, never a condition, and nesting depth and total output
are capped. A template cannot loop forever, and a page cannot be made to consume
the machine by feeding it recursive content. Rendering terminates for all
inputs, which is a property, not a hope.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Any, Iterator
from urllib.parse import quote, urlsplit

MAX_DEPTH = 12
MAX_OUTPUT = 4_000_000        # 4 MB of rendered page is already absurd
MAX_ITERATIONS = 50_000       # across the whole render, not per loop

# A path is dotted names and integer indices. No calls, no operators, no
# underscore-prefixed names — the last one keeps `__class__` and its relatives
# unreachable even if a dictionary somehow carried them.
_PATH = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9][A-Za-z0-9_]*)*$")

_TAG = re.compile(r"\{\{(.*?)\}\}|\{%(.*?)%\}", re.DOTALL)

# Schemes permitted in a URL context. `javascript:` and `data:` are the two that
# turn an escaped-looking value into script execution.
_SAFE_SCHEMES = {"http", "https", "mailto", "tel", ""}


class TemplateError(ValueError):
    """The template is malformed, or asks for something the language lacks."""


# -- contexts --------------------------------------------------------------
TEXT = "text"        # between tags
ATTR = "attr"        # inside a quoted attribute value
URL = "url"          # inside href/src/action


def _escape_text(value: str) -> str:
    return html.escape(value, quote=False)


def _escape_attr(value: str) -> str:
    return html.escape(value, quote=True)


def _escape_url(value: str) -> str:
    """Escape for a URL attribute, and refuse a scheme that can execute.

    HTML-escaping a URL is not enough: `javascript:alert(1)` contains nothing
    that needs escaping and runs anyway. The scheme has to be checked, and an
    unsafe one is replaced rather than passed through, because emitting it and
    hoping the browser declines is not a control.
    """
    stripped = value.strip()
    try:
        scheme = urlsplit(stripped).scheme.lower()
    except ValueError:
        return "#unsafe-url"
    if scheme not in _SAFE_SCHEMES:
        return "#unsafe-url"
    return html.escape(quote(stripped, safe="/:?#[]@!$&'()*+,;=-._~%"), quote=True)


_ESCAPERS = {TEXT: _escape_text, ATTR: _escape_attr, URL: _escape_url}


# -- parsing ---------------------------------------------------------------
@dataclass
class Node:
    kind: str            # literal | value | raw | if | for
    text: str = ""
    path: str = ""
    var: str = ""
    context: str = TEXT
    children: list["Node"] | None = None


def _lookup(data: Any, path: str) -> Any:
    """Walk a dotted path through plain data. Never touches a Python attribute."""
    if not _PATH.match(path):
        raise TemplateError(
            f"{path!r} is not a value path. Names and dots only — there are no "
            f"calls, operators or attributes in this language.")
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, (list, tuple)) and part.isdigit():
            idx = int(part)
            current = current[idx] if 0 <= idx < len(current) else None
        else:
            # Anything else — an object, a string being indexed by name — is a
            # miss rather than an error, so a template renders with a gap
            # instead of failing a whole page over one field.
            return None
        if current is None:
            return None
    return current


def _detect_context(rendered_so_far: str) -> str:
    """Which HTML context the next value lands in.

    Deliberately simple: look back at the text already produced. If we are
    inside an unclosed tag and the nearest attribute is a URL one, this is a URL
    context; inside a tag at all, an attribute; otherwise text. It is not a full
    HTML parser and does not need to be, because the fallback is the *stricter*
    escaping rather than the looser one.
    """
    open_tag = rendered_so_far.rfind("<")
    close_tag = rendered_so_far.rfind(">")
    if open_tag <= close_tag:
        return TEXT
    tail = rendered_so_far[open_tag:].lower()
    if re.search(r'\b(?:href|src|action|formaction|xlink:href)\s*=\s*["\']?[^"\']*$', tail):
        return URL
    return ATTR


def parse(source: str) -> list[Node]:
    """Turn template text into nodes. Any unknown tag is an error, not output."""
    nodes: list[Node] = []
    stack: list[Node] = []
    pos = 0

    def push(node: Node) -> None:
        (stack[-1].children if stack else nodes).append(node)  # type: ignore[union-attr]

    for m in _TAG.finditer(source):
        if m.start() > pos:
            push(Node("literal", text=source[pos:m.start()]))
        pos = m.end()

        if m.group(1) is not None:
            push(Node("value", path=m.group(1).strip()))
            continue

        stmt = m.group(2).strip()
        head, _, rest = stmt.partition(" ")
        head, rest = head.strip(), rest.strip()

        if head == "if":
            node = Node("if", path=rest, children=[])
            push(node)
            stack.append(node)
        elif head == "for":
            var, _, src = rest.partition(" in ")
            var, src = var.strip(), src.strip()
            if not var.isidentifier():
                raise TemplateError(f"{var!r} is not a usable loop variable")
            node = Node("for", var=var, path=src, children=[])
            push(node)
            stack.append(node)
        elif head == "raw":
            push(Node("raw", path=rest))
        elif head == "end":
            if not stack:
                raise TemplateError("{% end %} with nothing open")
            stack.pop()
        else:
            raise TemplateError(
                f"unknown tag {head!r}. This language has if, for, end and raw, "
                f"and nothing else — there is no way to add one.")

        if len(stack) > MAX_DEPTH:
            raise TemplateError(f"nested deeper than {MAX_DEPTH}")

    if pos < len(source):
        push(Node("literal", text=source[pos:]))
    if stack:
        raise TemplateError(f"{len(stack)} block(s) left open")
    return nodes


# -- rendering -------------------------------------------------------------
@dataclass
class Budget:
    output: int = 0
    iterations: int = 0

    def spend_output(self, n: int) -> None:
        self.output += n
        if self.output > MAX_OUTPUT:
            raise TemplateError(f"rendered past {MAX_OUTPUT:,} characters")

    def spend_iteration(self) -> None:
        self.iterations += 1
        if self.iterations > MAX_ITERATIONS:
            raise TemplateError(f"iterated past {MAX_ITERATIONS:,} times")


def _truthy(value: Any) -> bool:
    """Presence, not Python truthiness on arbitrary objects."""
    if value is None or value is False:
        return False
    if isinstance(value, (str, list, tuple, dict)):
        return len(value) > 0
    if isinstance(value, (int, float)):
        return value != 0
    return True


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    # A structure rendered into a page is almost always a mistake, and printing
    # its repr would leak shape. Render nothing and let it be visible as a gap.
    return ""


def _walk(nodes: list[Node], data: dict[str, Any], out: list[str],
          budget: Budget, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise TemplateError(f"nested deeper than {MAX_DEPTH}")

    for node in nodes:
        if node.kind == "literal":
            budget.spend_output(len(node.text))
            out.append(node.text)

        elif node.kind == "value":
            text = _stringify(_lookup(data, node.path))
            context = _detect_context("".join(out[-4:]))
            escaped = _ESCAPERS[context](text)
            budget.spend_output(len(escaped))
            out.append(escaped)

        elif node.kind == "raw":
            # The one place trust is extended, and it is greppable by design.
            text = _stringify(_lookup(data, node.path))
            budget.spend_output(len(text))
            out.append(text)

        elif node.kind == "if":
            if _truthy(_lookup(data, node.path)):
                _walk(node.children or [], data, out, budget, depth + 1)

        elif node.kind == "for":
            items = _lookup(data, node.path)
            if not isinstance(items, (list, tuple)):
                continue
            for item in items:
                budget.spend_iteration()
                # A shallow copy per iteration, so a loop variable cannot leak
                # out of its block and templates stay reasoned about locally.
                scope = dict(data)
                scope[node.var] = item
                _walk(node.children or [], scope, out, budget, depth + 1)


def render(source: str, data: dict[str, Any]) -> str:
    """Render a template against plain data. Terminates for every input."""
    out: list[str] = []
    _walk(parse(source), data, out, Budget())
    return "".join(out)


def raw_sites(source: str) -> Iterator[str]:
    """Every place a template opts out of escaping.

    Exists so extending trust is reviewable in aggregate rather than one file at
    a time.
    """
    for m in _TAG.finditer(source):
        if m.group(2) is not None:
            stmt = m.group(2).strip()
            if stmt.startswith("raw "):
                yield stmt[4:].strip()
