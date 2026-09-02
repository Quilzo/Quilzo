#!/usr/bin/env python3
"""Render the Incubator proposal as the plain text an ASF list will accept.

    python3 scripts/proposal/plaintext.py

Reads docs/apache-incubator-proposal.md and writes the .txt beside it.

# Why this is a script and not a thing somebody does once

ASF lists are plain text and strip HTML, so the proposal has to exist in two
forms. Two forms of one document is two things to keep true, and the pair
drifted within a fortnight: the markdown was corrected to say the AgentDojo
benchmark had been run, and the text still said it never had. The text is what
gets pasted into a permanently archived mailing list.

So the text is generated, this is the generator, and a test asserts the file in
the tree is what this produces. The markdown is the source; the text is output.

# The bug this converter had

"It is tracked as issue #33 and it is an explicit initial goal" rendered as a
level-two heading in the middle of a sentence, because "#33" was read as a
heading marker. A markdown heading requires a space after the hashes and an
issue number does not have one, which is why the pattern below is anchored on
`#{1,6}\\s` rather than on a leading hash.
"""

import pathlib
import re
import sys
import textwrap

WIDTH = 76
HERE = pathlib.Path(__file__).resolve().parents[2]
SOURCE = HERE / "docs" / "apache-incubator-proposal.md"
TARGET = HERE / "docs" / "apache-incubator-proposal.txt"


def clean(t):
    t = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 <\2>", t)
    t = re.sub(r"~~([^~]+)~~", r"\1", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"\1", t)
    t = re.sub(r"(?<!\w)\*([^*]+)\*(?!\w)", r"\1", t)
    return (t.replace("`", "").replace("—", "--").replace("–", "-")
             .replace("“", '"').replace("”", '"')
             .replace("’", "'").replace("‘", "'"))


def blocks(body):
    """Fold the markdown into blocks, so a wrapped list item stays one item."""
    out, kind, buf = [], None, []

    def close():
        nonlocal kind, buf
        if buf:
            out.append((kind, " ".join(buf)))
        kind, buf = None, []

    fenced = False
    for raw in body.split("\n"):
        s = raw.strip()
        if s.startswith("```"):
            close()
            fenced = not fenced
            continue
        if fenced:
            close()
            out.append(("pre", raw))
            continue
        if not s:
            close()
            continue
        if s.startswith("|"):
            close()
            out.append(("row", s))
            continue
        if s == "---":
            close()
            out.append(("rule", ""))
            continue
        # A space after the hashes: "#33" is an issue number, not a heading.
        if re.match(r"^#{1,6}\s", s):
            close()
            level = len(s) - len(s.lstrip("#"))
            out.append((f"h{min(level, 3)}", s.lstrip("# ").strip()))
            continue
        m = re.match(r"^([-*]|\d+\.)\s+(.*)$", s)
        if m:
            close()
            kind = "ol" if m.group(1)[0].isdigit() else "ul"
            buf = [m.group(2)]
            if kind == "ol":
                out.append(("marker", m.group(1)))
            continue
        if kind in ("ul", "ol"):
            buf.append(s)
        else:
            if kind is None:
                kind = "p"
            buf.append(s)
    close()
    return out


def render(body):
    lines = ["QUILZO -- APACHE INCUBATOR PROPOSAL", "=" * WIDTH, ""]
    marker, in_table = None, False

    for kind, text in blocks(body):
        if kind not in ("row",) and in_table:
            lines.append("")
            in_table = False
        t = clean(text)
        if kind == "marker":
            marker = text
        elif kind == "pre":
            lines.append("    " + text.rstrip()[:WIDTH - 4])
        elif kind.startswith("h"):
            lines.append("")
            if kind in ("h1", "h2"):
                lines += [t.upper(), "-" * min(len(t), WIDTH)]
            else:
                lines += [t, "~" * min(len(t), WIDTH)]
            lines.append("")
        elif kind == "rule":
            lines += ["-" * WIDTH, ""]
        elif kind == "ul":
            lines += textwrap.wrap(t, WIDTH, initial_indent="  - ",
                                   subsequent_indent="    ")
        elif kind == "ol":
            m = marker or "1."
            marker = None
            lines += textwrap.wrap(t, WIDTH, initial_indent=f"  {m} ",
                                   subsequent_indent=" " * (len(m) + 3))
        elif kind == "row":
            cells = [clean(c.strip()) for c in text.strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            lines.append(("  " + "  ".join(c.ljust(20) for c in cells)
                          ).rstrip()[:WIDTH])
            in_table = True
        else:
            lines += textwrap.wrap(t, WIDTH) + [""]

    # A blank line between a list or a block and the paragraph after it.
    spaced = []
    for i, l in enumerate(lines):
        spaced.append(l)
        if i + 1 < len(lines):
            n = lines[i + 1]
            item = (l.startswith("  - ") or re.match(r"^  \d+\. ", l)
                    or l.startswith("    "))
            para = n and not n.startswith(" ") and not set(n) <= set("-~=")
            if item and para:
                spaced.append("")
    return re.sub(r"\n{4,}", "\n\n\n", "\n".join(spaced)).rstrip() + "\n"


def build():
    src = SOURCE.read_text()
    marker = "## Licensing, first"
    if marker not in src:
        raise SystemExit(f"{SOURCE} has no {marker!r} section to start from")
    return render(marker + src.split(marker, 1)[1])


# Fixtures for --self-test.
#
# The converter's own bugs cannot be caught by rendering the real proposal:
# they only appear when the source contains the shape that triggers them, and
# the source stops containing it the moment somebody rewrites a paragraph. The
# "#33" case was caught in review and then became untestable that way when the
# paragraph naming the issue was replaced.
SELF_TESTS = [
    (
        # At the start of a line, which is how it happened: the markdown
        # paragraph wrapped so that "#33 and it is an explicit initial goal"
        # began a line, and the converter read the hash as a heading marker.
        # A fixture with the number mid-line does not reproduce it and passes
        # against the broken converter.
        "an issue number at the start of a line is not a heading",
        "It is tracked as issue\n#33 and it is an explicit initial goal above.",
        # Case is the discriminator: a heading is upper-cased and underlined,
        # so the sentence surviving in its original case means it stayed prose.
        lambda out: "#33 and it is an explicit initial goal above." in out,
    ),
    (
        "a real heading is still a heading",
        "## Known Risks\n\nOne contributor.",
        lambda out: "KNOWN RISKS" in out and "-----" in out,
    ),
    (
        "a wrapped list item keeps its indent",
        "- " + "word " * 40,
        lambda out: all(l.startswith("    ") for l in out.splitlines()[3:]
                        if l.strip() and not l.startswith("  - ")),
    ),
    (
        "nothing exceeds the line width",
        "x" * 20 + " " + "word " * 60,
        lambda out: all(len(l) <= WIDTH for l in out.splitlines()),
    ),
]


def self_test():
    failed = 0
    for name, source, ok in SELF_TESTS:
        out = render(source)
        if not ok(out):
            failed += 1
            print(f"FAIL: {name}\n--- rendered ---\n{out}\n---",
                  file=sys.stderr)
        else:
            print(f"ok: {name}")
    return 1 if failed else 0


def main():
    if "--self-test" in sys.argv:
        return self_test()
    text = build()
    over = [l for l in text.splitlines() if len(l) > WIDTH]
    if over:
        raise SystemExit(f"{len(over)} line(s) exceed {WIDTH} columns")
    if "--check" in sys.argv:
        if not TARGET.exists() or TARGET.read_text() != text:
            print(f"{TARGET} is not what this script produces. Run "
                  f"`python3 {pathlib.Path(__file__).relative_to(HERE)}`.",
                  file=sys.stderr)
            return 1
        print(f"{TARGET.name} matches its source")
        return 0
    TARGET.write_text(text)
    print(f"wrote {TARGET.relative_to(HERE)}: {len(text.splitlines())} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
