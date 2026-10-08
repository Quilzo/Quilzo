# SPDX-FileCopyrightText: 2026 Rashik Adhikari
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

"""Writes c14n/expected.json: libxml2's exclusive canonical form (through
lxml) of every element of every document in c14n/, with and without an
InclusiveNamespaces PrefixList.

A second, independent implementation is the only way to know the Go one is
right rather than consistent with itself. Run by hand when the corpus
changes; the test never runs Python.

    python3 internal/xmldsig/testdata/gen_c14n.py
"""

import json
import os

from lxml import etree

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "c14n")
PREFIX_LISTS = [[], ["xs"], ["#default"], ["xs", "xsi", "p"]]


def paths(el, prefix=()):
    yield prefix, el
    for i, child in enumerate(c for c in el if isinstance(c.tag, str)):
        yield from paths(child, prefix + (i,))


def main():
    out = []
    for name in sorted(os.listdir(CORPUS)):
        if not name.endswith(".xml"):
            continue
        with open(os.path.join(CORPUS, name), "rb") as f:
            root = etree.fromstring(f.read())
        for path, el in paths(root):
            for plist in PREFIX_LISTS:
                lxml_list = list(plist)  # libxml2 reads "#default" itself
                c = etree.tostring(el, method="c14n", exclusive=True,
                                   with_comments=False,
                                   inclusive_ns_prefixes=lxml_list or None)
                out.append({"file": name, "path": list(path),
                            "inclusive": plist, "c14n": c.decode("utf-8")})
    with open(os.path.join(CORPUS, "expected.json"), "w") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print(len(out), "cases")


if __name__ == "__main__":
    main()
