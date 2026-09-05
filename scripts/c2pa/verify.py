#!/usr/bin/env python3
"""An independent C2PA verifier, written against the specification.

Why this exists
---------------
The manifests are produced by Go code in internal/c2pa, and its tests are Go
tests. A reader written beside a writer repeats the writer's mistakes -- that
is not a hypothetical here, it is how the JPEG framing bug survived a passing
round-trip until exiftool disagreed.

So this parses the containers, decodes the CBOR with a third-party library,
rebuilds the COSE Sig_structure and checks the signature, recomputes the hard
binding, and follows the ingredient to the file it names. Nothing here imports
anything from the Go implementation. If the two agree, they agree for a reason.

    scripts/c2pa/verify.py <file> [--parent DIR] [--cert PEM]

Needs cbor2 and cryptography, which is why it is a script rather than part of
the program: the program has no dependencies and this is a check on it.
"""
import argparse
import hashlib
import struct
import sys

try:
    import cbor2
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    sys.exit("needs cbor2 and cryptography:  pip install cbor2 cryptography")

C2PA_SUFFIX = bytes([0x00, 0x11, 0x00, 0x10, 0x80, 0x00,
                     0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71])


def uuid_for(name):
    return name.encode() + C2PA_SUFFIX


def extract(body):
    """Return (jumbf bytes, (offset, length)) for whichever container this is."""
    if body.startswith(b"\x89PNG\r\n\x1a\n"):
        at = 8
        while at + 12 <= len(body):
            length = struct.unpack(">I", body[at:at + 4])[0]
            kind = body[at + 4:at + 8]
            end = at + 12 + length
            if kind == b"caBX":
                data = body[at + 8:at + 8 + length]
                want = struct.unpack(">I", body[at + 8 + length:end])[0]
                got = 0xFFFFFFFF & __import__("zlib").crc32(kind + data)
                if got != want:
                    raise ValueError(f"chunk CRC {got:08x} claims {want:08x}")
                return data, (at, end - at)
            at = end
        raise ValueError("this PNG carries no manifest")

    if body.startswith(b"\xff\xd8"):
        at = 2
        while at + 4 <= len(body):
            if body[at] != 0xFF:
                raise ValueError(f"byte {at} is not a marker")
            marker = body[at + 1]
            if not 0xE0 <= marker <= 0xEF:
                break
            size = struct.unpack(">H", body[at + 2:at + 4])[0]
            end = at + 2 + size
            if marker == 0xEB and body[at + 4:at + 6] == b"JP":
                return body[at + 12:end], (at, end - at)
            at = end
        raise ValueError("this JPEG carries no manifest")
    raise ValueError("not a PNG or a JPEG")


def parse_boxes(data, depth=0):
    """Walk a run of JUMBF boxes into (kind, uuid, label, body, children)."""
    if depth > 16:
        raise ValueError("boxes nest too deeply")
    out, at = [], 0
    while at < len(data):
        if len(data) - at < 8:
            raise ValueError("trailing bytes shorter than a box header")
        length = struct.unpack(">I", data[at:at + 4])[0]
        kind = data[at + 4:at + 8].decode("latin1")
        if length < 8 or at + length > len(data):
            raise ValueError(f"a box claims {length} bytes")
        payload = data[at + 8:at + length]
        uuid = label = None
        children = []
        body = None
        if kind == "jumb":
            children = parse_boxes(payload, depth + 1)
            if not children or children[0]["kind"] != "jumd":
                raise ValueError("a superbox does not open with a description")
            d = children[0]["body"]
            uuid = d[:16]
            if d[16] & 0x02:
                label = d[17:d.index(b"\0", 17)].decode()
            children = children[1:]
        else:
            body = payload
        out.append({"kind": kind, "uuid": uuid, "label": label,
                    "body": body, "children": children})
        at += length
    return out


def find(box, uuid):
    for c in box["children"]:
        if c["uuid"] == uuid:
            return c
    return None


def content(box):
    for c in box["children"]:
        if c["kind"] in ("cbor", "json"):
            return c["body"]
    raise ValueError(f"box {box['label']!r} carries no content")


def hash_excluding(body, start, length):
    h = hashlib.sha256()
    h.update(body[:start])
    h.update(body[start + length:])
    return h.digest()


def check(path, parent_dir=None, cert_pem=None):
    body = open(path, "rb").read()
    raw, (offset, length) = extract(body)

    boxes = parse_boxes(raw)
    store = next((b for b in boxes if b["uuid"] == uuid_for("c2pa")), None)
    if store is None:
        raise ValueError("no manifest store")
    for b in boxes:
        if b["uuid"] != uuid_for("c2pa") and b["kind"] != "free":
            raise ValueError(f"unexpected {b['kind']!r} box beside the manifest")

    manifest = find(store, uuid_for("c2ma"))
    claim_box = find(manifest, uuid_for("c2cl"))
    sig_box = find(manifest, uuid_for("c2cs"))
    assertions = find(manifest, uuid_for("c2as"))

    claim_bytes = content(claim_box)
    sig_bytes = content(sig_box)
    claim = cbor2.loads(claim_bytes)

    # -- the signature -------------------------------------------------------
    cose = cbor2.loads(sig_bytes)
    tag = None
    if isinstance(cose, cbor2.CBORTag):
        tag, cose = cose.tag, cose.value
    if tag != 18:
        raise ValueError(f"COSE tag is {tag}, expected 18")
    protected, unprotected, payload, signature = cose
    headers = cbor2.loads(protected)
    alg = headers.get(1)
    if alg != -8:
        raise ValueError(f"algorithm {alg} is not EdDSA")
    if payload != claim_bytes:
        raise ValueError("the signature covers a different claim")

    der = headers.get(33)
    if isinstance(der, list):
        der = der[0]
    if cert_pem:
        cert = x509.load_pem_x509_certificate(open(cert_pem, "rb").read())
    else:
        cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("the certificate does not hold an Ed25519 key")

    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload],
                                canonical=True)
    pub.verify(signature, sig_structure)

    # -- the assertions ------------------------------------------------------
    by_label = {}
    for c in assertions["children"]:
        if c["kind"] == "jumb":
            by_label[c["label"]] = content(c)

    for ref in claim["assertions"]:
        label = ref["url"].rsplit("/", 1)[-1]
        if label not in by_label:
            raise ValueError(f"the claim commits to {label} and it is absent")
        got = hashlib.sha256(by_label[label]).digest()
        if got != ref["hash"]:
            raise ValueError(f"assertion {label} does not match what was signed")

    # -- the hard binding ----------------------------------------------------
    data_hash = cbor2.loads(by_label["c2pa.hash.data"])
    ex = data_hash["exclusions"]
    if len(ex) != 1:
        raise ValueError(f"{len(ex)} exclusions; the manifest occupies one")
    if ex[0]["start"] != offset or ex[0]["length"] != length:
        raise ValueError(
            f"the manifest excludes {ex[0]['start']}..{ex[0]['start'] + ex[0]['length']} "
            f"and sits at {offset}..{offset + length}")
    got = hash_excluding(body, offset, length)
    if got != data_hash["hash"]:
        raise ValueError("the file does not hash to what the manifest claims")

    # -- what it says --------------------------------------------------------
    actions = cbor2.loads(by_label["c2pa.actions.v2"])["actions"][0]
    result = {
        "title": claim.get("title"),
        "generator": claim.get("claim_generator"),
        "action": actions.get("action"),
        "source_type": (actions.get("digitalSourceType") or "").rsplit("/", 1)[-1],
        "model": (actions.get("parameters") or {}).get("com.quilzo.model"),
        "signature": "verified (Ed25519 over COSE Sig_structure)",
        "binding": f"verified over {len(body) - length} bytes",
    }

    # -- the claim binding ---------------------------------------------------
    if "c2pa.ingredient.v3" in by_label:
        ing = cbor2.loads(by_label["c2pa.ingredient.v3"])
        result["derived_from"] = ing["hash"].hex()
        result["parent_title"] = ing.get("dc:title")
        result["relationship"] = ing.get("relationship")
        if parent_dir:
            import os
            found = None
            for name in os.listdir(parent_dir):
                p = os.path.join(parent_dir, name)
                if not os.path.isfile(p):
                    continue
                if hashlib.sha256(open(p, "rb").read()).digest() == ing["hash"]:
                    found = name
                    break
            result["parent_resolved"] = found or "NOT FOUND in " + parent_dir
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--parent", help="directory to resolve the ingredient in")
    ap.add_argument("--cert", help="verify against this PEM rather than the embedded chain")
    a = ap.parse_args()
    try:
        for k, v in check(a.file, a.parent, a.cert).items():
            print(f"  {k:16} {v}")
        print("\nVERIFIED")
    except Exception as e:
        print(f"REFUSED: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
