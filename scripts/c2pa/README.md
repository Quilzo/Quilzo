# Checking the manifests with something that is not this program

`internal/c2pa` writes C2PA manifests and its tests are Go tests. A reader
written beside a writer repeats the writer's mistakes, and that is not a
hypothetical here: a JPEG framing bug survived a passing Go round-trip until
exiftool disagreed, because the Go reader made the same wrong assumption the Go
writer did.

So these are the checks that come from outside.

## verify.py

An independent verifier written against the specification. It parses the PNG
chunk and JPEG APP11 containers itself, decodes the CBOR with `cbor2`, rebuilds
the COSE `Sig_structure` and checks the Ed25519 signature with `cryptography`,
recomputes the hard binding over the excluded range, and follows the ingredient
assertion to the file it names. It imports nothing from the Go implementation.

```
python3 -m venv .venv && .venv/bin/pip install cbor2 cryptography
.venv/bin/python scripts/c2pa/verify.py FILE [--parent DIR] [--cert PEM]
```

`--parent` is a directory to resolve the ingredient in: it hashes every file
there and reports which one the derivative was actually made from. That is the
check that matters for a claim binding, because a binding nobody can resolve is
a label.

It found two real faults the Go tests could not:

- the ingredient carried the derivative's own name instead of its parent's;
- the ingredient bound to the parent as *stored*, while what a reader can
  download is the parent as *served*, manifest and all. Different bytes, so the
  reference resolved against nothing anybody outside the machine could obtain.

Keep it in the loop when the manifest format changes.

## exiftool

Reads the JUMBF box tree and decodes the CBOR inside it, with no setup:

```
exiftool -G1 -a FILE | grep -i 'jumbf\|cbor'
```

Faster than `verify.py` and checks a different thing — that the *container* is
well formed, which is what a reader that is not looking for C2PA sees. It is
the one that caught the JPEG framing bug.

## Cross-checking the encoder

`cbor2` will decode a structure and re-encode it canonically. If the bytes come
back identical, the hand-written deterministic encoder in `internal/c2pa/cbor.go`
agrees with a third-party implementation of RFC 8949 §4.2 — which matters
because those bytes are signed, and two encoders that disagree produce a
manifest one of them cannot verify.
