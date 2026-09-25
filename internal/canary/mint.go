// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package canary

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// Minting a value that looks like the thing it is pretending to be.
//
// The shape matters and the entropy matters, for different reasons. The shape
// is what makes an attacker who finds it try to use it: a 43-character
// base64 blob in a file named deploy.env does not look like an access key and
// nobody will paste it into an SDK. The entropy is what makes the detection
// sound: 160 bits means the value cannot be produced by anything but reading
// the place it was planted, which is the entire claim this package makes.
//
// What is deliberately not here: minting a real, live credential at a cloud
// provider. That is the best-known form of this idea and it is a better
// detection than anything below, because the trip is recorded by the provider
// at the moment of use rather than by whatever telemetry happens to carry the
// value. It also means handing a third party the ability to see your
// canaries, and it cannot be done with no dependencies. When a connector
// exists that can mint one, it plants the value here like any other; nothing
// in this package assumes it produced the token.

// base32 is the alphabet for values meant to be typed, read aloud or pasted.
//
// No 0/O, no 1/I/l: an analyst reading a canary out of a screenshot into a
// search box is a real step in a real investigation, and a token that cannot
// survive it costs an hour at the worst moment.
const base32 = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

const lower32 = "abcdefghjkmnpqrstuvwxyz23456789"

const hexdigits = "0123456789abcdef"

// Mint produces a value shaped like what the kind imitates.
//
// Every shape carries at least 128 bits. The uniformity is not decorative:
// selecting from a 31-character alphabet by taking a byte modulo 31 is
// measurably biased, and a biased canary is a canary whose value an attacker
// with a few samples can start to predict. pick rejects instead.
func Mint(kind Kind) (string, error) {
	switch kind {
	case AsCredential:
		// Forty characters of upper-case and digits: the shape of a secret
		// access key, which is the single most tried-on-sight value there is.
		return pick(base32, 40)
	case AsFile:
		// A long hex string, which is what a checksum, a session id or an
		// internal reference looks like inside a document.
		return pick(hexdigits, 48)
	case AsRecord:
		// UUID-shaped, so it survives being pasted into a field that
		// validates the format before anybody looks at the value.
		raw, err := pick(hexdigits, 32)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s-%s-%s-%s-%s", raw[0:8], raw[8:12],
			raw[12:16], raw[16:20], raw[20:32]), nil
	case AsAddress:
		// A local part. The domain is the deployment's, and deliberately not
		// chosen here: a canary address at a domain nobody in the
		// organisation uses is a canary that tells whoever harvested it that
		// the mailbox is watched.
		return pick(lower32, 20)
	default:
		return "", fmt.Errorf(
			"%s is not a kind of canary, so there is no shape to mint", kind)
	}
}

// pick draws n characters uniformly from an alphabet.
func pick(alphabet string, n int) (string, error) {
	if len(alphabet) < 2 || len(alphabet) > 256 {
		return "", fmt.Errorf("an alphabet of %d cannot carry a value",
			len(alphabet))
	}
	// The largest multiple of the alphabet that fits in a byte. Anything at
	// or above it is drawn again, which is what keeps the distribution flat.
	//
	// Held as an int, not a byte. For a 16-character alphabet the multiple is
	// 256 exactly, and narrowing that to a byte makes it 0 — every draw is
	// rejected and the loop never ends. A silent hang in the one function
	// whose output must be unguessable.
	limit := 256 / len(alphabet) * len(alphabet)
	var out strings.Builder
	out.Grow(n)
	buf := make([]byte, n)
	for out.Len() < n {
		if _, err := rand.Read(buf); err != nil {
			// Unreachable on every supported platform since Go 1.24, where
			// rand.Read cannot fail. Returned rather than ignored because a
			// canary minted from a failed read is a canary an attacker can
			// guess, and that failure must never be silent.
			return "", fmt.Errorf("no randomness to mint a canary from: %w",
				err)
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			out.WriteByte(alphabet[int(b)%len(alphabet)])
			if out.Len() == n {
				break
			}
		}
	}
	return out.String(), nil
}
