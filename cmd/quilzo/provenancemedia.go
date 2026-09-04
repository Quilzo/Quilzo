package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/c2pa"
	"github.com/quilzo/quilzo/internal/media"
)

// Attaching a manifest on the way out.
//
// # Why here and not in the library
//
// The asset library files everything under the hash of its own bytes, and Put
// refuses anything else -- storing an image under a name that is not its
// address would break every integrity check downstream. Embedding a manifest
// changes the bytes, so a manifest cannot go in at upload without either
// breaking that rule or making the same photograph uploaded twice into two
// files. So the stored object stays the original, and the copy a reader gets
// carries the manifest.
//
// Site.Bundle crawls this program's own handler, so a published site gets the
// same bytes a live one serves and there is no second path to keep in step.
//
// # What a failure does
//
// Serves the original. An image is content, and a page missing its pictures
// because a signature failed is a worse outcome than a picture whose
// provenance cannot be checked. The count is kept so the failure is visible
// rather than silent.

// signedMedia wraps a media lookup so images come back carrying a manifest.
type signedMedia struct {
	inner func(string) (media.File, []byte, error)
	chain [][]byte
	key   ed25519.PrivateKey
	agent string
	now   func() time.Time

	mu     sync.Mutex
	cache  map[string][]byte
	failed int
}

// cacheLimit bounds what is held. Files are immutable and named by their own
// hash, so an entry can never be stale -- the only reason to evict is memory.
// A site serving more distinct images than this per process signs the overflow
// each time, which is a cost, not a fault.
const cacheLimit = 256

func newSignedMedia(inner func(string) (media.File, []byte, error),
	chain [][]byte, key ed25519.PrivateKey, agent string) *signedMedia {

	return &signedMedia{
		inner: inner, chain: chain, key: key, agent: agent,
		now:   time.Now,
		cache: map[string][]byte{},
	}
}

func (s *signedMedia) get(id string) (media.File, []byte, error) {
	f, body, err := s.inner(id)
	if err != nil {
		return f, body, err
	}
	if !embeddable(f) {
		return f, body, nil
	}

	s.mu.Lock()
	if hit, ok := s.cache[id]; ok {
		s.mu.Unlock()
		return f, hit, nil
	}
	s.mu.Unlock()

	claim := s.claimFor(f)
	s.bindToParent(f, &claim)

	signed, serr := c2pa.Embed(body, claim, s.chain, s.key)
	if serr != nil {
		// Includes the case that matters most: a file that already carries a
		// manifest. Passing it through untouched is the right answer -- a
		// camera or a generator said something about this image before it got
		// here, and overwriting that would destroy the record rather than add
		// to it.
		s.mu.Lock()
		s.failed++
		s.mu.Unlock()
		return f, body, nil
	}

	s.mu.Lock()
	if len(s.cache) >= cacheLimit {
		s.cache = map[string][]byte{}
	}
	s.cache[id] = signed
	s.mu.Unlock()
	return f, signed, nil
}

// embeddable reports whether a manifest can go into this file.
//
// PNG and JPEG only, because those are the two containers implemented. A
// rendition is skipped: it is a narrower copy of a picture whose original
// carries the claim, and signing each one would say this site created a
// resize.
func embeddable(f media.File) bool {
	if f.Kind != media.Image {
		return false
	}
	switch strings.ToLower(f.Format) {
	case "png", "jpeg", "jpg":
		return true
	}
	return false
}

func (s *signedMedia) claimFor(f media.File) c2pa.Claim {
	when := time.Unix(f.UploadedAt, 0)
	if f.UploadedAt == 0 {
		when = s.now()
	}
	return c2pa.Claim{
		Title:             f.Name,
		Format:            f.MIME(),
		DigitalSourceType: f.Origin.SourceType,
		SoftwareAgent:     s.agent,
		Author:            f.Origin.Author,
		Model:             f.Origin.Model,
		Instruction:       f.Origin.Instruction,
		When:              when,
	}
}

// bindToParent fills in what a derivative was made from.
//
// The hash is over the parent as a reader receives it -- manifest and all --
// not over the copy this library keeps. Those are different bytes, and binding
// to the stored one produces a reference that resolves against nothing anybody
// can download: the check fails for everybody outside this machine, which is
// every reader the binding exists for. It named the right file and could not
// be used to find it, which is the "label rather than a chain" outcome the
// ingredient assertion is meant to avoid.
//
// Signing the parent to describe the child is affordable because the result is
// deterministic and cached, and because the recursion is one level deep: a
// rendition is never made from a rendition.
func (s *signedMedia) bindToParent(f media.File, c *c2pa.Claim) {
	if f.RenditionOf == "" {
		return
	}
	parent, body, err := s.get(f.RenditionOf)
	if err != nil {
		// A rendition whose parent cannot be read still gets a manifest of its
		// own. It says less than it might, and that is better than refusing to
		// serve a picture over a provenance link.
		return
	}
	sum := sha256.Sum256(body)
	c.DerivedFrom = sum[:]
	c.ParentTitle = parent.Name
}

// mediaLookup is the accessor every surface reads images through.
//
// One function because there is more than one surface -- the public server and
// the static export at least -- and each one opening the library itself is how
// a live site and a copy of it came to serve different bytes: the server
// attached manifests and the export shipped the originals, so the same page
// carried a provenance record in one place and none in the other.
//
// A signing identity that cannot be loaded is not a reason to serve no images.
// The error is returned so a caller can say so, and the lookup still works.
func mediaLookup(root string) (func(string) (media.File, []byte, error), error) {
	lib, err := openMedia(root)
	if err != nil {
		return nil, err
	}
	plain := func(id string) (media.File, []byte, error) { return lib.Get(id) }

	chain, key, kerr := provenanceSigner(root, siteName(root), time.Now())
	if kerr != nil {
		return plain, kerr
	}
	return newSignedMedia(plain, chain, key, "Quilzo").get, nil
}
