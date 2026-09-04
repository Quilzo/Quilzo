package public

import (
	"bytes"
	"crypto"
	"fmt"
	"net/http"
	"time"

	"github.com/quilzo/quilzo/internal/activitypub"
	"github.com/quilzo/quilzo/internal/httpsig"
)

// Signer posts an activity to a remote inbox, signed as this site.
//
// # Why the body digest is not optional
//
// A signature over the request line says this site sent *a* POST to that
// address. It says nothing about what was in it, so a receiver that accepted
// one would be accepting an envelope whose letter anybody could replace.
//
// This site's own inbox refuses such a signature — it was exploitable until it
// did — so sending one would be asking of others what it will not accept
// itself.
type Signer struct {
	// KeyID is the actor's key, as remote servers will look it up.
	KeyID string
	// Key signs.
	Key crypto.Signer
	// Post makes the request. Supplied so it goes through the same address
	// checks as every other outbound call.
	Post func(req *http.Request) (int, error)
	// Now is a clock seam.
	Now func() time.Time
}

// Send delivers one activity.
func (s *Signer) Send(inbox string, activity map[string]any) error {
	body, err := activitypub.Marshal(activity)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, inbox, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("cannot build the delivery: %w", err)
	}
	req.Header.Set("Content-Type", activitypub.ContentType)

	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	httpsig.SetContentDigest(req, body)

	// Signed with draft-cavage, which is what the receiving end verifies.
	//
	// RFC 9421 is the standard and this program prefers it everywhere it can.
	// It cannot here. Mastodon gained RFC 9421 verification in June 2025 and
	// every other implementation -- Pleroma, Akkoma, Misskey, GoToSocial, and
	// every Mastodon before that -- verifies only the draft. The two formats
	// put incompatible syntax in the same Signature header, so a sender picks
	// one, and picking the standard means picking the one almost nobody can
	// check.
	//
	// This replaced an RFC 9421 signature that covered @target-uri, added so
	// that Mastodon's 9421 verifier would accept it. That was the right fix
	// for the wrong half of the problem: it made deliveries acceptable to the
	// one implementation that had moved, while leaving them unreadable to
	// every implementation that had not. The 9421 work it came from still
	// applies to what arrives here, where this program is the receiver and
	// takes whichever format the sender chose.
	//
	// The covered headers are what the ecosystem expects: the request line,
	// the host, the date and the digest. Date because it is the draft's only
	// replay bound, and digest because without it a captured signature can be
	// put on any body.
	if err := httpsig.SignCavage(req, s.KeyID, httpsig.RSAPKCS1SHA256, s.Key,
		[]string{"(request-target)", "host", "date", "digest"},
		now); err != nil {
		return fmt.Errorf("cannot sign the delivery: %w", err)
	}

	status, err := s.Post(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case status == http.StatusGone || status == http.StatusNotFound:
		// The account is gone. Reported as an error so the queue records it,
		// and it will exhaust its attempts rather than being retried forever
		// against something that will never answer differently.
		return fmt.Errorf("%s is gone (%d)", inbox, status)
	default:
		return fmt.Errorf("%s answered %d", inbox, status)
	}
}
