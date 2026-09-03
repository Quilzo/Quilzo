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
	if err := httpsig.Sign(req, s.KeyID, httpsig.RSAPKCS1SHA256, s.Key,
		[]string{"@method", "@authority", "@path", "content-digest"},
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
