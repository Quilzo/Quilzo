// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"time"
)

// Security events from the identity provider (internal/ssf), as the admin
// reaches them: the endpoint the transmitter pushes to, and what the
// Sign-ins screen says about the stream.
//
// Shown, not changed, here. Connecting a stream takes the client secret
// from the environment of whoever runs the command, as the OIDC client's
// does, and a form that took it would put it in a browser's memory and a
// request log; turning one off is the same command. So the screen is the
// place to see whether it is working, and the terminal the place to set it.

// SignalsAdmin is the stream as the admin reaches it.
type SignalsAdmin struct {
	// Handler answers the transmitter at SignalsPath.
	Handler http.Handler
	// Status is the stream as connected now, or nil when none is.
	Status func() (*SignalsStatus, error)
}

// SignalsStatus is what the Sign-ins screen says about the stream.
type SignalsStatus struct {
	// Provider is the sign-in it speaks for: "oidc" or "saml:NAME".
	Provider string
	Issuer   string
	// Manual is a stream made in the transmitter's own console, which
	// cannot be asked to verify; the screen says so rather than showing a
	// verification that can never come.
	Manual bool
	// Verified is when the transmitter last answered a verification, and
	// Asked when one was last asked for.
	Verified, Asked time.Time
	// State is what the transmitter last said the stream is: enabled,
	// paused or disabled.
	State     string
	Connected time.Time
	// LastAt and LastType are the last event received.
	LastAt   time.Time
	LastType string
	// What came, what was done, and what was not.
	Received, Acted, Unmatched, Refused, Capped int
}

// signalsPanel is the stream as the Sign-ins template reads it.
type signalsPanel struct {
	Provider, Issuer, State, LastType  string
	Verified, Asked, Connected, LastAt string
	Manual, Silent                     bool
	Received, Acted, Unmatched         int
	Refused, Capped                    int
}

// signalsSilentAfter is how long a stream may go without answering a
// verification before the screen calls it silent, as the posture rule
// signals.stream-silent does.
const signalsSilentAfter = 24 * time.Hour

// signalsData puts the stream on the Sign-ins screen, or says why it
// cannot.
func (s *Server) signalsData(data map[string]any, now time.Time) {
	if s.Signals == nil || s.Signals.Status == nil {
		return
	}
	st, err := s.Signals.Status()
	if err != nil {
		data["SignalsError"] = err.Error()
		return
	}
	if st == nil {
		data["SignalsOff"] = true
		return
	}
	when := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format("2 Jan 15:04 UTC")
	}
	data["Signals"] = signalsPanel{
		Provider: st.Provider, Issuer: st.Issuer, State: st.State, LastType: st.LastType,
		Verified: when(st.Verified), Asked: when(st.Asked), Connected: when(st.Connected), LastAt: when(st.LastAt),
		Manual:   st.Manual,
		Silent:   now.Sub(st.Verified) > signalsSilentAfter && now.Sub(st.Connected) > signalsSilentAfter,
		Received: st.Received, Acted: st.Acted, Unmatched: st.Unmatched, Refused: st.Refused, Capped: st.Capped,
	}
}
