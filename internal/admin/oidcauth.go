package admin

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/oidc"
)

// OIDC wires an identity provider into the admin.
//
// The division is deliberate: the provider says *who* somebody is, and this
// program's own access policy says what they may do. A verified ID token is
// exchanged for an ordinary quilzo session token, which means every existing
// mechanism — the role ladder, path bindings, revocation, the audit trail —
// applies unchanged and none of it had to learn about OIDC.
//
// It also means revocation stays local. Cutting somebody off does not depend on
// the provider noticing, or on a token expiring, or on a back-channel logout
// arriving.
type OIDC struct {
	Provider *oidc.Provider
	ClientID string
	// Secret is read from the environment by the caller. It is never stored
	// beside the data.
	Secret      string
	RedirectURI string
	// Claim is which claim becomes the principal: "email" or "sub".
	Claim string
	// RequireVerifiedEmail refuses a sign-in whose address the provider has not
	// verified. An unverified address is a claim by whoever signed up, and
	// mapping it to a principal would let them choose who to be.
	RequireVerifiedEmail bool
	// SessionTTL bounds the token minted after a successful sign-in.
	SessionTTL time.Duration

	mu      sync.Mutex
	pending map[string]*oidc.Request
}

// DefaultSessionTTL is how long an OIDC session lasts.
//
// Eight hours: a working day, so nobody is signed out mid-task, and short
// enough that a laptop left on a train stops being a credential overnight.
const DefaultSessionTTL = 8 * time.Hour

// start begins a sign-in.
func (o *OIDC) start(w http.ResponseWriter, r *http.Request) {
	req, err := oidc.NewRequest(o.RedirectURI)
	if err != nil {
		http.Error(w, "cannot begin sign-in", http.StatusInternalServerError)
		return
	}

	// Held server-side, keyed by the state. Putting the nonce and code verifier
	// in a cookie would let whoever controls the browser choose them, and the
	// verifier is the one value PKCE depends on the client keeping to itself.
	o.mu.Lock()
	if o.pending == nil {
		o.pending = map[string]*oidc.Request{}
	}
	// Sweep expired attempts on every start, so an abandoned sign-in cannot
	// accumulate into a memory leak somebody has to notice.
	for k, v := range o.pending {
		if v.Expired(time.Now()) {
			delete(o.pending, k)
		}
	}
	if len(o.pending) > 1000 {
		o.mu.Unlock()
		http.Error(w, "too many sign-ins in progress", http.StatusTooManyRequests)
		return
	}
	o.pending[req.State] = req
	o.mu.Unlock()

	http.Redirect(w, r, o.Provider.AuthorizationURL(o.ClientID, req, nil),
		http.StatusSeeOther)
}

// take consumes a pending request, so a state cannot be replayed.
func (o *OIDC) take(state string) *oidc.Request {
	o.mu.Lock()
	defer o.mu.Unlock()
	for k, v := range o.pending {
		if subtle.ConstantTimeCompare([]byte(k), []byte(state)) == 1 {
			delete(o.pending, k)
			return v
		}
	}
	return nil
}

// callback finishes a sign-in.
func (o *OIDC) callback(ctx context.Context, r *http.Request) (string, error) {
	if e := r.URL.Query().Get("error"); e != "" {
		return "", fmt.Errorf("the provider refused: %s (%s)", e,
			r.URL.Query().Get("error_description"))
	}
	state := r.URL.Query().Get("state")
	if state == "" {
		return "", fmt.Errorf("no state parameter; this response did not come " +
			"from a sign-in this server started")
	}
	req := o.take(state)
	if req == nil {
		return "", fmt.Errorf("this state does not match a sign-in in progress. " +
			"It has already been used, it expired, or the request did not " +
			"originate here")
	}
	if req.Expired(time.Now()) {
		return "", fmt.Errorf("this sign-in took too long; start again")
	}

	tokens, err := o.Provider.Exchange(ctx, o.ClientID, o.Secret, req,
		r.URL.Query().Get("code"))
	if err != nil {
		return "", err
	}

	claims, err := o.Provider.Verifier(o.ClientID).Verify(tokens.IDToken, req.Nonce)
	if err != nil {
		return "", err
	}

	principal, err := o.principalFor(claims)
	if err != nil {
		return "", err
	}
	return principal, nil
}

// principalFor maps a verified token to a name the access policy knows.
func (o *OIDC) principalFor(c *oidc.Claims) (string, error) {
	switch o.Claim {
	case "sub":
		return c.Subject, nil
	default:
		if c.Email == "" {
			return "", fmt.Errorf("the provider returned no email address, so " +
				"there is nothing to match against the access policy. Configure " +
				"--claim sub, or request the email scope")
		}
		if o.RequireVerifiedEmail && !c.EmailVerified {
			return "", fmt.Errorf(
				"%s has not been verified by the provider. An unverified address "+
					"is a claim by whoever signed up, and honouring it would let "+
					"somebody choose which principal to be", c.Email)
		}
		return c.Email, nil
	}
}

// handleOIDCStart begins a sign-in.
func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		http.NotFound(w, r)
		return
	}
	s.OIDC.start(w, r)
}

// handleOIDCCallback finishes one.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	principal, err := s.OIDC.callback(ctx, r)
	if err != nil {
		s.refuseSignIn(w, r, err.Error(), "")
		return
	}

	// No auto-provisioning, and this is the decision that matters most here.
	//
	// A verified token proves the provider knows this person. It does not say
	// they should be able to edit anything. Creating a principal on first
	// sign-in would mean everybody with an account at the identity provider —
	// which for a public provider is everybody — becomes a user of this system.
	// The access policy is the list of who may work here, and it is maintained
	// deliberately.
	if !s.knownPrincipal(principal) {
		s.refuseSignIn(w, r,
			fmt.Sprintf("%s signed in successfully, but is not in the access "+
				"policy for this site.", principal),
			fmt.Sprintf("An administrator can add them:  quilzo auth grant %s author",
				principal))
		return
	}

	// A short-lived session token, minted by this program and revocable here.
	// The provider authenticated; everything after this is local.
	secret, tok, err := s.Tokens.Issue(
		"oidc:"+principal, principal, s.roleFor(principal), "/",
		s.OIDC.ttl(), auth.RoleAdmin)
	if err != nil {
		s.refuseSignIn(w, r, "the session could not be created: "+err.Error(), "")
		return
	}
	if s.SaveTokens != nil {
		if err := s.SaveTokens(s.Tokens); err != nil {
			s.refuseSignIn(w, r, "the session could not be stored: "+err.Error(), "")
			return
		}
	}
	if s.OnSignIn != nil {
		s.OnSignIn(principal, tok.ID)
	}

	http.SetCookie(w, &http.Cookie{
		Name: "quilzo_token", Value: secret, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		// Lax rather than Strict, and only here: a redirect arriving from the
		// identity provider is a cross-site navigation, and Strict would drop
		// the cookie so the person lands signed out. Lax still blocks the
		// cross-site POSTs that CSRF needs.
		Secure: r.TLS != nil,
		MaxAge: int(s.OIDC.ttl().Seconds()),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (o *OIDC) ttl() time.Duration {
	if o.SessionTTL <= 0 {
		return DefaultSessionTTL
	}
	return o.SessionTTL
}

// refuseSignIn renders a failure without leaking whether the principal exists
// beyond what the person already knows about themselves.
func (s *Server) refuseSignIn(w http.ResponseWriter, r *http.Request, reason, hint string) {
	w.WriteHeader(http.StatusForbidden)
	s.render(w, r, "signin.html", map[string]any{
		"Title": "Sign in", "Error": reason, "Hint": hint,
		"OIDC": s.OIDC != nil,
	})
}

// knownPrincipal reports whether the access policy mentions somebody.
func (s *Server) knownPrincipal(name string) bool {
	if name == "" {
		return false
	}
	for _, b := range s.Policy.Bindings {
		if b.Principal == name {
			return true
		}
	}
	return false
}

// roleFor returns the role the session token carries.
//
// The token cannot exceed what the policy already grants; it is a session, not
// a promotion. Evaluate is asked rather than the bindings read directly, so a
// deny is honoured here exactly as it is everywhere else.
func (s *Server) roleFor(name string) auth.Role {
	// Highest first, taking the first that is permitted. Asking Evaluate rather
	// than reading the bindings means a deny is honoured here exactly as it is
	// everywhere else, and inheritance is not reimplemented.
	for _, probe := range []struct {
		role auth.Role
		act  auth.Action
	}{
		{auth.RoleAdmin, auth.ActGrant},
		{auth.RolePublisher, auth.ActPublish},
		{auth.RoleAuthor, auth.ActEditDraft},
		{auth.RoleReader, auth.ActView},
	} {
		if s.Policy.Evaluate(name, probe.act, "/").Allowed {
			return probe.role
		}
	}
	return auth.RoleReader
}
