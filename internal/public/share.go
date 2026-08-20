package public

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/throttle"
)

// Receiving what somebody shared from their phone.
//
// # The one deep OS integration that needs no script
//
// A web app manifest can declare share_target with method POST and enctype
// multipart/form-data, which registers the installed site in the operating
// system's share sheet. When somebody shares a photo or a link to it, the
// system sends an ordinary multipart form POST to a URL on this server.
//
// MDN is explicit that the receiving side needs no client code: the service
// worker route exists for offline handling and is optional. So this is the
// share sheet reaching a plain HTTP handler — the same mechanism the forms
// already use, pointed at the operating system.
//
// That matters here more than it would elsewhere. Every other route to the
// device — the File System Access API, launchQueue, Web Bluetooth — is
// JavaScript by construction, and the admin serves none. This one is a JSON
// declaration and a form POST.
//
// # Where a share goes
//
// Into a declared form, as a submission. Not into the content store: a share
// arrives from outside with no authentication, and content that anybody with
// the URL can create is the vulnerability every CMS with open registration
// has had. A submission is already the shape for "somebody outside sent us
// something" — it has a retention period, a privacy notice, and it lives
// outside the merkle store precisely because it may need deleting.
//
// # Why files are refused for now
//
// share_target can carry files, and accepting them would mean an unauthenticated
// upload endpoint. The media library validates by decoding rather than sniffing,
// so a polyglot would not get through — but the disk would still fill, and rate
// limiting an anonymous multipart upload is a different piece of work from
// accepting a form. Text, title and url first; files when there is a quota to
// put in front of them.

// ShareTarget describes where shares land.
type ShareTarget struct {
	// Form is the declared form a share becomes a submission of.
	Form string
	// TitleField, TextField and URLField are which of that form's fields the
	// three shared values map onto. Named rather than assumed, because a form
	// somebody already uses for enquiries has its own field names and this
	// must not require renaming them.
	TitleField string
	TextField  string
	URLField   string
}

// shareManifest is the manifest fragment for the share sheet.
//
// method POST with multipart/form-data, which is what makes this server-side.
// A GET share target would put the shared text in a query string, which is
// simpler and puts whatever somebody shared into every access log between here
// and them.
func (st *Site) shareManifest() map[string]any {
	if st.Share == nil || st.Share.Form == "" {
		return nil
	}
	params := map[string]any{}
	if st.Share.TitleField != "" {
		params["title"] = st.Share.TitleField
	}
	if st.Share.TextField != "" {
		params["text"] = st.Share.TextField
	}
	if st.Share.URLField != "" {
		params["url"] = st.Share.URLField
	}
	if len(params) == 0 {
		return nil
	}
	return map[string]any{
		"action":  "/share",
		"method":  "POST",
		"enctype": "multipart/form-data",
		"params":  params,
	}
}

// handleShare receives a share and turns it into a form submission.
//
// It does not render its own page. The share is stored and the browser is sent
// to the form's own page, which already says what happens to a submission —
// writing a second confirmation here would be a second place for the privacy
// notice to be wrong.
func (st *Site) handleShare(w http.ResponseWriter, r *http.Request) {
	if st.Share == nil || st.Share.Form == "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		// A GET here is somebody typing the URL, not a share. Sent to the
		// form rather than shown an error, because there is nothing wrong.
		http.Redirect(w, r, "/"+st.Share.Form, http.StatusSeeOther)
		return
	}
	// Bounded before parsing. A share sheet sends what the user picked, and an
	// unauthenticated multipart body with no ceiling is a way to fill a disk.
	r.Body = http.MaxBytesReader(w, r.Body, maxShareBytes)
	if err := r.ParseMultipartForm(maxShareBytes); err != nil {
		// Some senders post form-urlencoded despite the declaration. Accepted,
		// because refusing a share that arrived in the wrong envelope helps
		// nobody — the values are the same either way.
		if perr := r.ParseForm(); perr != nil {
			http.Error(w, "that share could not be read", http.StatusBadRequest)
			return
		}
	}

	// Rewritten into the field names the form declares, so the rest of the
	// pipeline — validation, retention, the privacy notice — is the same code
	// a browser submission goes through. A share that took its own path would
	// be a second way to write a submission, with its own bugs.
	values := map[string]string{}
	for shared, field := range map[string]string{
		"title": st.Share.TitleField,
		"text":  st.Share.TextField,
		"url":   st.Share.URLField,
	} {
		if field == "" {
			continue
		}
		if v := strings.TrimSpace(r.FormValue(shared)); v != "" {
			values[field] = clampShare(v)
		}
	}
	if len(values) == 0 {
		http.Redirect(w, r, "/"+st.Share.Form, http.StatusSeeOther)
		return
	}

	// The rate limit that stands in for the honeypot and the timing stamp.
	//
	// /share is an unauthenticated write with one fewer defence than a form,
	// because the two a form has both need a page this server rendered and a
	// share was not one. So it gets a harder limit rather than the same one.
	source := sourceOf(r)
	if st.Forms != nil && st.Forms.Limit != nil {
		if d := st.Forms.Limit.Check(throttle.Subject{Source: source}); !d.Allowed {
			http.Error(w, "too many shares from here, try again shortly",
				http.StatusTooManyRequests)
			return
		}
	}

	if err := st.storeShare(st.Share.Form, values, r); err != nil {
		// A refused share counts against the limiter, so somebody probing for
		// what passes is slowed by their own failures.
		if st.Forms != nil && st.Forms.Limit != nil {
			st.Forms.Limit.Fail(throttle.Subject{Source: source})
		}
		http.Error(w, "that share could not be stored",
			http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/"+st.Share.Form+"?shared=1", http.StatusSeeOther)
}

// maxShareBytes bounds a whole share.
//
// Generous for text and a hard stop for anything else. Files are not accepted
// yet — see the note at the top — so this is a ceiling on a handful of strings.
const maxShareBytes = 512 << 10

// maxShareField bounds one shared value.
const maxShareField = 8 << 10

func clampShare(s string) string {
	if len(s) <= maxShareField {
		return s
	}
	return s[:maxShareField]
}

// storeShare writes the submission through the form pipeline.
//
// Through form.AcceptShare, so declared fields, kinds, required-ness,
// retention and the store are all the ones a browser submission gets. The only
// difference is the two checks a share cannot carry, and the rate limit above
// that stands in for them.
func (st *Site) storeShare(name string, values map[string]string,
	r *http.Request) error {

	if st.Forms == nil || st.Forms.Store == nil {
		return fmt.Errorf("this server stores no submissions")
	}
	set, err := st.Forms.Set()
	if err != nil {
		return err
	}
	f, ok := set.Get(name)
	if !ok {
		return fmt.Errorf("no form called %q", name)
	}
	sub, err := form.AcceptShare(f, values, sourceOf(r), time.Now())
	if err != nil {
		return err
	}
	return st.Forms.Store.Put(sub)
}

// Validate refuses a share target that cannot work.
//
// The failure this catches is specific and silent: a share carries at most a
// title, a text and a url, so if the target form has a required field none of
// those map onto, every share is refused at the point somebody tries one —
// weeks after the manifest was published, from a phone, with no error anybody
// sees. Checked at startup instead.
func (s *ShareTarget) Validate(required []string) error {
	if s == nil || strings.TrimSpace(s.Form) == "" {
		return fmt.Errorf("no form named")
	}
	mapped := map[string]bool{}
	for _, f := range []string{s.TitleField, s.TextField, s.URLField} {
		if f = strings.TrimSpace(f); f != "" {
			mapped[f] = true
		}
	}
	if len(mapped) == 0 {
		return fmt.Errorf(
			"the share target names %s and maps none of title, text or url "+
				"onto it, so a share would arrive empty", s.Form)
	}
	var unreachable []string
	for _, r := range required {
		if !mapped[r] {
			unreachable = append(unreachable, r)
		}
	}
	if len(unreachable) > 0 {
		return fmt.Errorf(
			"%s requires %s, and a share carries only title, text and url — "+
				"so every share would be refused. Map those fields, or point "+
				"the share target at a form whose required fields it can fill",
			s.Form, strings.Join(unreachable, ", "))
	}
	return nil
}
