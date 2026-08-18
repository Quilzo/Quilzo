package admin

import (
	"net/http"
	"strconv"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/site"
)

// The screen somebody sees first.
//
// # Why a checklist of real state rather than a tour
//
// The usual onboarding is a carousel of screenshots that says the same thing to
// everybody and is dismissed without being read. It cannot say anything true,
// because it does not know what is in the store — so the second screen somebody
// sees contradicts it, and the tour is the first thing in the product they
// learned to ignore.
//
// This reads the store instead. Every step is a question about *this*
// installation answered at request time: is there a page, is a type bound to
// it, has anything been published, does anybody besides you hold a role. A step
// that is done says so and stays visible, because "what did I already do" is
// the question somebody coming back after a week actually has.
//
// # Why it explains what will refuse them
//
// The gates are the thing about this program that surprises people, and being
// surprised by a refusal is how somebody decides a tool is broken rather than
// careful. So the last section is the list of things that will stop a publish,
// stated before the first one happens.

// StartDismissedCookie records that somebody has finished with this screen.
//
// A cookie rather than a stored flag on the person, deliberately. Onboarding is
// a fact about a screen somebody has read, not a property of the content store,
// and putting it in the store would mean an editor's first-run state survives
// into a colleague's session on a shared account. The cost is that a new
// machine shows it again, which is the right failure: seeing the getting
// started screen once more is cheaper than never seeing it.
const StartDismissedCookie = "quilzo_started"

// step is one thing to do, and whether this store shows it done.
type step struct {
	Title string
	// Body says what the step is for. Never what to click — a screen that
	// narrates its own buttons goes stale the moment one is renamed.
	Body string
	// Where is the screen that does it, and What names the link.
	Where string
	What  string
	// Done is read from the store at request time.
	Done bool
	// DoneNote states what was found, so a tick is evidence rather than a
	// claim. "3 pages" is checkable; a green tick is not.
	DoneNote string
}

// startState answers each step against the store.
func (s *Server) startState(p principal) []step {
	pages := 0
	if got, err := site.PagesAt(s.Store, site.RefDraft); err == nil {
		pages = len(got)
	} else if got, err := site.PagesAt(s.Store, site.RefLive); err == nil {
		pages = len(got)
	}

	published := s.Store.GetRef(site.RefLive) != ""

	types := 0
	if s.Types != nil && s.Types.Load != nil {
		if st, err := s.Types.Load(); err == nil && st != nil {
			types = len(st.Registry.Types)
		}
	}

	// People other than whoever is looking, because "you have an account" is
	// not a step and counting yourself would tick it on a fresh store.
	others := 0
	if s.Policy != nil {
		for _, name := range s.Policy.Principals() {
			if name != p.Name {
				others++
			}
		}
	}

	return []step{
		{
			Title: "Write something",
			Body: "A page is fields, not markup. What it looks like is the " +
				"template's job, which is why the same page can be a web page, " +
				"a feed entry and an API response without being written three " +
				"times.",
			Where: "/", What: "Pages",
			Done: pages > 0, DoneNote: counted(pages, "page", "pages"),
		},
		{
			Title: "Give it a shape",
			Body: "A content type says which fields a page must have and what " +
				"they may contain. Every surface checks it — the browser, the " +
				"command line and the agent interface — so content that is " +
				"wrong cannot be stored by going around this screen.",
			Where: "/types", What: "Types",
			Done: types > 0, DoneNote: counted(types, "type", "types"),
		},
		{
			Title: "Publish it",
			Body: "Publishing moves one pointer. Nothing is overwritten and the " +
				"previous version is still addressable, so rolling back is the " +
				"pointer moving again rather than a restore from a backup.",
			Where: "/publish", What: "Review and publish",
			Done: published, DoneNote: "live",
		},
		{
			Title: "Decide who else may do what",
			Body: "Four roles on a ladder: reader, author, publisher, admin. A " +
				"token can carry less than the person holding it and never " +
				"more, so a credential for a script is narrower than the " +
				"person who issued it.",
			Where: "/people", What: "People",
			Done: others > 0, DoneNote: counted(others, "other person", "other people"),
		},
	}
}

// counted renders "1 page" or "3 pages", so a completed step states what was
// found rather than only that something was.
func counted(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// gate is something that will refuse a publish, said before it does.
type gate struct {
	Name string
	What string
}

// gates is the list of refusals, in the order somebody meets them.
//
// Stated up front because a refusal nobody expected reads as a malfunction. The
// override exists for every one of these and is recorded in the commit, which
// is the part that makes refusing acceptable rather than obstructive.
var gates = []gate{
	{"Accessibility", "The page is rendered and checked. A failure that makes " +
		"the page unusable for somebody stops the publish rather than warning " +
		"about it."},
	{"Content types", "A page bound to a type must satisfy it. The store is " +
		"append-only, so a page that is wrong stays addressable forever — it " +
		"is refused before it is written rather than fixed afterwards."},
	{"Provenance", "AI-generated content carries a machine-readable mark. " +
		"Publishing unmarked AI content is refused, because the EU AI Act " +
		"asks for the mark and a label people can read is not the same thing."},
	{"Menus", "A menu entry pointing at a page that is not going live is " +
		"refused, naming the entry. A navigation link to nothing is a 404 " +
		"somebody finds later."},
	{"Approval", "Where dual authorisation is configured, an approval names " +
		"the content hash it agreed to — so editing the draft afterwards does " +
		"not carry the approval forward."},
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}

	steps := s.startState(p)
	done := 0
	for _, st := range steps {
		if st.Done {
			done++
		}
	}

	s.render(w, r, "start.html", map[string]any{
		"Title": "Get started", "Principal": p, "Nav": "start",
		"Steps": steps, "Done": done, "Total": len(steps),
		"Gates":     gates,
		"Dismissed": startDismissed(r),
	})
}

// handleStartDone records that somebody is finished with this screen.
func (s *Server) handleStartDone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Authenticated, because it sets a cookie on this origin and nothing
	// unauthenticated has a reason to.
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: StartDismissedCookie, Value: "1", Path: "/",
		MaxAge: 365 * 24 * 3600, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// startDismissed reports whether this person has finished with the screen.
func startDismissed(r *http.Request) bool {
	c, err := r.Cookie(StartDismissedCookie)
	return err == nil && c.Value == "1"
}
