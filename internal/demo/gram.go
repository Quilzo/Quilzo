package demo

import (
	"github.com/rsh1k/scrivet/internal/collection"
	"github.com/rsh1k/scrivet/internal/form"
	"github.com/rsh1k/scrivet/internal/listing"
	"github.com/rsh1k/scrivet/internal/menu"
	"github.com/rsh1k/scrivet/internal/schema"
	"github.com/rsh1k/scrivet/internal/taxonomy"
)

// Gram is the demonstration application.
//
// Built through the admin interface first and written down afterwards, in that
// order deliberately: every value below is one somebody typed into a screen,
// so anything the screens refuse cannot end up here. Four bugs were found on
// the way, which is the argument for doing it in that order.
//
// # The shape, and why it is that shape
//
// Photographs are records, not pages. A record lives in a collection and a
// collection is what a listing can query, which is what makes the feed
// sortable and the explore page filterable. Pages are the screens of the
// application, and each one names the listing it shows.
//
// People are pages with a content type, so a profile missing a required field
// is refused before it is stored rather than rendering half a card.
//
// Stories are pages carrying a publish window. One of them has not started yet
// and is not served anywhere, and no scheduled job is responsible for that —
// the check happens when the page is asked for, so it cannot be late.
func Gram() *Site {
	s := &Site{
		Name: "Gram",
		Summary: "A photo-sharing site: a feed over structured records, an " +
			"explore page with a real filter, profiles with a content type, " +
			"stories that take themselves down, and a message box.",
		Template: templateHTML(),
		CSS:      styleSheet(),
		Bind:     map[string]string{},
		Pages:    map[string]any{},
		Records:  map[string][]collection.Record{},
	}
	s.addMedia()
	s.addTypes()
	s.addTaxonomy()
	s.addPosts()
	s.addPeople()
	s.addStories()
	s.addScreens()
	s.addListings()
	s.addMenu()
	s.addForms()
	return s
}

func (s *Site) addMedia() {
	for _, a := range []struct{ name, alt string }{
		{"harbour-dawn", "Orange dawn light over a still harbour, masts in silhouette"},
		{"kitchen-table", "A wooden kitchen table in warm light, flour dusted across it"},
		{"studio-window", "Cool grey light falling through a tall studio window"},
		{"night-market", "Red and amber lanterns strung above a crowded night market"},
		{"coast-road", "A pale blue coast road curving toward deep water"},
		{"paper-and-ink", "An open notebook and a fountain pen on off-white paper"},
		{"rooftop-signal", "Golden hour on a rooftop, city haze behind an aerial"},
		{"morning-run", "Green park path in early light, mist low over the grass"},
		{"avatar-mira", "Mira's avatar, a warm coral gradient"},
		{"avatar-theo", "Theo's avatar, a cool blue gradient"},
		{"avatar-nel", "Nel's avatar, a soft green gradient"},
		{"avatar-sol", "Sol's avatar, an amber gradient"},
	} {
		s.Media = append(s.Media, Asset{
			Name: a.name, Alt: a.alt, Bytes: image(a.name)})
	}
}

func (s *Site) addTypes() {
	// Note what is absent: neither type declares "expires". It is reserved —
	// any page may carry it whatever its type — and a type declaring it would
	// be describing something it does not own. The interface refuses it, which
	// is how that was learned.
	s.Types = []schema.Type{
		{
			Name:        "post",
			Description: "A photograph with a caption, which is the whole app.",
			Fields: []schema.Field{
				{Name: "image", Kind: schema.Text, Label: "Photo", Required: true},
				{Name: "alt", Kind: schema.Text, Label: "Alt text",
					AltFor: "image", Required: true},
				{Name: "caption", Kind: schema.LongText, Label: "Caption", MaxLen: 2200},
				{Name: "place", Kind: schema.Text, Label: "Location"},
				{Name: "topic", Kind: schema.Choice, Label: "Topic",
					Choices: []string{"travel", "food", "design", "music", "photography"}},
				{Name: "author", Kind: schema.Text, Label: "Posted by", Required: true},
				{Name: "posted", Kind: schema.Date, Label: "Posted on", Required: true},
			},
		},
		{
			Name:        "story",
			Description: "A photograph with a shelf life.",
			Fields: []schema.Field{
				{Name: "image", Kind: schema.Text, Label: "Photo", Required: true},
				{Name: "alt", Kind: schema.Text, Label: "Alt text",
					AltFor: "image", Required: true},
				{Name: "caption", Kind: schema.Text, Label: "Caption", MaxLen: 120},
				{Name: "author", Kind: schema.Text, Label: "Posted by", Required: true},
			},
		},
		{
			Name:        "profile",
			Description: "A person on Gram.",
			Fields: []schema.Field{
				{Name: "handle", Kind: schema.Slug, Label: "Handle", Required: true},
				{Name: "display", Kind: schema.Text, Label: "Display name", Required: true},
				{Name: "avatar", Kind: schema.Text, Label: "Avatar"},
				{Name: "avatar_alt", Kind: schema.Text, Label: "Avatar alt",
					AltFor: "avatar"},
				{Name: "bio", Kind: schema.LongText, Label: "Bio", MaxLen: 300},
				{Name: "link", Kind: schema.URL, Label: "Link"},
				{Name: "joined", Kind: schema.Date, Label: "Joined"},
			},
		},
	}
}

func (s *Site) addTaxonomy() {
	set := &taxonomy.Set{}
	// Closed, which is the default and the point: a misspelled tag cannot
	// quietly invent a new one and split a listing in two.
	v := taxonomy.Vocabulary{Name: "topics", Label: "Topics"}
	for _, t := range []struct {
		id, label, desc string
		syn             []string
	}{
		{"travel", "Travel", "Somewhere the photographer went.",
			[]string{"trip", "holiday"}},
		{"food", "Food", "Something cooked or eaten.",
			[]string{"cooking", "eating"}},
		{"design", "Design", "Made objects, type, and the places work happens.",
			[]string{"craft"}},
		{"music", "Music", "Playing, listening, or the rooms it happens in.",
			[]string{"sound"}},
		{"photography", "Photography", "About the photograph itself rather " +
			"than its subject.", []string{"photo", "pictures"}},
	} {
		v.Terms = append(v.Terms, taxonomy.Term{
			ID: t.id, Label: t.label, Description: t.desc, Synonyms: t.syn})
	}
	_ = set.Add(v)
	s.Vocabularies = set
}

func (s *Site) addPosts() {
	type p struct {
		slug, img, alt, caption, place, topic, author, posted string
		likes                                                 int
	}
	for _, x := range []p{
		{"harbour-dawn", "harbour-dawn",
			"Orange dawn light over a still harbour, masts in silhouette",
			"Up before the boats. Worth every minute of it.",
			"Gothenburg", "travel", "mira", "2026-07-02", 214},
		{"kitchen-table", "kitchen-table",
			"A wooden kitchen table in warm light, flour dusted across it",
			"Sunday. Third attempt at the sourdough and this one has a crumb I am proud of.",
			"Home", "food", "theo", "2026-07-05", 508},
		{"studio-window", "studio-window",
			"Cool grey light falling through a tall studio window",
			"North light does half the work. The other half is turning up.",
			"Studio", "design", "nel", "2026-07-09", 97},
		{"night-market", "night-market",
			"Red and amber lanterns strung above a crowded night market",
			"Everything smells like charcoal and lime. Stayed until they packed up.",
			"Hanoi", "travel", "sol", "2026-07-14", 1322},
		{"coast-road", "coast-road",
			"A pale blue coast road curving toward deep water",
			"Forty minutes of this and then the road simply stops at the sea.",
			"Donegal", "travel", "mira", "2026-07-19", 436},
		{"paper-and-ink", "paper-and-ink",
			"An open notebook and a fountain pen on off-white paper",
			"Still faster than any app I have tried.",
			"Studio", "design", "nel", "2026-07-23", 181},
		{"rooftop-signal", "rooftop-signal",
			"Golden hour on a rooftop, city haze behind an aerial",
			"Climbed six flights for eleven minutes of light.",
			"Lisbon", "photography", "sol", "2026-07-28", 765},
		{"morning-run", "morning-run",
			"Green park path in early light, mist low over the grass",
			"Cold enough to see your breath. Empty enough to hear it.",
			"Home", "photography", "theo", "2026-08-03", 329},
	} {
		s.Records["posts"] = append(s.Records["posts"], collection.Record{
			Fields: map[string]any{
				"slug": x.slug, "image": Ref + x.img, "alt": x.alt,
				"caption": x.caption, "place": x.place, "topic": x.topic,
				"author": x.author, "posted": x.posted, "likes": x.likes,
			},
		})
	}
}

func (s *Site) addPeople() {
	type p struct{ handle, display, bio, link, joined string }
	for _, x := range []p{
		{"mira", "Mira Okonkwo",
			"Harbour light and long walks. Runs this place.",
			"https://example.org/mira", "2026-01-08"},
		{"theo", "Theo Lindqvist",
			"Cooks on weekends, edits on weekdays.",
			"https://example.org/theo", "2026-01-14"},
		{"nel", "Nel Ashford",
			"Studio light, paper, and very strong coffee.", "", "2026-02-02"},
		{"sol", "Sol Reyes",
			"Rooftops, night markets, anything after sundown.", "", "2026-02-19"},
	} {
		name := "people/" + x.handle
		body := map[string]any{
			"handle": x.handle, "display": x.display,
			"avatar":     Ref + "avatar-" + x.handle,
			"avatar_alt": x.display + "'s avatar",
			"bio":        x.bio, "joined": x.joined,
		}
		// An optional field left blank is left out rather than stored empty.
		// Storing "" and then binding a type to it is how a page becomes
		// invalid without anybody writing to it.
		if x.link != "" {
			body["link"] = x.link
		}
		s.Pages[name] = body
		s.Bind[name] = "profile"
	}
}

func (s *Site) addStories() {
	// Two visible, one embargoed. The embargoed one is the point: it is
	// published, it is in the live commit, and it is not served — because the
	// window is read when the page is asked for. Nothing has to run for that.
	type st struct{ slug, img, alt, caption, author, starts, expires string }
	for _, x := range []st{
		{"mira-harbour", "harbour-dawn",
			"Orange dawn light over a still harbour",
			"still here, still cold", "mira", "", "2026-12-31T23:59:59Z"},
		{"theo-bread", "kitchen-table",
			"Flour dusted across a wooden table",
			"loaf number four", "theo", "", "2027-01-15T18:00:00Z"},
		{"sol-rooftop", "rooftop-signal",
			"Golden hour on a rooftop",
			"back up here at sundown", "sol",
			"2026-09-01T17:00:00Z", "2027-09-02T17:00:00Z"},
	} {
		body := map[string]any{
			"image": Ref + x.img, "alt": x.alt,
			"caption": x.caption, "author": x.author,
		}
		if x.starts != "" {
			body["starts"] = x.starts
		}
		body["expires"] = x.expires
		name := "stories/" + x.slug
		s.Pages[name] = body
		s.Bind[name] = "story"
	}
}

func (s *Site) addScreens() {
	s.Pages["index"] = map[string]any{
		"title":    "Gram",
		"intro":    "Eight photographs and the people who took them.",
		"listings": "feed",
		"screen":   "feed",
	}
	s.Pages["popular"] = map[string]any{
		"title":    "Most liked",
		"intro":    "The same eight, in a different order.",
		"listings": "popular",
		"screen":   "feed",
	}
	s.Pages["explore"] = map[string]any{
		"title": "Explore",
		"intro": "Pick a topic. The list is closed, so a tag nobody agreed " +
			"on cannot appear here.",
		"listings": "by_topic",
		"screen":   "explore",
	}
	s.Pages["stories"] = map[string]any{
		"title": "Stories",
		"intro": "Three stories. One of them is not here yet — it has a " +
			"start date in September, and the page will begin answering on " +
			"its own when that moment passes.",
		"screen": "stories",
	}
	s.Pages["messages"] = map[string]any{
		"title": "Messages",
		"intro": "Send something to whoever runs this. It goes to a store " +
			"the public server can write to and cannot read back.",
		"screen": "messages",
		"form":   "message",
		"privacy": "Messages reach the people who run Gram and nobody else. " +
			"We keep them for 90 days and then they are deleted automatically.",
	}
	s.Pages["about"] = map[string]any{
		"title":  "About Gram",
		"intro":  "What this is, and how it is put together.",
		"screen": "about",
		"body":   aboutBody,
	}
}

const aboutBody = `<h2>What this is</h2>
<p>Gram is a demonstration. Eight photographs, four people, a feed, an explore
page with a real filter, stories that take themselves down, and a message box.
Everything you can see was built through the Scrivet admin interface — no
configuration files were edited, and no code was written for it beyond one HTML
template and one stylesheet.</p>

<h2>How it is put together</h2>
<p>The photographs are <strong>records</strong> in a collection, which is what
makes the feed sortable and the explore page filterable. The people are
<strong>pages</strong> with a content type, so a profile missing a required
field is refused before it is stored. The stories are pages carrying a publish
window: one of them does not appear anywhere on this site yet, because its
start date has not arrived, and no scheduled job is involved in that — the check
happens when the page is asked for.</p>
<p>The navigation is a <strong>menu</strong>, and it refused to save while it
pointed at pages that did not exist yet. The topics are a closed
<strong>vocabulary</strong>, so a misspelled tag cannot quietly create a new
one. The message box is a <strong>form</strong>, and it is the only thing on
this server that can write anything.</p>

<h2>What is deliberately missing</h2>
<p>There is no comment thread, no follower graph and no messaging between
visitors, because none of those are content management and pretending otherwise
would make this demonstration dishonest. What a CMS is responsible for is the
part above: structured content, a query over it, a gate before publication, and
a record of who changed what.</p>`

func (s *Site) addListings() {
	fields := []string{"slug", "image", "alt", "caption", "place", "topic",
		"author", "posted", "likes"}
	base := func(name, label, desc, sort string, rows int) listing.Listing {
		return listing.Listing{
			Name: name, Label: label, Description: desc,
			Collection: "posts", Fields: fields,
			Sort: sort, Descending: true, Rows: rows,
		}
	}
	feed := base("feed", "The feed", "Everything, newest first.", "posted", 24)
	popular := base("popular", "Most liked",
		"The same posts, ordered by how many likes they have.", "likes", 12)

	byTopic := base("by_topic", "Explore a topic",
		"Posts filtered to one topic, chosen by the reader.", "posted", 24)
	byTopic.Params = []listing.Param{{
		Name: "topic", Kind: listing.Slug, Help: "Which topic to show"}}
	byTopic.Where = []listing.Condition{{
		Field: "topic", Match: listing.Is, Param: "topic"}}

	byAuthor := base("by_author", "Someone's posts",
		"Everything one person has posted.", "posted", 24)
	byAuthor.Params = []listing.Param{{
		Name: "author", Kind: listing.Slug, Help: "Whose posts to show"}}
	byAuthor.Where = []listing.Condition{{
		Field: "author", Match: listing.Is, Param: "author"}}

	search := base("search", "Search captions",
		"Substring search over captions.", "posted", 24)
	search.Params = []listing.Param{{
		Name: "q", Kind: listing.Text, Help: "What to look for"}}
	search.Where = []listing.Condition{{
		Field: "caption", Match: listing.Has, Param: "q"}}

	s.Listings = []listing.Listing{feed, popular, byTopic, byAuthor, search}
}

func (s *Site) addMenu() {
	set := &menu.Set{}
	m := menu.Menu{Name: "main", Label: "Gram"}
	for i, x := range []struct{ id, label, target string }{
		{"i1", "Feed", "index"},
		{"i2", "Explore", "explore"},
		{"i3", "Popular", "popular"},
		{"i4", "Stories", "stories"},
		{"i5", "Messages", "messages"},
		{"i6", "About", "about"},
	} {
		m.Items = append(m.Items, menu.Item{
			ID: x.id, Label: x.label, Kind: menu.Page, Target: x.target,
			Order: (i + 1) * 10,
		})
	}
	_ = set.Add(m)
	s.Menus = set
}

func (s *Site) addForms() {
	s.Forms = []form.Form{
		{
			Name: "message", Label: "Send a message",
			Notice: "Messages reach the people who run Gram and nobody else. " +
				"We keep them for 90 days and then they are deleted " +
				"automatically.",
			RetentionDays: 90,
			Fields: []form.Field{
				{Name: "name", Label: "Your name", Kind: form.Line, Required: true},
				{Name: "email", Label: "Email", Kind: form.Email, Required: true},
				{Name: "subject", Label: "About", Kind: form.Choice,
					Choices: []string{"a photo", "a collaboration", "something else"}},
				{Name: "body", Label: "Message", Kind: form.Para, Required: true},
			},
		},
		{
			Name: "report", Label: "Report a post",
			Notice: "Reports go to the people who run Gram. We keep them for " +
				"a year so we can see a repeated problem, then they are deleted.",
			RetentionDays: 365,
			Fields: []form.Field{
				{Name: "post", Label: "Which post", Kind: form.Line, Required: true},
				{Name: "reason", Label: "What is wrong", Kind: form.Choice,
					Choices: []string{"not mine", "misleading", "abusive", "something else"}},
				{Name: "detail", Label: "Anything else", Kind: form.Para},
			},
		},
	}
}
