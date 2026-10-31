// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/theme"
)

// Building a whole site from a sentence.
//
// The site builder writes a site package (site.go): the site's name and
// look, its pages, its menus, a contact form, a privacy page and a question
// box that answers from the site's own pages. It is then read, approved and
// installed like any other package, so a whole site is one decision that
// can be taken back as one.
//
// It works the same way with a model or without one. Without one, the kind
// of site picks the pages and the sections on them. With one, the model
// rewrites that start for the brief, and its answer is read back through
// the same checks as any draft and put right where it can be (RepairSite).
// Either way the result is a declaration: content blocks this program
// already runs and has tested, never code.
//
// The builder never makes up a fact. Where a page needs a price, an
// address, opening hours, a date, somebody's name or words, or a figure,
// and the brief does not give it, the page says [[what goes here]]
// (internal/section/fill.go). The card counts them, `quilzo site fill` and
// the Fill in screen write them in, and the publish gate refuses a page
// that still holds one.
//
// The privacy page is written from what the package collects, not by the
// model: every form, what it asks for, why, on what basis and for how long,
// and what the question box keeps. It is rewritten whenever the site is,
// so it says what the site does.

// SiteBrief is what somebody asks for when they ask for a site.
type SiteBrief struct {
	// Description is what the site is for, in their words.
	Description string `json:"description"`
	// Name is what the site is called. A model may suggest one when this is
	// empty; without a model it is needed.
	Name string `json:"name,omitempty"`
	// Kind is one of SiteKinds; empty is read from the description.
	Kind string `json:"kind,omitempty"`
	// Colour and Style are the look, when the person chose one.
	Colour string `json:"colour,omitempty"`
	Style  string `json:"style,omitempty"`
}

// MaxBrief bounds a brief: a paragraph, not a document.
const MaxBrief = 2000

// Bounds on what a built site holds, so a person can read all of it.
const (
	maxSitePages = 16
	maxSiteForms = 4
)

// SiteKind is a kind of site the builder knows how to start.
type SiteKind struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
	// Colour and Style are the look it starts with.
	Colour string `json:"colour"`
	Style  string `json:"style"`
	// words in a description suggest this kind.
	words string
	// pages are its pages before the ones every site has.
	pages func(name string) []sitePage
}

// sitePage is a page and where it sits in the main menu: a label of ""
// leaves it out.
type sitePage struct {
	name, label string
	body        obj
}

type obj = map[string]any

// SiteKinds lists the kinds of site, in the order a screen offers them.
func SiteKinds() []SiteKind { return siteKinds }

// SiteKindNamed returns a kind by name.
func SiteKindNamed(name string) (SiteKind, bool) {
	for _, k := range siteKinds {
		if k.Name == name {
			return k, true
		}
	}
	return SiteKind{}, false
}

// GuessSiteKind reads which kind of site a description is for, by the words
// in it. A description that names none is a business.
func GuessSiteKind(description string) SiteKind {
	words := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(description), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-'
	}) {
		words[w] = true
		words[strings.TrimSuffix(w, "s")] = true
	}
	best, score := siteKinds[0], 0
	for _, k := range siteKinds {
		n := 0
		for _, w := range strings.Fields(k.words) {
			if words[w] {
				n++
			}
		}
		if n > score {
			best, score = k, n
		}
	}
	return best
}

// mark is a blank for the person to fill in.
var mark = section.Mark

func sec(kind string, fields obj) any { return obj{kind: fields} }

func hero(lead, cta, ctaHref, second, secondHref string) obj {
	h := obj{"style": "center", "surface": "surface-wash", "lead": lead}
	if cta != "" {
		h["cta_label"], h["cta_href"] = cta, ctaHref
	}
	if second != "" {
		h["secondary_label"], h["secondary_href"] = second, secondHref
	}
	return h
}

func plainHero(lead string) obj { return obj{"style": "plain", "lead": lead} }

func card(icon, title, body string) obj { return obj{"icon": icon, "title": title, "body": body} }

func step(title, body string) obj { return obj{"title": title, "body": body} }

func qa(q, a string) obj { return obj{"q": q, "a": a} }

func cta(title, body, label, href string) any {
	return sec("cta", obj{"title": title, "body": body, "cta_label": label, "cta_href": href})
}

func row(cells ...any) obj { return obj{"cells": cells} }

var siteKinds = []SiteKind{
	{
		Name: "business", Title: "A business",
		Summary: "What you offer, how working with you goes, and how to get in touch.",
		Colour:  "#1d4ed8", Style: "business",
		words: "service consultant consulting consultancy agency plumber plumbing electrician lawyer solicitor " +
			"accountant accounting bookkeeping clinic dentist dental therapist therapy salon barber hairdresser " +
			"garage repair cleaning cleaner builder firm practice tutor tutoring coach coaching landscaping " +
			"gardener gardening vet physio physiotherapy decorator roofer locksmith removals",
		pages: func(name string) []sitePage {
			services := []any{
				card("bolt", mark("your first service"), mark("what your first service is, and who it is for")),
				card("handshake", mark("your second service"), mark("what your second service is, and who it is for")),
				card("schedule", mark("your third service"), mark("what your third service is, and who it is for")),
			}
			return []sitePage{
				{name: "index", body: obj{
					"title": name,
					"hero":  hero(mark("a sentence on what you do and who it is for"), "Get in touch", "/contact", "What we do", "/services"),
					"sections": []any{
						sec("features", obj{"title": "What we do", "columns": "3", "items": services}),
						sec("steps", obj{"title": "How it works", "items": []any{
							step("Tell us what you need", "Send a message, or ask a question in the box below."),
							step("We talk it through", mark("what happens after somebody gets in touch")),
							step("We get to work", mark("how the work is done, and how long it usually takes")),
						}}),
						sec("faq", obj{"title": "Questions", "items": []any{
							qa("Where do you work?", mark("the area you cover")),
							qa("What does it cost?", mark("how you price your work")),
							qa("How soon can you start?", mark("how far ahead you are booked")),
						}}),
						cta("Tell us what you need", "Send a message and we will get back to you.", "Get in touch", "/contact"),
					},
				}},
				{name: "services", label: "What we do", body: obj{
					"title": "What we do",
					"hero":  plainHero(mark("a sentence on the work you take on")),
					"sections": []any{
						sec("features", obj{"title": "Services", "columns": "3", "items": services}),
						cta("Not sure which you need?", "Tell us about the job and we will say.", "Get in touch", "/contact"),
					},
				}},
			}
		},
	},
	{
		Name: "product", Title: "A product or app",
		Summary: "What it does, how it works, what it costs and how to start.",
		Colour:  "#4f46e5", Style: "glass",
		words: "app software saas platform product startup api tool plugin extension device gadget " +
			"subscription dashboard automation integration",
		pages: func(name string) []sitePage {
			return []sitePage{
				{name: "index", body: obj{
					"title": name,
					"hero":  hero(mark("a sentence on what it does and who it is for"), "Get started", "/contact", "How it works", "/how-it-works"),
					"sections": []any{
						sec("features", obj{"title": "What it does", "columns": "3", "items": []any{
							card("bolt", mark("the first thing it does"), mark("why the first thing matters to somebody using it")),
							card("shield", mark("the second thing it does"), mark("why the second thing matters")),
							card("insights", mark("the third thing it does"), mark("why the third thing matters")),
						}}),
						sec("faq", obj{"title": "Questions", "items": []any{
							qa("Who is it for?", mark("who it is for")),
							qa("What does it cost?", mark("what it costs, or that it is free")),
							qa("Where is my data kept?", mark("where data is kept and who can see it")),
						}}),
						cta("Try it", mark("the one thing to do to start"), "Get started", "/contact"),
					},
				}},
				{name: "how-it-works", label: "How it works", body: obj{
					"title": "How it works",
					"hero":  plainHero(mark("a sentence on how it works")),
					"sections": []any{
						sec("steps", obj{"title": "From start to done", "items": []any{
							step(mark("the first step"), mark("what somebody does first")),
							step(mark("the second step"), mark("what happens next")),
							step(mark("the third step"), mark("what they have at the end")),
						}}),
					},
				}},
				{name: "pricing", label: "Pricing", body: obj{
					"title": "Pricing",
					"hero":  plainHero(mark("a sentence on how pricing works")),
					"sections": []any{
						sec("pricing", obj{"title": "Plans", "items": []any{
							obj{"name": mark("your first plan"), "price": mark("the first plan's price"), "period": "/month",
								"body": mark("who the first plan is for"), "cta_label": "Start", "cta_href": "/contact"},
							obj{"name": mark("your second plan"), "price": mark("the second plan's price"), "period": "/month",
								"featured": "featured", "body": mark("who the second plan is for"),
								"cta_label": "Start", "cta_href": "/contact"},
						}}),
					},
				}},
			}
		},
	},
	{
		Name: "restaurant", Title: "A café, restaurant or bar",
		Summary: "The food, when you are open, where to find you and how to get in touch.",
		Colour:  "#c2410c", Style: "soft",
		words: "restaurant cafe café coffee bakery bakehouse bar pub bistro kitchen pizzeria pizza deli diner " +
			"brewery takeaway catering tearoom food brunch patisserie wine",
		pages: func(name string) []sitePage {
			return []sitePage{
				{name: "index", body: obj{
					"title": name,
					"hero":  hero(mark("a sentence on the food and the place"), "See the menu", "/menu", "Find us", "/visit"),
					"sections": []any{
						sec("features", obj{"title": "On the menu", "columns": "3", "items": []any{
							card("restaurant", mark("your best-known dish"), mark("what is in your best-known dish")),
							card("local_cafe", mark("a second dish or drink"), mark("what is in the second dish or drink")),
							card("star", mark("a third dish"), mark("what is in the third dish")),
						}}),
						sec("split", obj{"title": "Come and see us", "image": "", "alt": "", "paragraphs": []any{
							mark("your address"), mark("your opening hours, in a sentence"),
						}}),
						cta("Hungry?", "The menu, the hours and how to find us are a click away.", "Find us", "/visit"),
					},
				}},
				{name: "menu", label: "Menu", body: obj{
					"title": "Menu",
					"hero":  plainHero(mark("when this menu is served")),
					"sections": []any{
						sec("table", obj{"title": "Food", "caption": "Dishes and prices",
							"columns": []any{"Dish", "Price"}, "rows": []any{
								row(mark("your best-known dish"), mark("the price of your best-known dish")),
								row(mark("a second dish or drink"), mark("the price of the second dish or drink")),
								row(mark("a third dish"), mark("the price of the third dish")),
							}}),
						sec("prose", obj{"title": "Allergies", "paragraphs": []any{mark("how somebody finds out what is in each dish")}}),
					},
				}},
				{name: "visit", label: "Visit", body: obj{
					"title": "Visit",
					"hero":  plainHero(mark("your address")),
					"sections": []any{
						sec("table", obj{"title": "Opening hours", "caption": "When we are open",
							"columns": []any{"Day", "Hours"}, "rows": []any{
								row("Monday to Friday", mark("weekday hours")),
								row("Saturday", mark("Saturday hours")),
								row("Sunday", mark("Sunday hours")),
							}}),
						sec("prose", obj{"title": "Getting here", "paragraphs": []any{
							mark("how to get there, and where to park"),
							mark("step-free access and anything else a visitor should know"),
						}}),
					},
				}},
			}
		},
	},
	{
		Name: "portfolio", Title: "A portfolio",
		Summary: "Your work first, then who made it and how to commission it.",
		Colour:  "#0f766e", Style: "editorial",
		words: "portfolio photographer photography designer illustrator illustration artist art architect " +
			"architecture maker potter ceramics painter painting creative freelance freelancer filmmaker " +
			"animator animation sculptor jeweller weaver",
		pages: func(name string) []sitePage {
			work := []any{
				obj{"image": "", "alt": "", "caption": mark("a piece of work")},
				obj{"image": "", "alt": "", "caption": mark("another piece")},
				obj{"image": "", "alt": "", "caption": mark("a third piece")},
			}
			return []sitePage{
				{name: "index", body: obj{
					"title": name,
					"hero":  hero(mark("a sentence on the work you make"), "See the work", "/work", "Get in touch", "/contact"),
					"sections": []any{
						sec("gallery", obj{"title": "Selected work", "shape": "square", "items": work}),
						cta("Have something in mind?", "Tell me about it.", "Get in touch", "/contact"),
					},
				}},
				{name: "work", label: "Work", body: obj{
					"title": "Work",
					"hero":  plainHero(mark("a sentence on the kind of work you take on")),
					"sections": []any{
						sec("gallery", obj{"title": "Projects", "shape": "square", "items": work}),
						sec("steps", obj{"title": "Working together", "items": []any{
							step("Get in touch", "Say what you have in mind, and when you need it."),
							step(mark("what happens next"), mark("how you agree the brief and the price")),
							step(mark("how it ends"), mark("what somebody receives at the end")),
						}}),
					},
				}},
			}
		},
	},
	{
		Name: "community", Title: "A charity, club or community group",
		Summary: "What you do, how to join in and how to help.",
		Colour:  "#15803d", Style: "classic",
		words: "charity nonprofit non-profit volunteer volunteering club community association society foundation " +
			"church mosque temple synagogue school parish group trust cooperative co-op union scouts choir " +
			"team league allotment residents",
		pages: func(name string) []sitePage {
			return []sitePage{
				{name: "index", body: obj{
					"title": name,
					"hero":  hero(mark("a sentence on what you do and for whom"), "Get involved", "/get-involved", "About us", "/about"),
					"sections": []any{
						sec("features", obj{"title": "What we do", "columns": "3", "items": []any{
							card("groups", mark("something you do"), mark("who that helps, and how")),
							card("favorite", mark("something else you do"), mark("who the second thing helps, and how")),
							card("calendar_month", mark("a third thing you do"), mark("who the third thing helps, and how")),
						}}),
						sec("steps", obj{"title": "How to join in", "items": []any{
							step("Say hello", "Tell us you are interested on the get involved page."),
							step(mark("what happens next"), mark("how a new person is welcomed")),
							step("Come along", mark("where and when you meet")),
						}}),
						cta("Every bit helps", "There is a way to help whatever time you have.", "Get involved", "/get-involved"),
					},
				}},
				{name: "get-involved", label: "Get involved", body: obj{
					"title": "Get involved",
					"hero":  plainHero("Tell us you would like to help, and we will be in touch."),
					"form":  "volunteer",
					"sections": []any{
						sec("features", obj{"title": "Ways to help", "columns": "3", "items": []any{
							card("favorite", "Volunteer", mark("what volunteers do, and how much time it takes")),
							card("groups", "Join", mark("how to become a member, and what it costs")),
							card("campaign", "Spread the word", "Tell somebody who would want to know about us."),
						}}),
					},
				}},
			}
		},
	},
	{
		Name: "event", Title: "An event",
		Summary: "When and where, what happens, and how to come.",
		Colour:  "#be123c", Style: "expressive",
		words: "conference festival wedding event meetup summit workshop gig concert exhibition fair race " +
			"marathon party celebration retreat hackathon launch reunion ceremony",
		pages: func(name string) []sitePage {
			return []sitePage{
				{name: "index", body: obj{
					"title": name,
					"hero": func() obj {
						h := hero(mark("a sentence on what the event is and who it is for"), "Register", "/register", "Programme", "/programme")
						h["eyebrow"] = mark("the date and the place, in a few words")
						return h
					}(),
					"sections": []any{
						sec("features", obj{"title": "What to expect", "columns": "3", "items": []any{
							card("calendar_month", mark("the main thing that happens"), mark("why somebody would come for the main thing")),
							card("groups", mark("something else that happens"), mark("why somebody would come for that")),
							card("celebration", mark("a third thing that happens"), mark("why somebody would come for the third")),
						}}),
						sec("faq", obj{"title": "Questions", "items": []any{
							qa("Where is it?", mark("the venue and how to get there")),
							qa("What does it cost?", mark("what it costs, or that it is free")),
							qa("Is it accessible?", mark("step-free access, seating and anything else people ask")),
						}}),
						cta("Coming?", "Registering takes a minute.", "Register", "/register"),
					},
				}},
				{name: "programme", label: "Programme", body: obj{
					"title": "Programme",
					"hero":  plainHero(mark("the date and the place, in a few words")),
					"sections": []any{
						sec("table", obj{"title": "The day", "caption": "Times and what happens",
							"columns": []any{"Time", "What"}, "rows": []any{
								row(mark("when it starts"), mark("what happens first")),
								row(mark("a later time"), mark("what happens after that")),
							}}),
					},
				}},
				{name: "register", label: "Register", body: obj{
					"title": "Register",
					"hero":  plainHero("Tell us you are coming."),
					"form":  "register",
				}},
			}
		},
	},
}

// siteForms are the forms a kind of site has besides the contact form.
func siteForms(kind string) []form.Form {
	switch kind {
	case "community":
		return []form.Form{{
			Name: "volunteer", Label: "Get involved",
			Fields: []form.Field{
				{Name: "name", Label: "Your name", Kind: form.Line, Required: true},
				{Name: "email", Label: "Your email address", Kind: form.Email, Required: true},
				{Name: "how", Label: "How would you like to help?", Kind: form.Para},
			},
			Notice:  "We use what you send only to get in touch about helping.",
			Purpose: "to get in touch with you about helping", Basis: "legitimate-interests", RetentionDays: 365,
		}}
	case "event":
		return []form.Form{{
			Name: "register", Label: "Register",
			Fields: []form.Field{
				{Name: "name", Label: "Your name", Kind: form.Line, Required: true},
				{Name: "email", Label: "Your email address", Kind: form.Email, Required: true},
				{Name: "notes", Label: "Anything we should know?", Kind: form.Para,
					Help: "Leave out anything you would rather not tell us."},
			},
			Notice:  "We use what you send only to organise the event and tell you about it.",
			Purpose: "to organise the event and keep you informed about it", Basis: "contract", RetentionDays: 180,
		}}
	}
	return nil
}

// contactForm is the form every built site has.
func contactForm() form.Form {
	return form.Form{
		Name: "contact", Label: "Send a message",
		Fields: []form.Field{
			{Name: "name", Label: "Your name", Kind: form.Line, Required: true},
			{Name: "email", Label: "Your email address", Kind: form.Email, Required: true, Help: "So we can reply."},
			{Name: "message", Label: "Your message", Kind: form.Para, Required: true},
		},
		Notice:  "We use what you send only to reply to you.",
		Purpose: "to reply to your message", Basis: "legitimate-interests", RetentionDays: 365,
	}
}

// helpBot is the question box every built site has. It answers from the
// published pages only, without a model, so nothing a visitor asks leaves
// the site; the privacy page says so, and an owner who turns a model on
// later decides what to tell visitors about it.
//
// It declares no actions. Only a model offers one (see internal/assistant,
// WhyNoOffers), so a contact action here was a row on the Chatbots screen
// no visitor was ever shown. Turning the model on whenever a route exists
// would make it fire, and would break the privacy page's promise on the day
// somebody adds a route for something else, without anybody deciding to: a
// package is the same file on every installation, and whether this one has
// a model is not something it can know. So the refusal points at the
// contact page instead, which works without one, and an owner who turns a
// model on adds the action with it, on purpose.
func helpBot(name string, suggestions []string) assistant.Assistant {
	if len(suggestions) > assistant.MaxSuggestions {
		suggestions = suggestions[:assistant.MaxSuggestions]
	}
	return assistant.Assistant{
		Name: "help", Title: "Ask " + name,
		Greeting: "Ask a question. The answer comes from this site's own pages.",
		Refusal:  "This site does not say. The contact page is the way to ask a person.",
		Public:   true,
		Launcher: &assistant.Launcher{Style: "pill", Label: "Ask", Suggestions: suggestions},
	}
}

// QuestionBox is the question box a built or imported site has: answering
// from the site's own pages, sending nothing anywhere, and pointing at the
// contact page when there is one.
func QuestionBox(siteName string, suggestions []string, contact bool) assistant.Assistant {
	a := helpBot(siteName, suggestions)
	if !contact {
		a.Refusal = "This site does not say."
	}
	return a
}

// BuildSite writes a site package from a brief, without a model.
func BuildSite(b SiteBrief, by string, now time.Time) (*Package, error) {
	b.Description = strings.TrimSpace(b.Description)
	b.Name = strings.TrimSpace(b.Name)
	if len(b.Description) > MaxBrief {
		return nil, fmt.Errorf("a description is at most %d characters", MaxBrief)
	}
	if b.Name == "" {
		return nil, fmt.Errorf("give the site a name: without a model, nothing can suggest one")
	}
	kind, ok := SiteKindNamed(b.Kind)
	if b.Kind == "" {
		kind, ok = GuessSiteKind(b.Description), true
	}
	if !ok {
		return nil, fmt.Errorf("there is no kind of site called %q; one of %s", b.Kind, strings.Join(siteKindNames(), ", "))
	}
	s := &Site{Name: b.Name, Starter: "sections", Style: kind.Style, Colour: kind.Colour}
	if b.Style != "" {
		s.Style = b.Style
	}
	if b.Colour != "" {
		s.Colour = b.Colour
	}
	p := &Package{
		Format: Format, Name: PackageName(b.Name), Version: "1.0.0", Title: clip(b.Name, 120),
		Purpose: clip("The whole website of "+b.Name+": its pages, menus, forms, question box and look.", 600),
		Made:    &Made{By: by, From: clip(b.Description, 600), At: now.UTC()},
		Site:    s,
	}
	main := menu.Menu{Name: "main", Label: "Main"}
	order := 0
	add := func(sp sitePage) {
		p.Pages = append(p.Pages, Page{Name: sp.name, Body: sp.body})
		if sp.label != "" {
			order += 10
			main.Items = append(main.Items, menu.Item{ID: sp.name, Label: sp.label, Kind: menu.Page, Target: sp.name, Order: order})
		}
	}
	for _, sp := range kind.pages(b.Name) {
		add(sp)
	}
	if !hasPage(p, "about") {
		add(sitePage{name: "about", label: "About", body: obj{
			"title": "About",
			"hero":  plainHero(mark("who you are, in a sentence")),
			"sections": []any{
				sec("prose", obj{"title": "Our story", "paragraphs": []any{
					mark("how it started"), mark("what you care about, and why"),
				}}),
			},
		}})
	}
	add(sitePage{name: "contact", label: "Contact", body: obj{
		"title": "Contact",
		"hero":  plainHero("Send a message, or ask a question and get an answer straight away."),
		"form":  "contact",
		"sections": []any{
			sec("ask", obj{"title": "Ask a question", "assistant": "help", "label": "Your question", "button": "Ask"}),
		},
	}})
	p.Menus = []menu.Menu{main}
	p.Forms = append([]form.Form{contactForm()}, siteForms(kind.Name)...)
	p.Chatbots = []assistant.Assistant{helpBot(b.Name, faqQuestions(p))}
	finishSite(p)
	return p, nil
}

func siteKindNames() []string {
	var out []string
	for _, k := range siteKinds {
		out = append(out, k.Name)
	}
	return out
}

func hasPage(p *Package, name string) bool {
	for _, pg := range p.Pages {
		if pg.Name == name {
			return true
		}
	}
	return false
}

// PackageName is a package name from a site's name: harts-bakery from
// Hart's Bakery, or site when nothing usable is left.
func PackageName(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r == '\'' || r == '’':
			continue
		case r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)):
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 58 {
		out = strings.Trim(out[:58], "-")
	}
	if out == "" || !unicode.IsLetter(rune(out[0])) {
		out = "site-" + out
	}
	out = strings.Trim(out, "-")
	if !reName.MatchString(out) {
		return "site"
	}
	return out
}

// faqQuestions are the questions a site's pages already answer, for the
// question box to offer before anybody asks.
func faqQuestions(p *Package) []string {
	var out []string
	for _, pg := range p.Pages {
		secs, _ := pg.Body["sections"].([]any)
		for _, s := range secs {
			m, _ := s.(map[string]any)
			f, _ := m["faq"].(map[string]any)
			items, _ := f["items"].([]any)
			for _, it := range items {
				q, _ := it.(map[string]any)["q"].(string)
				if q = strings.TrimSpace(q); q != "" && len(section.Unfilled(q)) == 0 &&
					len([]rune(q)) <= assistant.MaxSuggestionLen && len(out) < assistant.MaxSuggestions {
					out = append(out, q)
				}
			}
		}
	}
	return out
}

// finishSite writes what a built site always has and nobody drafts: the
// privacy page, from what the package collects, and the footer menu.
func finishSite(p *Package) {
	body := privacyPage(p)
	kept := p.Pages[:0]
	for _, pg := range p.Pages {
		if pg.Name != "privacy" {
			kept = append(kept, pg)
		}
	}
	p.Pages = append(kept, Page{Name: "privacy", Body: body})

	foot := menu.Menu{Name: "foot", Label: "Footer", Items: []menu.Item{
		{ID: "contact", Label: "Contact", Kind: menu.Page, Target: "contact", Order: 10},
		{ID: "privacy", Label: "Privacy", Kind: menu.Page, Target: "privacy", Order: 20},
	}}
	menus := p.Menus[:0]
	for _, m := range p.Menus {
		if m.Name != "foot" {
			menus = append(menus, m)
		}
	}
	p.Menus = append(menus, foot)
}

// privacyPage says what the site collects, from the package itself: so it
// is true of the site, whoever wrote the rest.
func privacyPage(p *Package) obj {
	where := map[string]string{}
	for _, pg := range p.Pages {
		if f, _ := pg.Body["form"].(string); f != "" {
			title, _ := pg.Body["title"].(string)
			if title == "" {
				title = pg.Name
			}
			where[f] = title
		}
	}
	paras := []any{
		"The site is run by " + mark("the name of the person or organisation that runs this site") +
			". To ask about your data, use the contact form.",
	}
	for _, f := range p.Forms {
		var asks []string
		for _, fl := range f.Fields {
			asks = append(asks, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fl.Label), "?")))
		}
		label := f.Label
		if label == "" {
			label = f.Name
		}
		on := ""
		if page, ok := where[f.Name]; ok {
			on = " on the " + page + " page"
		}
		paras = append(paras, fmt.Sprintf("The %s form%s asks for %s. %s", label, on, joinAnd(asks), f.Told()))
	}
	for _, a := range p.Chatbots {
		if a.Public {
			paras = append(paras, "The question box answers from this site's own pages. What you ask it is not "+
				"stored, and is not sent anywhere else.")
		}
	}
	paras = append(paras,
		"Reading this site sets no cookies. Visits are counted on the server as daily totals for each page, "+
			"and nothing that identifies you is kept.",
		"You can ask what we hold about you, and ask us to correct or delete it. You can also complain to "+
			mark("your data protection authority, such as the ICO in the UK")+".")
	return obj{
		"title":    "Privacy",
		"hero":     plainHero("What this site collects about you, why, and for how long."),
		"sections": []any{sec("prose", obj{"title": "", "paragraphs": paras})},
	}
}

func joinAnd(xs []string) string {
	switch len(xs) {
	case 0:
		return "nothing"
	case 1:
		return xs[0]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
}

// SitePrompt is the system prompt for drafting a site: what a site package
// holds, the rule about facts, and every section kind with its shape.
func SitePrompt(kinds []section.Kind) string {
	var b strings.Builder
	b.WriteString(`You write websites for Quilzo, a content platform. You are given a brief and a starting site, as one JSON package. Answer with the whole package rewritten for the brief, as one JSON object and nothing else.

Rules:
- Keep these keys and add no others: format, name, version, title, purpose, site, forms, pages, menus, chatbots.
- Write the words for this brief: headings, leads, cards, steps, questions and answers. Plain, warm and specific, in the language of the brief. No hype, no lorem ipsum.
- Never make up a fact. A price, an address, a phone number, an email address, opening hours, a date, a person's name, a quote, a review, a figure, a client, an award: when the brief does not give it, write [[what goes here]] instead, such as [[your opening hours]]. The owner fills these in, and the site cannot be published until they do. Use the same words for the same blank everywhere.
- site: name is what the site is called; keep it if the brief names the site. description is one sentence for search results. style is one of ` + strings.Join(theme.Styles, ", ") + `; colour is the main colour as #rrggbb; motion is one of ` + strings.Join(theme.Motions, ", ") + `.
- pages: [{name, body}]. Keep the pages index, contact and privacy. You may add, remove and rename the others; at most ` + fmt.Sprint(maxSitePages) + ` pages. A page name is lower-case words joined by hyphens. A body has a title, a hero {eyebrow, lead, cta_label, cta_href, secondary_label, secondary_href} and sections. A section is an object with one key, its kind. A link to a page of the site is "/" and the page name, or "/" for index; link to nothing else.
- A page shows one of the site's forms with "form": "FORM". The privacy page is written for you from the forms; leave it as it is.
- forms: you may reword the contact form and add fields or forms the brief needs, at most ` + fmt.Sprint(maxSiteForms) + `. Field kinds: line, para, email, number, choice (with choices), agree. Each form has a notice, a purpose and a basis (consent, contract, legitimate-interests); consent needs a required agree field. Ask only for what the form is for.
- menus: main lists the pages a visitor needs, in order; foot is written for you. Every entry is {id, label, kind: "page", target: PAGE, order}.
- chatbots: keep the one chatbot, called help; you may reword its title, greeting and suggestions.
- Never add agents, webhooks, URLs to other sites, scripts, HTML, styles or secrets.

Section kinds, each with an example of its shape:
`)
	for _, k := range kinds {
		stub, err := json.Marshal(k.Stub)
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "- %s: %s %s\n", k.Name, k.Summary, stub)
	}
	return b.String()
}

// SiteRequest is the user turn for drafting a site: the brief, what the
// person chose, and the start to rewrite.
func SiteRequest(b SiteBrief, start *Package) (string, error) {
	body, err := json.MarshalIndent(start, "", " ")
	if err != nil {
		return "", err
	}
	var r strings.Builder
	r.WriteString("Brief: " + strings.TrimSpace(b.Description) + "\n")
	if b.Name != "" {
		r.WriteString("The site is called: " + b.Name + "\n")
	}
	r.WriteString("\nStarting site:\n")
	r.Write(body)
	return r.String(), nil
}

// ReadSiteDraft reads a model's site into a package and puts right what it
// can against the start it was given, saying what it changed.
func ReadSiteDraft(answer string, b SiteBrief, start *Package, by, model string, now time.Time) (*Package, []string, error) {
	kinds := map[string]bool{}
	for _, k := range section.Kinds() {
		kinds[k.Name] = true
	}
	p, notes, err := readDraft(answer, kinds, by, b.Description, model, now, true)
	if err != nil {
		return nil, notes, err
	}
	return p, append(notes, RepairSite(p, b, start)...), nil
}

// RepairSite puts a drafted site right where it can, against the start it
// was drafted from: what the person chose wins, what every built site has
// is put back, and what cannot work is taken out. It returns what it did.
func RepairSite(p *Package, b SiteBrief, start *Package) []string {
	var notes []string
	note := func(format string, a ...any) { notes = append(notes, fmt.Sprintf(format, a...)) }

	// The package itself.
	p.Format, p.Version = Format, "1.0.0"
	p.Types, p.Collections, p.Listings, p.Agents, p.Webhooks, p.Roles = nil, nil, nil, nil, nil, nil
	if p.Site == nil {
		s := *start.Site
		p.Site = &s
	}
	s := p.Site
	if n := strings.TrimSpace(b.Name); n != "" {
		s.Name = n
	}
	if strings.TrimSpace(s.Name) == "" || len([]rune(s.Name)) > MaxSiteName || !printable(s.Name) {
		s.Name = start.Site.Name
	}
	if s.Name == "" {
		s.Name = strings.TrimSpace(p.Title)
	}
	if s.Name == "" {
		s.Name = "My site"
	}
	s.Name = strings.TrimSpace(s.Name)
	s.Description = strings.TrimSpace(s.Description)
	if len([]rune(s.Description)) > MaxSiteDescription || !printable(s.Description) || len(section.Unfilled(s.Description)) > 0 {
		s.Description = ""
	}
	s.Starter, s.Tokens = "sections", nil
	if b.Style != "" {
		s.Style = b.Style
	}
	if b.Colour != "" {
		s.Colour = b.Colour
	}
	if !contains(theme.Styles, s.Style) {
		s.Style = start.Site.Style
	}
	if s.Motion != "" && !contains(theme.Motions, s.Motion) {
		s.Motion = ""
	}
	if siteRefused(s) {
		note("site: the look the model chose is hard to read, so the site keeps %s", start.Site.Colour)
		s.Colour, s.Style = start.Site.Colour, start.Site.Style
	}
	if !reName.MatchString(p.Name) {
		p.Name = PackageName(s.Name)
	}
	if t := strings.TrimSpace(p.Title); t == "" || len(t) > 120 {
		p.Title = clip(s.Name, 120)
	}
	if t := strings.TrimSpace(p.Purpose); t == "" || len(t) > 600 {
		p.Purpose = start.Purpose
	}

	// Forms: the ones that pass, and the contact form whatever happened.
	var forms []form.Form
	seenForm := map[string]bool{}
	for _, f := range p.Forms {
		if seenForm[f.Name] || len(forms) >= maxSiteForms {
			continue
		}
		if err := f.Validate(); err != nil {
			note("form %s: left out, because %v", f.Name, err)
			continue
		}
		seenForm[f.Name] = true
		forms = append(forms, f)
	}
	if !seenForm["contact"] {
		forms = append([]form.Form{contactForm()}, forms...)
		seenForm["contact"] = true
	}
	p.Forms = forms

	// The question box: answering from the site's pages, with nothing sent
	// anywhere, as the privacy page says.
	var bot *assistant.Assistant
	for i := range p.Chatbots {
		if p.Chatbots[i].Name == "help" {
			bot = &p.Chatbots[i]
		}
	}
	if bot == nil {
		bot = &start.Chatbots[0]
	}
	help := *bot
	def := helpBot(s.Name, nil)
	help.Public, help.UseModel, help.Handoff, help.Static, help.Embed, help.Documents = true, false, false, false, nil, nil
	help.Pages, help.Exclude, help.KeepInstructions = nil, nil, false
	// Nothing the model wrote decides what the question box offers to do:
	// it answers without a model, and so offers what helpBot does, nothing.
	help.Actions = def.Actions
	if help.Launcher == nil {
		help.Launcher = def.Launcher
	}
	if strings.TrimSpace(help.Title) == "" {
		help.Title = def.Title
	}
	if err := help.Validate(); err != nil {
		note("chatbot help: put back as it was, because %v", err)
		help = start.Chatbots[0]
		help.Title = def.Title
	}
	p.Chatbots = []assistant.Assistant{help}

	// Pages: usable names, the ones every site has, and sections that work.
	byName := map[string]Page{}
	var pages []Page
	for _, pg := range p.Pages {
		switch {
		case !rePage.MatchString(pg.Name) || strings.Contains(pg.Name, "/") || len(pg.Name) > 64:
			note("page %q: left out, because that is not a usable page name", pg.Name)
			continue
		case byName[pg.Name].Body != nil || pg.Body == nil || pg.Name == "privacy":
			continue
		case len(pages) >= maxSitePages-1:
			note("page %s: left out, because a built site has at most %d pages", pg.Name, maxSitePages)
			continue
		}
		byName[pg.Name] = pg
		pages = append(pages, pg)
	}
	for _, must := range []string{"index", "contact"} {
		if _, ok := byName[must]; !ok {
			for _, pg := range start.Pages {
				if pg.Name == must {
					note("page %s: put back, because every site has one", must)
					byName[must] = pg
					pages = append(pages, pg)
				}
			}
		}
	}
	exists := func(name string) bool { _, ok := byName[name]; return ok || name == "privacy" }
	for i := range pages {
		pages[i].Body = repairPage(pages[i], exists, seenForm, note)
	}
	p.Pages = pages

	// Menus: the main menu points at pages there are; the footer is written.
	var main menu.Menu
	for _, m := range p.Menus {
		if m.Name == "main" {
			main = m
		}
	}
	main.Name, main.Label = "main", "Main"
	seenItem := map[string]bool{}
	var items []menu.Item
	for i, it := range main.Items {
		if it.Kind != menu.Page || !exists(it.Target) || it.Parent != "" {
			if it.Label != "" {
				note("menu main: left out %q, which does not point at a page of the site", it.Label)
			}
			continue
		}
		if seenItem[it.Target] {
			continue
		}
		seenItem[it.Target] = true
		it.ID, it.Order, it.Note = it.Target, (i+1)*10, ""
		if l := strings.TrimSpace(it.Label); l == "" || len(l) > menu.MaxLabel {
			it.Label = it.Target
		}
		items = append(items, it)
	}
	if len(items) == 0 {
		for _, m := range start.Menus {
			if m.Name == "main" {
				for _, it := range m.Items {
					if exists(it.Target) {
						items = append(items, it)
					}
				}
			}
		}
	}
	main.Items = items
	p.Menus = []menu.Menu{main}

	finishSite(p)
	return notes
}

// repairPage keeps what a built page can render: sections of kinds this
// program has, forms and chatbots the site declares, and links that go to
// its own pages.
func repairPage(pg Page, exists func(string) bool, forms map[string]bool, note func(string, ...any)) map[string]any {
	body := pg.Body
	for _, k := range []string{"layout", "members_only", "expires", "publish_at"} {
		if _, ok := body[k]; ok {
			delete(body, k)
			note("page %s: left out %q, which a built site does not set", pg.Name, k)
		}
	}
	if f, ok := body["form"].(string); ok && !forms[f] {
		delete(body, "form")
		note("page %s: left out the form %q, which the site does not have", pg.Name, f)
	}
	if secs, ok := body["sections"].([]any); ok {
		var kept []any
		for _, s := range secs {
			m, _ := s.(map[string]any)
			if len(m) != 1 {
				continue
			}
			for kind, inner := range m {
				fields, _ := inner.(map[string]any)
				switch {
				case fields == nil:
					continue
				case kind == "listing" || kind == "comments":
					note("page %s: left out a %s section, which needs records a built site does not have yet", pg.Name, kind)
					continue
				case kind == "ask":
					fields["assistant"] = "help"
				}
				if bad, _ := section.Validate(obj{"sections": []any{s}}); len(bad) > 0 {
					note("page %s: left out a %s section: %s", pg.Name, kind, bad[0].Detail)
					continue
				}
				kept = append(kept, s)
			}
		}
		if len(kept) > section.MaxSections {
			kept = kept[:section.MaxSections]
		}
		body["sections"] = kept
	}
	links(body, func(key, href string) string {
		switch {
		case href == "" || href == "/" || strings.HasPrefix(href, "#"):
			return href
		case strings.HasPrefix(href, "/") && !strings.HasPrefix(href, "//") && exists(strings.Trim(strings.SplitN(href[1:], "#", 2)[0], "/")):
			return href
		}
		note("page %s: left out the link %s, which goes nowhere on this site", pg.Name, href)
		return ""
	})
	return body
}

// links walks every link on a page, a field whose name ends in href, and
// sets it to what fix returns.
func links(v any, fix func(key, href string) string) {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if s, ok := e.(string); ok && strings.HasSuffix(k, "href") {
				t[k] = fix(k, s)
				continue
			}
			links(e, fix)
		}
	case []any:
		for _, e := range t {
			links(e, fix)
		}
	}
}

// siteRefused is whether a site block's look would be refused.
func siteRefused(s *Site) bool { return len(s.lookRefused()) > 0 }

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Blanks lists what a package's pages still need filled in, by page, in
// page order.
func (p *Package) Blanks() map[string][]section.Blank {
	out := map[string][]section.Blank{}
	for _, pg := range p.Pages {
		if b := section.Unfilled(pg.Body); len(b) > 0 {
			out[pg.Name] = b
		}
	}
	return out
}

// BlankWhats is every distinct thing still to fill in across a package's
// pages, in the order its pages are read.
func (p *Package) BlankWhats() []string {
	seen := map[string]bool{}
	var out []string
	for _, pg := range p.Pages {
		for _, b := range section.Unfilled(pg.Body) {
			if !seen[b.What] {
				seen[b.What] = true
				out = append(out, b.What)
			}
		}
	}
	return out
}
