package admin

// The manual, the chapters about making things.

var chapterContent = chapter{
	Name: "Making things",
	Sections: []section{
		{
			ID:      "pages",
			Title:   "Pages",
			Summary: "The list of everything in the draft, what differs from live, and the editor.",
			Body: []block{
				p("A page is a set of named fields. It is not a file, not a row " +
					"and not a document with a body — the shape is entirely up " +
					"to the content type it is bound to, and a page with no type " +
					"may hold anything."),
				sub("The editor"),
				p("A bound page gets a form built from its type: the right " +
					"control for each field, the labels its author wrote, the " +
					"help text they wrote, and every declared field shown even " +
					"when empty. An unbound page gets a plain form over the keys " +
					"it happens to have, which is all that is possible when " +
					"nothing has said what it should have."),
				p("Anything on the page the type does not declare is shown last " +
					"and marked. Hiding it would leave a value the type rejects " +
					"sitting invisibly in the page, blocking every save with an " +
					"error about a field the editor never displayed."),
				sub("Two people, one page"),
				p("Opening a page claims it, and the claim is advisory: it never " +
					"stops a write, it expires on its own, and it is shown so " +
					"two people can talk before one of them loses an afternoon. " +
					"What actually prevents a lost edit is compare-and-swap — " +
					"the form remembers the commit it was rendered from, and a " +
					"save against a draft that has moved is refused with what " +
					"changed rather than silently overwriting it."),
				p("Who is holding what is listed on the Publishing screen."),
				sub("Preview"),
				p("Preview serves the real page to your real browser rather than " +
					"drawing an approximation in a panel. A preview panel is a " +
					"second renderer, and a second renderer can disagree with " +
					"the one readers get."),
			},
		},
		{
			ID:      "types",
			Title:   "Content types",
			Summary: "What a page is allowed to contain, and why this is not JSON Schema.",
			Body: []block{
				p("A type is a flat list of fields. Each field has a kind, and " +
					"may be required, bounded in length, bounded in value, or " +
					"limited to a fixed set of choices."),
				table([]string{"Kind", "Holds"},
					[]string{"text", "one line"},
					[]string{"longtext", "a body of prose"},
					[]string{"number", "a number, optionally bounded"},
					[]string{"boolean", "true or false"},
					[]string{"date", "YYYY-MM-DD"},
					[]string{"url", "http or https only"},
					[]string{"email", "an address"},
					[]string{"slug", "a url-safe identifier"},
					[]string{"choice", "one of a fixed list"},
					[]string{"list", "several short strings"},
				),
				sub("Why not JSON Schema"),
				p("Because a CMS whose users define content types is accepting " +
					"schemas from the people using it, and the three most " +
					"powerful keywords in JSON Schema are where its published " +
					"vulnerabilities live: a pattern reaching a backtracking " +
					"engine is a denial of service in one request, a $ref to an " +
					"http URL is a server-side request forgery, and a " +
					"self-referencing $ref with no cycle detection spins a " +
					"worker until it is killed."),
				p("So there is no regular expression, no reference of any kind, " +
					"no recursion and no combinators. What you give up is " +
					"\"matches this pattern\", which is the feature carrying the " +
					"vulnerability, and a content field that needs an arbitrary " +
					"pattern is usually modelling something that belongs in code."),
				sub("Binding, and what happens when it fails"),
				p("Binding a page to a type means every write to that page has " +
					"to satisfy it. The screen tells you immediately whether it " +
					"currently does, because a rule whose effect is felt at the " +
					"next write is a rule somebody discovers at the worst moment."),
				p("A refused save answers 422, not 400: the request was well " +
					"formed and you were allowed to make it — the content simply " +
					"does not match the shape this site declared."),
				warn("Deleting a type that pages are bound to is refused. " +
					"Validation fails closed on a binding pointing at nothing, " +
					"so deleting one in use would break every page under it with " +
					"an error about the configuration rather than the content."),
			},
		},
		{
			ID:      "data",
			Title:   "Data and records",
			Summary: "Collections of records, for holding an application's data rather than a site's pages.",
			Body: []block{
				p("A record is a row. Records live in collections, share the " +
					"store with pages, and are what makes this able to hold an " +
					"application rather than a brochure — a device inventory, a " +
					"control register, a product catalogue."),
				sub("Identifiers"),
				p("The identifier is assigned by the store and never taken from " +
					"the fields. An identifier that lives in the data is an " +
					"identifier somebody can edit, and once it can be edited it " +
					"is a claim about the record rather than the address of it."),
				sub("Querying"),
				p("A query is a set of exact matches, substring matches, a time " +
					"bound, a sort and a page. Never an expression — the moment " +
					"a query carries an expression it needs an evaluator, and an " +
					"evaluator over user-supplied input in a data store is the " +
					"shape of every injection vulnerability there has ever been."),
				note("A listing is a scan with a filter, not an index. That is " +
					"fine for the collections one node holds and it is said " +
					"plainly rather than hidden behind a name like Query, " +
					"because knowing it is a scan is what stops somebody " +
					"building a page that runs twenty of them."),
			},
		},
		{
			ID:      "structure",
			Title:   "Classification and navigation",
			Summary: "Vocabularies that stay controlled, and menus that cannot point at nothing.",
			Body: []block{
				p("Two features every CMS has, and the two places the big ones " +
					"reliably rot. They share a screen because they share a " +
					"failure: both are structure that refers to content, and " +
					"content can be deleted."),
				sub("Why vocabularies are closed by default"),
				p("Free-text tags do not stay a small list. The documented " +
					"outcomes are an organisation with over two thousand tags, " +
					"and another with fourteen hundred entries in one dropdown, " +
					"most of them duplicates. \"Marketing\", \"marketing\" " +
					"and \"mktg\" become three unrelated categories, a filter " +
					"on any one returns a third of the content, and nobody can " +
					"tell a gap from a spelling."),
				p("That is not a discipline problem. It is what happens when " +
					"inventing a permanent category costs one keystroke and " +
					"somebody else pays for the fragmentation later. So a " +
					"vocabulary here is closed: terms are declared, and only " +
					"declared terms apply. Opening one is possible and is a " +
					"decision about that vocabulary."),
				list(
					"Spellings go in as synonyms and resolve to the real term, so the variants stop existing rather than accumulating.",
					"Terms nest, so filtering by a parent finds everything under it without anybody maintaining a list.",
					"A term in use cannot be deleted — the refusal names what carries it.",
					"Every term has a description, which is the field that decides whether two people tag alike.",
				),
				sub("Why menus cannot point at nothing"),
				p("Drupal's issue queue carries this as an open problem: menu " +
					"links keep the reference to a deleted target, and at least " +
					"five contributed modules exist to patch around it. " +
					"WordPress is quieter and no better — delete a page and the " +
					"menu entry stays, silently linking to a 404."),
				p("It happens everywhere because the menu is stored in one place " +
					"and the pages in another, so nothing owns the question " +
					"\"is this still true\". Here it is asked three times:"),
				steps(
					"When an entry is saved, an internal target that does not exist is refused.",
					"When a menu is read, every entry carries whether it resolves, so a broken one is shown rather than rendered.",
					"When a site is published, an entry pointing at a page that is not going live refuses the publication.",
				),
				p("That third one catches the version nobody checks for: an " +
					"entry pointing at a page that exists in the draft and is " +
					"not live yet. The link works for the person who made it " +
					"and 404s for every reader, which is the worst place to " +
					"find out. It is the same kind of refusal as an " +
					"inaccessible page, with the same recorded override."),
				sub("External links"),
				p("Checked for shape and never fetched. Making requests from a " +
					"publish gate would turn this into a scanner of somebody " +
					"else's infrastructure. Only http and https are accepted: " +
					"a menu entry becomes a link in a page a reader clicks, so " +
					"a javascript: or data: target is script execution with a " +
					"friendly label on it."),
				sub("Renaming a page"),
				p("Retargeting rewrites every entry that named the old page. " +
					"Without it, a rename means finding every menu by hand — " +
					"which is the manual step that does not happen, and is how " +
					"the dangling entry gets there."),
			},
		},
		{
			ID:      "media",
			Title:   "Media",
			Summary: "Images and files: what is accepted, what happens to them, and why an SVG is not.",
			Body: []block{
				p("Every upload is decoded rather than sniffed. Magic bytes are " +
					"bypassable with a polyglot, so a file has to actually parse " +
					"as what it claims to be before it is stored, and each " +
					"format has its own size cap — a two-hundred-megabyte PNG is " +
					"not a photograph, it is a decompression bomb with a header."),
				sub("What happens to an image"),
				list(
					"It is decoded, to prove it is an image.",
					"It is resized to the configured bounds, if it is larger.",
					"It is re-encoded, which strips metadata — a photograph from a phone usually carries GPS coordinates.",
					"It is re-accepted, so the stored name is the hash of what is actually stored rather than of what arrived.",
				),
				sub("Descriptions are required"),
				p("An image needs a description at the point it enters, not in " +
					"an audit afterwards. A library full of undescribed images " +
					"is a library somebody has to go back through, and nobody " +
					"ever does. Marking something decorative is possible and is " +
					"a claim somebody makes rather than a box they skip."),
				sub("Why SVG is refused"),
				p("An SVG is XML that browsers execute. Script elements, event " +
					"handlers, external references and entity expansion all " +
					"work inside one, and ImageTragick was the server-side half " +
					"of the same problem. Export it as PNG or WebP."),
				sub("Using one"),
				p("The media screen shows the published path beside each file. " +
					"Put that path in a page field. The name is the hash of the " +
					"bytes, so the same photograph uploaded twice is stored " +
					"once, a change is a different address, and these can be " +
					"cached forever with nothing to purge."),
			},
		},
		{
			ID:      "templates",
			Title:   "Templates",
			Summary: "The language that renders a page, and the four things it cannot do.",
			Body: []block{
				p("A template is HTML with holes in it. The language has " +
					"substitution, conditionals, loops and filters, and that is " +
					"the entire list."),
				code("<h1>{{ page.title }}</h1>\n" +
					"{{ if page.subtitle }}<p>{{ page.subtitle }}</p>{{ end }}\n" +
					"{{ for tag in page.tags }}<span>{{ tag }}</span>{{ end }}\n" +
					"<time>{{ page.published | date }}</time>"),
				sub("What it cannot do, and why that is the feature"),
				list(
					"No method calls. Every server-side template engine with a serious history of remote code execution got there through method access on objects reachable from the context.",
					"No arbitrary attribute traversal. There is no way to walk from a page to the object graph behind it.",
					"No includes from a path. A template cannot be made to read a file whose name came from content.",
					"No evaluation. There is no eval, no exec, and nothing that compiles a string at render time.",
				),
				p("Filters are the extension point, and they are a closed set " +
					"implemented in Go. That is the alternative to a scripting " +
					"language: a fixed vocabulary of transformations rather than " +
					"a general-purpose interpreter that has to be sandboxed."),
				sub("Why there is no template editor here"),
				p("A template decides what every page renders as. Letting the " +
					"web interface write one would mean an editing session " +
					"could change the markup of the whole site — which is not " +
					"code execution, because the language cannot execute, but " +
					"is close enough to it that the blast radius stops matching " +
					"the permission. Templates are files an operator deploys, " +
					"and `scrivet audit` checks them before they go."),
				sub("Escaping"),
				p("Output is escaped by context — inside an attribute, inside a " +
					"URL, inside text — and there is no way to turn it off. A " +
					"raw filter is the single most common source of stored " +
					"cross-site scripting in every CMS that has one, so this " +
					"does not have one."),
			},
		},
		{
			ID:      "languages",
			Title:   "Languages",
			Summary: "Locales, translation state, and the failure that reads perfectly.",
			Body: []block{
				p("The default language keeps the page names it has. Every other " +
					"language lives under its own prefix, so adding a second one " +
					"moves nothing."),
				sub("Stale is the interesting state"),
				p("A translation records the exact version of the source it was " +
					"made from. When that source changes, the translation " +
					"becomes stale — and a stale translation is the failure " +
					"worth naming, because it reads perfectly and says something " +
					"the original no longer says."),
				p("A translation with no record is untracked, and the honest " +
					"answer for it is that nothing can be said about whether it " +
					"is current. That is a different state from stale and is " +
					"shown as one."),
				sub("Negotiation"),
				p("The public site honours Accept-Language as RFC 9110 " +
					"specifies, including the part most implementations miss: a " +
					"quality of zero means refused, not unranked."),
			},
		},
		{
			ID:      "ai",
			Title:   "The assistant, and AI content",
			Summary: "Describing a site to a model, and the mark the law requires on the result.",
			Body: []block{
				p("The assistant takes a description and returns a proposal. " +
					"Nothing is written until somebody accepts it — and that is " +
					"not a courtesy, it is the same rule everything else here " +
					"follows: a model's output is untrusted input, and untrusted " +
					"input does not get stored without passing the gates."),
				sub("Which model"),
				p("Any OpenAI-compatible endpoint: a self-hosted server, a " +
					"gateway, a hosted provider. Which one is a decision about " +
					"where this site's content is allowed to go, so it is " +
					"configuration rather than a default, set with " +
					"SCRIVET_MODEL_URL and SCRIVET_MODEL_KEY. No model configured " +
					"is a complete configuration and the screen says so."),
				sub("The mark"),
				p("Accepted pages are recorded as model-generated. EU AI Act " +
					"Article 50 requires AI-generated content to carry a " +
					"machine-readable mark, and publishing refuses unmarked " +
					"pages — because \"unrecorded\" is not the same as " +
					"\"human-written\", and treating it as such is how the " +
					"obligation quietly stops being met."),
				p("The mark travels in the page: meta tags and a JSON-LD block " +
					"in the head of every served page, not only a row in a file " +
					"on the server. A machine-readable marking has to be in the " +
					"thing a machine reads."),
				sub("Agents that write"),
				p("Anything writing over the machine interface is marked the " +
					"same way, without being asked. An agent is a model, and the " +
					"one interface built for agents is the one that would " +
					"otherwise forget."),
			},
		},
	},
}
