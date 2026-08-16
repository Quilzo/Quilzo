package admin

// The manual, chapter one: what this is and how to stand it up.
//
// Split across several files because it is long, and long is the point — the
// complaint that produced it was that features existed and nobody could find
// them. Each file is one chapter, and the chapters are assembled in
// docs_manual.go so the order is visible in one place.

var chapterStart = chapter{
	Name: "Getting started",
	Sections: []section{
		{
			ID:      "start",
			Title:   "What Lithoform is",
			Summary: "A content management system whose defining property is that nothing in it executes.",
			Body: []block{
				p("Lithoform manages content and publishes it. That much it shares " +
					"with every other CMS. What it does differently is refuse to " +
					"execute anything: there is no plugin runtime in the server, " +
					"no scripting language in the templates, no expression " +
					"evaluator in the queries, and no JavaScript in the interface " +
					"you are reading this in."),
				p("That is not asceticism. Every one of those is a place where " +
					"CMS vulnerabilities actually come from, and removing a " +
					"capability removes the whole class rather than the " +
					"currently-known instances of it. A template language with " +
					"no method calls cannot be made to call a method. A schema " +
					"format with no regular expressions cannot be given a " +
					"catastrophically backtracking one."),
				sub("The three ideas everything else follows from"),
				p("Content is immutable and addressed by the hash of its own " +
					"bytes. Nothing is ever overwritten; a change writes a new " +
					"object with a new name, and the old one is still there. " +
					"This is the same model git uses, and it is what makes " +
					"history free, rollback a pointer move, and \"the bytes " +
					"production serves are the bytes staging served\" an exact " +
					"statement rather than a hope."),
				p("Publishing moves a pointer. A commit is a name for a tree of " +
					"content; an environment is a pointer at a commit. " +
					"Promotion re-points, so nothing is copied, re-serialised or " +
					"rebuilt on the way to production — which means it cannot be " +
					"changed on the way either."),
				p("Every control exists on all three surfaces. The web interface, " +
					"the command line and the machine interface are three doors " +
					"into one store, and a rule enforced at one of them is not a " +
					"rule. Tests walk the source to check this, because the " +
					"project has got it wrong three times."),
				sub("What it is made of"),
				p("One static binary with no third-party dependencies at all — " +
					"not vendored, not pinned, none. The container image is " +
					"built FROM scratch and contains the binary and nothing " +
					"else: no shell, no package manager, no interpreter, no " +
					"libc. There is nothing in it to exploit and nothing in it " +
					"to patch on a Tuesday, which is a different property from " +
					"being small — it is currently about 23 MB, and most of that " +
					"is the Go runtime and this manual."),
				note("Everything in this manual is reachable from the interface " +
					"you are in. Where a section names a command, that command " +
					"does the same thing from a terminal — they are the same " +
					"code path, not two implementations that agree."),
			},
		},
		{
			ID:      "setup",
			Title:   "Setting it up, step by step",
			Summary: "From nothing to a published site with access control, in order.",
			Body: []block{
				p("Nine steps. Each one is a thing you will actually have to do, " +
					"in the order the product needs them, and each names both " +
					"the screen and the command so it works whichever you have " +
					"in front of you."),
				sub("1. Create the store"),
				p("A store is a directory. It holds the content, the history, " +
					"the access policy and the credentials, and it is the only " +
					"state this program has — back it up and you have backed up " +
					"everything."),
				code("scrivet init"),
				sub("2. Grant the first administrator"),
				p("Access is granted before any credential exists. That ordering " +
					"is deliberate: the policy names who may do what, and a " +
					"token is only ever a way to prove you are one of those " +
					"people. Issuing a credential for somebody the policy has " +
					"never heard of gets you a credential that can do nothing."),
				code("scrivet auth grant dana admin"),
				sub("3. Issue a credential"),
				p("The secret is shown once and only a hash is stored, so it " +
					"cannot be recovered — losing it means issuing another and " +
					"revoking the first, which takes ten seconds and is the " +
					"correct outcome."),
				code("scrivet token issue laptop --principal dana --role admin"),
				sub("4. Start the interface"),
				p("Loopback by default. An editing interface that binds every " +
					"network interface the moment somebody runs it is how a " +
					"development server ends up on the internet, so widening it " +
					"has to be a decision somebody typed."),
				code("scrivet serve --addr 127.0.0.1:8080"),
				shot("signin", "The sign-in screen. One field, and an "+
					"explanation of why there is no second one."),
				p("Open it, paste the token, and you are signed in. There is no " +
					"password: no password storage, no reset flow, no credential " +
					"stuffing, and no puzzle to solve — WCAG 2.2 treats those as " +
					"cognitive function tests and prohibits them."),
				sub("5. Decide what your content is"),
				p("Go to Types. A type is a flat list of fields, and binding a " +
					"page to one means every write to that page has to satisfy " +
					"it — from this interface, from the command line, from the " +
					"API and from an agent, with no way to write around it."),
				shot("types", "The Types screen, with a content type that has "+
					"six fields and the pages required to satisfy it."),
				p("Do this before writing much content. Adding a required field " +
					"to a type that fifty pages are bound to means fifty pages " +
					"that cannot be saved until somebody fills it in."),
				sub("6. Write something"),
				p("Pages is the list; clicking one opens an editor built from " +
					"its type — the right control per field, the author's own " +
					"labels, and the fields that are missing shown as empty " +
					"rather than absent. A page with no type gets a plain form " +
					"over whatever keys it happens to have."),
				shot("pages", "Pages: everything in the draft, and which of it "+
					"differs from what is live."),
				shot("editor", "The editor for a page with a type — the "+
					"declared fields, in the order the type declares them, with "+
					"the author's own labels."),
				sub("7. Look at it before anybody else does"),
				p("Review shows what differs from what is live, and runs the " +
					"accessibility checks over the rendered result. A blocking " +
					"failure stops publication unless somebody gives a reason, " +
					"and the reason is recorded."),
				shot("review", "Review: what is about to change, and what the "+
					"accessibility checks say about it."),
				sub("8. Publish"),
				p("Publishing moves the live pointer. Everything that was " +
					"checked is what goes out, and the version you moved away " +
					"from is still stored — so rolling back is another pointer " +
					"move rather than a restore from a backup."),
				shot("publishing", "Publishing: each environment, what it is "+
					"serving, and what is waiting to go out."),
				sub("9. Serve it"),
				code("scrivet site --addr 0.0.0.0:8081 --base-url https://example.org"),
				p("Two processes rather than one. The public site serves " +
					"published content and has no editing surface at all, so " +
					"the part of the system exposed to the internet cannot write " +
					"anything even if it is wrong."),
				shot("security", "The security posture scan, which reads this "+
					"deployment rather than a checklist."),
				warn("Before this is reachable from outside: read the Security " +
					"chapter, put TLS in front of both processes, and open the " +
					"Security screen — it scans this deployment and lists what " +
					"is thin, with the reasoning behind each finding."),
			},
		},
		{
			ID:      "concepts",
			Title:   "The words this uses",
			Summary: "Store, object, commit, ref, environment, draft, live.",
			Body: []block{
				table([]string{"Word", "What it means here"},
					[]string{"Store", "A directory holding everything: content, history, policy, credentials."},
					[]string{"Object", "A blob, a tree or a commit, named by the SHA-256 of its own bytes."},
					[]string{"Blob", "One page's fields, or one record, serialised."},
					[]string{"Tree", "A directory listing: names pointing at objects. Trees nest."},
					[]string{"Commit", "A tree plus who, when, why, and what came before."},
					[]string{"Ref", "A name pointing at a commit. Refs move; objects never do."},
					[]string{"Draft", "The ref where work happens. Not public."},
					[]string{"Live", "The ref the public site serves."},
					[]string{"Environment", "A named ref in a promotion sequence — staging, production."},
					[]string{"Principal", "Who somebody is. A policy is written in terms of these."},
					[]string{"Binding", "A grant or a denial: this principal, this role, this subtree."},
					[]string{"Token", "A credential proving you are a principal. Not an identity."},
				)},
		},
	},
}
