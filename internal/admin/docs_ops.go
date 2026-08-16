package admin

// The manual, the chapters about shipping and running.

var chapterRelease = chapter{
	Name: "Shipping it",
	Sections: []section{
		{
			ID:      "publishing",
			Title:   "The publishing process",
			Summary: "Draft, review, the gates, and what publishing actually does.",
			Body: []block{
				p("Work happens on the draft. Nothing on the draft is public — " +
					"the site process serves a different ref entirely, so an " +
					"unpublished page is not merely hidden, it is not there."),
				sub("What review shows"),
				p("Every difference between the draft and what is live, the " +
					"accessibility report over the rendered pages, and which " +
					"pages have no provenance record."),
				sub("The gates"),
				p("Three things can refuse a publication, and each can be " +
					"overridden with a reason that is recorded:"),
				table([]string{"Gate", "Refuses when", "Override"},
					[]string{"Content types", "a page does not satisfy its type", "no override — fix the page"},
					[]string{"Accessibility", "a blocking failure would go out", "a written reason"},
					[]string{"Provenance", "an unmarked page would go out", "a written reason"},
				),
				p("The same gates run on the command line and over the machine " +
					"interface, with one difference: the machine interface has " +
					"no override at all, because deciding to ship a known " +
					"accessibility failure is a human decision."),
				sub("What publishing does"),
				p("Moves the live pointer to the draft commit. No copy, no " +
					"rebuild, no cache purge. Every cache in the path notices on " +
					"its own, because a page's ETag is its content hash — not " +
					"derived from it, it is it — so a conditional request " +
					"answers itself and cache invalidation stops being a problem."),
				sub("Rolling back"),
				p("The version you moved away from is still stored, so rolling " +
					"back is a pointer move to a commit that already passed the " +
					"gates once. That also means it runs none of them, which is " +
					"why it is a permission of its own and is not available to " +
					"agents."),
			},
		},
		{
			ID:      "environments",
			Title:   "Environments and scheduling",
			Summary: "Staging, promotion, work queued for later, and who is holding what.",
			Body: []block{
				p("An environment is a named pointer in a sequence. A store that " +
					"has never configured one has exactly one, called " +
					"production, pointing at the ref that has always been called " +
					"live — so nothing changes for a deployment that does not " +
					"want this."),
				sub("Promotion is the whole argument"),
				p("Elsewhere, staging and production are separate databases with " +
					"a copy job between them, and \"it worked in staging\" is a " +
					"hope: the copy can reorder, re-serialise, drop a field the " +
					"schema no longer has, or run against a row somebody edited " +
					"after the test."),
				p("Here, promotion re-points one name at the commit another name " +
					"already holds. Production ends up byte-identical to what " +
					"was tested — not equivalent, not \"the same content\", the " +
					"same bytes, because the name of the thing is a hash of the " +
					"thing."),
				sub("Skipping"),
				p("Promoting straight past staging is possible and has to be " +
					"asked for by name, and it is recorded. A sequence exists so " +
					"that things pass through it, and a pipeline that can skip " +
					"silently is one that eventually does — in a hurry, at the " +
					"worst moment."),
				sub("Scheduling"),
				p("A scheduled publication names one exact commit. Editing the " +
					"draft afterwards does not change what is scheduled; it " +
					"makes the entry stale, and a stale entry is reported rather " +
					"than fired. Every gate runs at publication, against the " +
					"content as it stands then."),
				code("scrivet schedule run   # from cron, systemd, or a CronJob"),
				note("There is no scheduler daemon. A long-lived process that " +
					"fires timers is a second thing that can be down, and every " +
					"system this runs on already has something that runs a " +
					"command every minute."),
			},
		},
		{
			ID:      "history",
			Title:   "History",
			Summary: "Every commit, and going back to one.",
			Body: []block{
				p("Every save is a commit: a tree, an author, a message, a time " +
					"and a parent. Nothing is ever overwritten, so history is " +
					"not a feature that was added — it is what the storage model " +
					"already was."),
				p("Rolling back moves the live pointer to an earlier commit. The " +
					"version you moved away from stays stored, so it is " +
					"reversible in the same way and by the same operation."),
			},
		},
		{
			ID:      "transfer",
			Title:   "Import, export and starters",
			Summary: "Getting a site in, getting one out, and starting from something.",
			Body: []block{
				p("These two decide whether this is a place you can leave, which " +
					"is a reasonable thing for a customer to check before they " +
					"arrive."),
				sub("Export"),
				p("Markdown, JSON or WordPress WXR. The export carries when each " +
					"page last actually changed and the redirect map, because " +
					"both are real information most systems cannot reconstruct — " +
					"losing them on the way out hands somebody a site whose " +
					"sitemap is wrong from its first day."),
				sub("Import"),
				p("Upload an export and it is read and reported without writing " +
					"anything. Read the skipped list first: an importer that " +
					"quietly drops half an export is worse than one that " +
					"refuses, because the loss is found months later by a reader."),
				p("Media URLs found in imported content are collected and " +
					"deliberately not fetched. Following them would turn a file " +
					"somebody sent you into a request from inside your network " +
					"to a host they chose."),
				p("Writing is a second upload with the box ticked, and it merges " +
					"rather than replacing — an import that replaced the draft " +
					"would delete everything the site had that the export did " +
					"not mention."),
				sub("Starters"),
				p("A starter is a template plus sample content that renders it " +
					"completely. Applying one over a page somebody wrote " +
					"replaces their work with an example, so it is refused " +
					"unless asked for explicitly."),
			},
		},
	},
}

var chapterInterfaces = chapter{
	Name: "The three surfaces",
	Sections: []section{
		{
			ID:      "api",
			Title:   "The content API",
			Summary: "HTTP for programs, with the same rules as everything else.",
			Body: []block{
				p("A read-only JSON API over published content, and a writable " +
					"one where an operator has asked for it. The API screen in " +
					"this interface calls it against this store, from this " +
					"origin, using your session — so what you see there is what " +
					"your own code will get."),
				table([]string{"Route", "Does"},
					[]string{"GET /api/v1/pages", "list published pages"},
					[]string{"GET /api/v1/pages/{name}", "one page's fields"},
					[]string{"GET /api/v1/collections", "the record collections"},
					[]string{"GET /api/v1/records/{collection}", "records, filtered and paged"},
					[]string{"GET /api/v1/records/{collection}/{id}", "one record"},
					[]string{"PUT /api/v1/records/{collection}/{id}", "write one, where writing is enabled"},
				),
				sub("Concurrency"),
				p("A record's ETag is its identifier and its update time. Send " +
					"it back as If-Match and the write is a compare-and-swap: " +
					"refused if somebody else got there first, rather than " +
					"silently overwriting them."),
				sub("Scoping"),
				p("A token can be narrower than the principal holding it — " +
					"limited to a subtree, to certain content types, to certain " +
					"locales. A credential in a build pipeline should be able to " +
					"read the product pages and nothing else, and that is a " +
					"property of the credential rather than of the person."),
				sub("Rate limiting"),
				p("Per principal after authentication, per source before it. " +
					"Refusing on the source's history alone would lock out " +
					"everybody behind one address, which is a denial of service " +
					"aimed at your own users."),
			},
		},
		{
			ID:      "cli",
			Title:   "The command line",
			Summary: "Everything, scriptable, and the same code as the screens.",
			Body: []block{
				p("Every capability in this interface exists as a command, and " +
					"they are the same code path rather than two implementations " +
					"that agree. Where this manual names a command beside a " +
					"screen, that is what it means."),
				code("scrivet help          # every command\n" +
					"scrivet <command> -h  # one command\n" +
					"scrivet --json ...    # machine-readable output"),
				sub("Authenticating"),
				p("A token, from --token, from SCRIVET_TOKEN, or from a file at " +
					"~/.scrivet/token. Reads need one too, once a store has " +
					"access control configured: a store where anybody who can " +
					"reach the directory can read every draft is not access " +
					"control."),
				sub("Exit codes"),
				table([]string{"Code", "Means"},
					[]string{"0", "it worked"},
					[]string{"1", "it failed"},
					[]string{"2", "a gate refused it — a check said no, which is not the same as an error"},
				),
			},
		},
		{
			ID:      "mcp",
			Title:   "The machine interface",
			Summary: "What an agent can do here, and the larger list of what it cannot.",
			Body: []block{
				code("scrivet mcp --list          # the operations\n" +
					"scrivet mcp --token scv_...  # speak MCP on stdin"),
				p("Operations are data rather than tools, so none of their " +
					"descriptions enter a context window until an agent searches " +
					"for one. Nineteen operations sit behind four tools."),
				sub("What an agent can do"),
				p("Read anything it is allowed to read, and author content: " +
					"pages, records, and the listings that tell it what shape " +
					"they have to be. Plus the read-only assurance operations — " +
					"the scanner, store verification, the inventory, and its own " +
					"activity record."),
				sub("What it deliberately cannot"),
				p("Grant a role, mint a credential, register an extension, " +
					"change a security setting, rotate a key, export the audit " +
					"log, or roll back. Twenty-two capabilities are in this " +
					"interface and withheld from that one, each with its reason " +
					"written next to it in the source."),
				p("The line is: anything that reads and anything that authors " +
					"content belongs there; anything that changes who may do " +
					"what, what code runs, or what the keys are does not. A " +
					"prompt injection in a page an agent is reading is a " +
					"plausible route to whatever that agent can call, and \"it " +
					"could grant itself a role\" is not a sentence anybody " +
					"should be able to write about their CMS."),
				sub("Everything it writes is marked"),
				p("Content written over this interface is recorded as " +
					"AI-generated without being asked, and publishing refuses " +
					"unmarked pages. See the AI section."),
			},
		},
	},
}
