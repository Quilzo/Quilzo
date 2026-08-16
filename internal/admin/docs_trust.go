package admin

// The manual, the chapters about who may do what and what this can prove.

var chapterAdmin = chapter{
	Name: "Access and administration",
	Sections: []section{
		{
			ID:      "auth",
			Title:   "How authentication and access work",
			Summary: "Principals, roles, bindings, tokens, and the difference between proving who you are and being allowed to act.",
			Body: []block{
				p("Two separate questions, kept separate. Authentication is " +
					"\"who are you\" and is answered by a credential or an " +
					"identity provider. Authorisation is \"may you do this\" and " +
					"is answered by the policy. Having an account is not access."),
				sub("The role ladder"),
				p("Four rungs, in order, each including everything below it. A " +
					"total order rather than a permission matrix, because the " +
					"complete answer to \"what does this let people do\" then " +
					"fits on a screen, and a permission model nobody can read in " +
					"full is one nobody checks."),
				table([]string{"Role", "Can"},
					[]string{"reader", "see content and drafts"},
					[]string{"author", "write drafts; cannot make anything public"},
					[]string{"publisher", "publish and roll back"},
					[]string{"admin", "manage who can do what"},
				),
				table([]string{"Action", "Needs at least"},
					[]string{"view", "reader"},
					[]string{"edit-draft", "author"},
					[]string{"publish", "publisher"},
					[]string{"rollback", "publisher"},
					[]string{"grant", "admin"},
					[]string{"manage-tokens", "admin"},
				),
				sub("Where is the contributor role?"),
				p("There isn't one, deliberately. Every CMS vocabulary has a " +
					"contributor — somebody who writes drafts and cannot publish " +
					"— and mapping that onto a ladder gets it wrong, because the " +
					"distinction is not less power. A contributor does exactly " +
					"what an author does; they do it to a smaller set of pages."),
				p("So it is a constraint on the grant rather than a rung: mark a " +
					"binding own-only and it applies to content that principal " +
					"created. It composes with everything — any role can be " +
					"own-only, it stacks with a subtree, and it stacks with a " +
					"token's own scope. A new rung would have composed with " +
					"nothing."),
				sub("Bindings"),
				p("A binding grants — or denies — a role to a principal on a " +
					"subtree. A denial wins wherever it applies, which is what " +
					"makes \"everything except this section\" expressible without " +
					"enumerating everything."),
				sub("Credentials"),
				p("A token proves you are a principal. The secret is shown once " +
					"and only a hash is stored, so it cannot be recovered or " +
					"read out of the store by anybody who gets the store."),
				p("Two lifetimes share the type on purpose. A long-lived token " +
					"is the thing you keep in a secret manager. A session is " +
					"minted from one at the moment of use and lives for minutes. " +
					"\"Generated rather than hardcoded\" is not the same as " +
					"\"short-lived\" — a thirty-day token is still a bearer " +
					"credential sitting somewhere for thirty days."),
				p("Revoking a parent invalidates everything minted from it. " +
					"Otherwise the sessions outlive the revocation and " +
					"\"revoked\" is a claim rather than a fact."),
				sub("Signing in with an identity provider"),
				p("Any OIDC provider. Discovery happens at startup rather than " +
					"at the first sign-in, so a misconfiguration is a server " +
					"that refuses to start rather than a person staring at a " +
					"button that does not work and no explanation."),
				code("# scrivet-root/oidc.json\n" +
					"{\n" +
					"  \"issuer\": \"https://id.example.org\",\n" +
					"  \"client_id\": \"scrivet\",\n" +
					"  \"redirect_uri\": \"https://cms.example.org/auth/callback\",\n" +
					"  \"claim\": \"email\",\n" +
					"  \"require_verified_email\": true\n" +
					"}"),
				code("export SCRIVET_OIDC_SECRET=...   # never in the store"),
				warn("require_verified_email defaults to true and should stay " +
					"true. An unverified address is a claim by whoever signed " +
					"up, and mapping it to a principal lets them choose who to be."),
				sub("Throttling"),
				p("Repeated failures are slowed, not locked out. NIST SP " +
					"800-63B requires throttling and prefers a soft response, " +
					"because a hard lockout is a denial of service that an " +
					"attacker aims at your users by failing their logins for " +
					"them. Throttling keys on the source before authentication " +
					"and on the principal after it, and a valid credential is " +
					"always let through."),
			},
		},
		{
			ID:      "users",
			Title:   "Managing people",
			Summary: "Adding, changing and removing access, and seeing who is signed in.",
			Body: []block{
				p("The People screen is grants and credentials side by side, " +
					"because they are two halves of one question and keeping " +
					"them on separate screens is how somebody ends up revoking a " +
					"grant and leaving a working token."),
				shot("people", "People: grants and live sessions side by side, "+
					"because they are two halves of one question."),
				steps(
					"Grant the role first. The policy is what decides; a credential only proves identity.",
					"Issue a credential for that principal. The secret is shown once.",
					"To take access away, revoke the credential and remove the grant. Either alone is incomplete.",
				),
				sub("Who is signed in"),
				p("Every live session, its principal, when it was issued and " +
					"when it expires, with a button to end it. Ending a session " +
					"takes effect on the next request everywhere, because every " +
					"process re-reads the credential store rather than trusting " +
					"what it loaded at startup — a revocation that waits for a " +
					"restart is a revocation with a window measured in uptime."),
				sub("What people can do for themselves"),
				p("Anybody can open You: see what they may do and why, see their " +
					"own sessions, end any of them, set a display name, and " +
					"arrange their own navigation. Nobody can change what they " +
					"are allowed to do — self-service privilege escalation is " +
					"the shape of most access-control failures, and it usually " +
					"arrives as a profile page with one field too many."),
			},
		},
		{
			ID:      "settings",
			Title:   "Settings",
			Summary: "Every setting, its default, and what happens when you weaken one.",
			Body: []block{
				p("The defaults are the recommended configuration. A setting can " +
					"be changed to something weaker, and that is allowed — a " +
					"product that forbids it gets deployed with the whole " +
					"mechanism disabled by whoever needed the exception."),
				p("What it costs is a reason. The reason goes in the audit log, " +
					"lapses after a set number of days, and is reported by the " +
					"security posture until it is changed back or renewed. " +
					"Nothing is forbidden and nothing is silent."),
				sub("Floors"),
				p("A small number of settings have a floor below which they " +
					"cannot go at all. These are the ones where a weaker value " +
					"is not a trade-off but a broken control."),
			},
		},
		{
			ID:      "integrations",
			Title:   "Integrations",
			Summary: "Webhooks, log forwarding, the identity provider, and extensions.",
			Body: []block{
				p("One screen, because it answers one question an auditor and an " +
					"operator both ask: what leaves this system, and what runs " +
					"inside it that we did not write."),
				sub("Webhooks"),
				p("https only. Over cleartext the payload is readable and the " +
					"signature is replayable by anyone on the path, so it is " +
					"refused rather than warned about. Each delivery is signed " +
					"with a per-endpoint key, shown once when the endpoint is " +
					"created — the receiver needs those exact bytes, so it is a " +
					"shared key and cannot be stored hashed."),
				p("Requests go through the same address check as every other " +
					"outbound request, so a webhook URL cannot be used to reach " +
					"something inside your network."),
				sub("Extensions"),
				p("This is the alternative to a plugin runtime. An extension is " +
					"a separate process with a declared manifest: what it is " +
					"sent, when it runs, and the hash of the executable. It " +
					"cannot see anything it did not declare — empty means " +
					"nothing, not everything, because an extension that gets " +
					"everything by default is one that sees the unpublished " +
					"legal review because somebody added a field last Tuesday."),
				p("The binary is pinned at registration. Replacing the file on " +
					"disk otherwise replaces the code with no record and no " +
					"signal."),
				warn("An extension that fails blocks the operation, by default. " +
					"An extension registered to validate content exists to " +
					"refuse some of it, so if it crashes then nothing validated " +
					"that page and storing it anyway records a check that did " +
					"not happen. Marking one optional is a decision to make with " +
					"your eyes open, per extension."),
				sub("Log forwarding"),
				p("The audit log exports as OCSF, CEF or JSON Lines, with an " +
					"integrity envelope over the events so the receiver can " +
					"check nothing was added or dropped in transit. Identifiers " +
					"stay pseudonymous unless asked for, and asking is itself " +
					"recorded."),
			},
		},
	},
}

var chapterTrust = chapter{
	Name: "Security and privacy",
	Sections: []section{
		{
			ID:      "security",
			Title:   "Security",
			Summary: "What this defends against by construction, what it defends by control, and what it does not.",
			Body: []block{
				p("Most of this product's security is subtraction. The list " +
					"below is not a set of mitigations; it is a set of things " +
					"that are not present to be attacked."),
				sub("Removed rather than defended"),
				table([]string{"Usual vulnerability", "Why it cannot occur here"},
					[]string{"Template injection to remote code execution", "the template language has no method calls, no attribute traversal and no evaluation"},
					[]string{"Stored XSS through a raw filter", "there is no raw filter; escaping is contextual and cannot be turned off"},
					[]string{"Plugin supply chain", "no plugin runtime in the server; extensions are separate processes with pinned hashes"},
					[]string{"Dependency vulnerabilities", "there are no third-party dependencies, and CI fails if one appears"},
					[]string{"Schema validator denial of service", "no regular expressions, references, recursion or combinators in content types"},
					[]string{"Query injection", "a query is a set of values, never an expression; there is no evaluator"},
					[]string{"SVG script execution", "SVG is not an accepted upload format"},
					[]string{"Image decompression bombs", "each format is decoded and separately size-capped"},
					[]string{"Container escape through a shell", "the image has no shell, no package manager and no interpreter"},
					[]string{"XSS in the admin", "the admin ships no JavaScript, and its policy forbids executing any"},
				),
				sub("Defended by control"),
				list(
					"Cross-site request forgery: SameSite=Strict on the session cookie, plus Sec-Fetch-Site and Origin checks on every state-changing request.",
					"Server-side request forgery: every outbound request — imports, webhooks, calendars, the model — goes through one client that checks the resolved address at connect time, so a DNS rebind does not help.",
					"Credential stuffing and brute force: throttled per source before authentication and per principal after, with soft delays rather than lockout.",
					"Privilege escalation: the policy is the only thing that grants, no screen lets a person change their own permissions, and the machine interface cannot grant at all.",
					"Session theft: sessions are minted short-lived from long-lived tokens, revoking a parent invalidates its children, and every process re-reads the credential store per request.",
					"Path traversal: nothing caller-supplied ever becomes a path. Identifiers are validated at every boundary that could build one, on both sides.",
					"Tampering with the record: the audit log is a hash chain, written by a separate account, and can be anchored to a timestamp authority or a public chain.",
				),
				sub("What this does not do"),
				p("Said plainly, because a security page that lists only " +
					"strengths is marketing:"),
				list(
					"It does not encrypt content at rest by default. That protects against a stolen disk, not against a process that can read the directory, and the filesystem is the trust boundary in most deployments. Turn it on where the disk is the threat.",
					"It does not terminate TLS. Put a reverse proxy in front, and tell the posture scan you have so it can tell interception from exposure.",
					"It does not send email, so it cannot alert you. It writes audit records a SIEM rule can match, which is the integration point.",
					"It cannot stop an administrator. Somebody with the grant permission can grant themselves anything; what it can do is make every such action a record in a chain they cannot quietly edit.",
					"It has not been independently audited. The scanner, the posture checks and the test suite are our own work and are not a substitute for somebody else's.",
				),
				sub("Checking it yourself"),
				p("The Security screen scans this deployment and explains each " +
					"finding. Under it: the static scanner over templates and " +
					"content, the content policy derived from what the site " +
					"actually references, the bill of materials and " +
					"cryptographic inventory, store verification, and what the " +
					"agents have been doing."),
			},
		},
		{
			ID:      "privacy",
			Title:   "Privacy",
			Summary: "What is stored about people, what leaves, and what is pseudonymous.",
			Body: []block{
				p("The short version: this stores the least it can, sends " +
					"nothing anywhere by default, and pseudonymises people in " +
					"the one place it has to keep a record of them."),
				sub("What is stored about a person"),
				table([]string{"Data", "Why", "Where"},
					[]string{"Principal name", "the policy is written in terms of it", "the access policy"},
					[]string{"Role and scope", "what they may do", "the access policy"},
					[]string{"Token hash", "to check a presented credential", "the credential store"},
					[]string{"Issued, expires, last used", "so a stale session can be found", "the credential store"},
					[]string{"Display name and contact", "optional, self-supplied, for colleagues", "the profile store"},
					[]string{"Pseudonym in the audit log", "so actions can be correlated without naming anybody", "the audit log"},
				),
				p("That is the complete list. No password, because there are no " +
					"passwords. No email address unless somebody types one into " +
					"their own contact field. No analytics, no telemetry, no " +
					"usage reporting, and no phoning home — the binary makes no " +
					"outbound request that an operator did not configure."),
				sub("Pseudonymous by default"),
				p("The audit log records a keyed hash of the principal rather " +
					"than the name. Actions by the same person still correlate, " +
					"which is what an investigation needs, and reading the log " +
					"does not hand somebody a staff list."),
				p("It can be resolved forward — compute the pseudonym for a " +
					"principal this store knows and compare — so an " +
					"administrator can answer \"was this dana\". It cannot be " +
					"reversed, so somebody the policy has never heard of stays " +
					"opaque."),
				sub("What leaves the system"),
				p("Nothing, unless configured. Each of these is an operator's " +
					"decision, each is visible on the Integrations screen, and " +
					"each is recorded:"),
				list(
					"Webhooks, to endpoints an administrator registered.",
					"Audit exports to a SIEM, when somebody exports one.",
					"Requests to a model, if the assistant is configured — this is the one that sends content to a third party, and which provider is deliberately not a default.",
					"Timestamp and anchoring requests, which send a hash and never content.",
				),
				sub("Data subject requests"),
				p("Export produces everything the store holds about the site in " +
					"a portable format. A principal's own record is their " +
					"bindings, their tokens and their profile row, all of which " +
					"are plain files in the store directory. Removing somebody " +
					"means revoking their credentials, removing their bindings " +
					"and deleting their profile row."),
				warn("Content history is immutable by design, so a page somebody " +
					"authored keeps their name in its commit. That is the point " +
					"of an audit trail and it is in tension with erasure — if " +
					"that tension matters to your regulator, decide before you " +
					"store personal data in page content, not afterwards."),
				sub("Retention"),
				p("Content and history are kept until somebody deletes the " +
					"store. The audit log is append-only and is not rotated by " +
					"this program, because a log that rotates itself is a log " +
					"that loses the record of whoever wanted it rotated. " +
					"Forward it to a system with a retention policy you control."),
			},
		},
		{
			ID:      "provenance",
			Title:   "Provenance",
			Summary: "Recording what was written by a model, because publishing requires it.",
			Body: []block{
				p("A provenance record says how a page came to exist: written by " +
					"a person, generated by a model, or somewhere between. It " +
					"names the model where there was one and the person " +
					"accountable in every case."),
				p("Publishing refuses pages with no record. Not because " +
					"unmarked content is presumed to be AI, but because " +
					"unrecorded is not the same as human-written, and a system " +
					"that treats them as the same is a system where the " +
					"obligation quietly stops being met."),
				p("The record is a content hash, so editing a page makes its " +
					"provenance stale rather than silently carrying it forward. " +
					"A mark that survives an unrelated rewrite is a mark about " +
					"nothing."),
			},
		},
		{
			ID:      "logging",
			Title:   "The audit log",
			Summary: "A hash chain, written by another account, that this process cannot edit.",
			Body: []block{
				p("Every consequential action is recorded: who, what, to which " +
					"resource, whether it succeeded, and why not when it did " +
					"not. Refusals are recorded too — somebody being stopped is " +
					"exactly the thing a log exists to preserve."),
				sub("Why it can be trusted"),
				list(
					"Each entry carries the hash of the one before it, so removing or altering one breaks the chain from that point on, visibly.",
					"The writer runs as a different account, so the process serving this interface can append and cannot rewrite. The log screen says whether that separation is actually in place in your deployment rather than assuming it.",
					"The chain can be timestamped by an RFC 3161 authority or anchored to a public blockchain, which makes \"this record existed at this time\" checkable by somebody who does not trust us.",
					"Principals are pseudonymous. See the Privacy section.",
				),
				sub("Reading it"),
				p("The Log screen shows the entries, verifies the chain in front " +
					"of you, and resolves pseudonyms for principals this store " +
					"knows. It is read-only, and not because of a permission — " +
					"this process has no code that writes it."),
			},
		},
	},
}

var chapterYou = chapter{
	Name: "This interface",
	Sections: []section{
		{
			ID:      "profile",
			Title:   "You",
			Summary: "Your permissions, your sessions, and how this looks to you.",
			Body: []block{
				p("Three parts, and the middle one is deliberately read-only."),
				list(
					"What you may do, resolved against the policy as written — including the rule that decided each answer, so \"why can I not publish\" has an answer on the screen.",
					"Your sessions. Every live credential issued to you, with the one you are using marked, and a button to end any of them. You do not need an administrator for this: a session you think has been taken should end now, not tomorrow.",
					"How this looks to you: light or dark, navigation on the top or the side, and the order of your own tabs.",
				),
				sub("Arranging the tabs"),
				p("Buttons rather than dragging. WCAG 2.2 forbids requiring a " +
					"drag gesture for any function, and pressing a button is " +
					"also faster, works on a phone and works from a keyboard. " +
					"Tabs move within their own group; the groups are the " +
					"structure rather than a preference."),
				p("The arrangement is a cookie, so it belongs to you rather than " +
					"to the store, and a screen added later appears rather than " +
					"being hidden by an old preference."),
				sub("Light and dark"),
				p("Three states, not two: light, dark, and follow your system. " +
					"The third is the default and is the one most products drop " +
					"— a two-state toggle takes away \"switch at sunset\" with no " +
					"way back."),
			},
		},
	},
}
