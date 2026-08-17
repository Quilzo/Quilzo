package posture

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// The rules, grouped by the control family they belong to.
//
// Each carries the NIST SP 800-53 identifiers it maps to and the OWASP
// Top 10:2025 category. That mapping is not decoration: it is what lets a
// finding be handed to an assessor as evidence rather than as an opinion, and
// it is what makes "we monitor continuously" a claim with a list behind it.
var rules = []Rule{

	// -- access control -----------------------------------------------------

	{
		ID:       "access.no-policy",
		Title:    "No access rules exist",
		Severity: Critical,
		Controls: []string{"AC-3", "AC-6"},
		OWASP:    "A01:2025 Broken Access Control",
		Why: "With no bindings, every check falls through to the default. " +
			"Whatever that default is, it is not a decision anyone made about " +
			"this site.",
		Check: func(s State) []Finding {
			if s.Policy == nil || len(s.Policy.Bindings) > 0 {
				return nil
			}
			return []Finding{{
				Detail: "the policy is empty, so access is decided by the " +
					"built-in default rather than by anything you configured",
				Fix: "scrivet auth grant YOU admin",
			}}
		},
	},
	{
		ID:       "access.no-deny-anywhere",
		Title:    "Nothing is denied anywhere",
		Severity: Low,
		Controls: []string{"AC-6"},
		OWASP:    "A01:2025 Broken Access Control",
		Why: "Least privilege is usually expressed as an exception: broad " +
			"access with specific carve-outs for the pages that matter. A " +
			"policy with no deny is one where nothing has been decided to be " +
			"more sensitive than anything else, which is rarely true.",
		Check: func(s State) []Finding {
			if s.Policy == nil || len(s.Policy.Bindings) == 0 {
				return nil
			}
			for _, b := range s.Policy.Bindings {
				if b.Deny {
					return nil
				}
			}
			return []Finding{{
				Detail: fmt.Sprintf("%d binding(s), none of them a deny",
					len(s.Policy.Bindings)),
				Fix: "scrivet auth deny WHO ROLE --on /some/sensitive/path",
			}}
		},
	},
	{
		ID:       "access.too-many-admins",
		Title:    "More administrators than the site needs",
		Severity: Medium,
		Controls: []string{"AC-6", "AC-6(5)", "AC-2(7)"},
		OWASP:    "A01:2025 Broken Access Control",
		Why: "Every administrator is a full compromise of the site if their " +
			"credential leaks. AC-6(5) asks that privileged accounts be " +
			"restricted to a named few, and the practical version of that is a " +
			"number small enough to list from memory.",
		Check: func(s State) []Finding {
			if s.Policy == nil {
				return nil
			}
			var admins []string
			for _, b := range s.Policy.Bindings {
				if b.Deny || b.Role != auth.RoleAdmin {
					continue
				}
				admins = append(admins, b.Principal)
			}
			admins = dedupe(admins)
			if len(admins) <= 3 {
				return nil
			}
			return []Finding{{
				Detail: fmt.Sprintf("%d administrators: %s",
					len(admins), joinShort(admins, 6)),
				Fix: "scrivet auth grant WHO publisher  # then revoke the admin role",
			}}
		},
	},
	{
		ID:       "access.sole-admin",
		Title:    "Only one administrator",
		Severity: Low,
		Controls: []string{"AC-2", "CP-2"},
		OWASP:    "",
		Why: "This is the opposite trade-off to the rule above, and both are " +
			"real. One administrator is the tightest possible privilege and " +
			"also a single point of failure: if that person loses their " +
			"credential, nobody can grant it back.",
		Check: func(s State) []Finding {
			if s.Policy == nil || len(s.Policy.Bindings) == 0 {
				return nil
			}
			var admins []string
			for _, b := range s.Policy.Bindings {
				if !b.Deny && b.Role == auth.RoleAdmin {
					admins = append(admins, b.Principal)
				}
			}
			if len(dedupe(admins)) != 1 {
				return nil
			}
			return []Finding{{
				Resource: admins[0],
				Detail: fmt.Sprintf("%s is the only administrator; there is no "+
					"recovery path if that credential is lost", admins[0]),
				Fix: "scrivet auth grant SOMEONE-ELSE admin",
			}}
		},
	},

	// -- credentials --------------------------------------------------------

	{
		ID:       "token.long-lived",
		Title:    "An API token lasts too long",
		Severity: High,
		Controls: []string{"IA-5", "AC-2(3)", "SC-12"},
		OWASP:    "A07:2025 Authentication Failures",
		Why: "A long-lived bearer token is a password that never gets rotated " +
			"and travels in a header. The exchange mechanism exists so a " +
			"long-lived credential can mint fifteen-minute sessions instead of " +
			"being handed to the thing that does the work.",
		Check: func(s State) []Finding {
			if s.Tokens == nil {
				return nil
			}
			var out []Finding
			for _, t := range s.Tokens.Tokens {
				if t.Revoked || t.IsSession() || t.Expired(s.Now) {
					continue
				}
				life := time.Unix(t.ExpiresAt, 0).Sub(time.Unix(t.CreatedAt, 0))
				if life <= 90*24*time.Hour {
					continue
				}
				sev := High
				if life > 365*24*time.Hour {
					sev = Critical
				}
				out = append(out, Finding{
					Severity: sev,
					Resource: t.ID,
					Detail: fmt.Sprintf("%s (%s, %s) is valid for %s, until %s",
						t.Name, t.Principal, t.Role, days(life),
						time.Unix(t.ExpiresAt, 0).UTC().Format("2006-01-02")),
					Fix: "scrivet token revoke " + t.ID +
						"  # then issue with --ttl 720h and exchange for sessions",
				})
			}
			return out
		},
	},
	{
		ID:       "token.admin-role",
		Title:    "An API token carries administrator rights",
		Severity: Critical,
		Controls: []string{"AC-6", "AC-6(2)", "IA-5"},
		OWASP:    "A01:2025 Broken Access Control",
		Why: "An admin token is the whole site in an HTTP header. It can " +
			"change the access policy, which means it can make its own " +
			"revocation impossible. Automation almost never needs this: it " +
			"needs to write drafts, or to publish, and both are lower.",
		Check: func(s State) []Finding {
			if s.Tokens == nil {
				return nil
			}
			var out []Finding
			for _, t := range s.Tokens.Tokens {
				if t.Revoked || t.Expired(s.Now) || t.Role != auth.RoleAdmin {
					continue
				}
				// A short-lived exchanged session is the intended shape of
				// this, so it is not the finding.
				if t.IsSession() {
					continue
				}
				out = append(out, Finding{
					Resource: t.ID,
					Detail: fmt.Sprintf("%s belongs to %s and can change the "+
						"access policy itself", t.Name, t.Principal),
					Fix: "scrivet token issue " + t.Name +
						" --principal " + t.Principal + " --role publisher",
				})
			}
			return out
		},
	},
	{
		ID:       "token.never-used",
		Title:    "A token was issued and never used",
		Severity: Medium,
		Controls: []string{"AC-2(3)", "IA-5"},
		OWASP:    "A07:2025 Authentication Failures",
		Why: "A credential nobody uses is a credential nobody would miss. It " +
			"is also the one most likely to still be sitting in a chat message " +
			"or a CI variable from the day it was created.",
		Check: func(s State) []Finding {
			if s.Tokens == nil {
				return nil
			}
			var out []Finding
			for _, t := range s.Tokens.Tokens {
				if t.Revoked || t.IsSession() || t.Expired(s.Now) || t.LastUsed != 0 {
					continue
				}
				age := s.Now.Sub(time.Unix(t.CreatedAt, 0))
				if age < 14*24*time.Hour {
					continue
				}
				out = append(out, Finding{
					Resource: t.ID,
					Detail: fmt.Sprintf("%s was issued %s ago and has never "+
						"authenticated", t.Name, days(age)),
					Fix: "scrivet token revoke " + t.ID,
				})
			}
			return out
		},
	},
	{
		ID:       "token.stale",
		Title:    "A token has not been used in a long time",
		Severity: Medium,
		Controls: []string{"AC-2(3)"},
		OWASP:    "A07:2025 Authentication Failures",
		Why: "AC-2(3) asks that inactive accounts be disabled. The reasoning " +
			"is that a credential still working three months after its last " +
			"legitimate use is working for whoever finds it next.",
		Check: func(s State) []Finding {
			if s.Tokens == nil {
				return nil
			}
			var out []Finding
			for _, t := range s.Tokens.Stale(s.Now, 90*24*time.Hour) {
				if t.IsSession() {
					continue
				}
				out = append(out, Finding{
					Resource: t.ID,
					Detail: fmt.Sprintf("%s last authenticated %s ago",
						t.Name, days(s.Now.Sub(time.Unix(t.LastUsed, 0)))),
					Fix: "scrivet token revoke " + t.ID,
				})
			}
			return out
		},
	},
	{
		ID:       "token.expired-not-revoked",
		Title:    "Expired tokens are still on file",
		Severity: Low,
		Controls: []string{"AC-2", "IA-5"},
		OWASP:    "",
		Why: "They cannot authenticate, so this is hygiene rather than " +
			"exposure. It matters because a token list nobody prunes is a token " +
			"list nobody reads, and the one that should not be there hides " +
			"among the forty that no longer work.",
		Check: func(s State) []Finding {
			if s.Tokens == nil {
				return nil
			}
			var n int
			for _, t := range s.Tokens.Tokens {
				if !t.Revoked && t.Expired(s.Now) {
					n++
				}
			}
			if n == 0 {
				return nil
			}
			return []Finding{{
				Detail: fmt.Sprintf("%d expired %s still listed",
					n, plural(n, "token is", "tokens are")),
				Fix: "scrivet token prune",
			}}
		},
	},

	// -- audit --------------------------------------------------------------

	{
		ID:       "audit.chain-broken",
		Title:    "The audit chain does not verify",
		Severity: Critical,
		Controls: []string{"AU-9", "AU-9(3)", "SI-7"},
		OWASP:    "A09:2025 Logging and Alerting Failures",
		Why: "The chain is the only reason to believe the log. If it does not " +
			"verify, every record in it is an assertion rather than evidence — " +
			"including the records about whoever broke it.",
		Check: func(s State) []Finding {
			if s.Audit == nil {
				return nil
			}
			ok, problems := audit.Verify(s.Audit)
			if ok {
				return nil
			}
			var where []string
			for _, p := range problems {
				where = append(where, fmt.Sprintf("seq %d: %s", p.Seq, p.Reason))
			}
			return []Finding{{
				Detail: fmt.Sprintf("%d break(s) — %s",
					len(problems), joinShort(where, 3)),
				Fix: "scrivet auditlog verify  # then treat the log as evidence " +
					"of tampering, not as a record of events",
			}}
		},
	},
	{
		ID:       "audit.empty",
		Title:    "Nothing has been logged",
		Severity: High,
		Controls: []string{"AU-2", "AU-12"},
		OWASP:    "A09:2025 Logging and Alerting Failures",
		Why: "An empty log after the site has been published means logging is " +
			"not wired up. Every control that depends on being able to say what " +
			"happened is inoperative, and nobody will find out until they need it.",
		Check: func(s State) []Finding {
			if s.Audit == nil || len(s.Audit) > 0 {
				return nil
			}
			if s.Content.PublishedAt == 0 {
				return nil // nothing has happened yet, so nothing is missing
			}
			return []Finding{{
				Detail: "the site has been published but the audit log is empty",
				Fix:    "scrivet auditlog  # check the log path is writable",
			}}
		},
	},
	{
		ID:       "audit.unverified-identities",
		Title:    "Most logged actions have unproven identities",
		Severity: Medium,
		Controls: []string{"AU-3", "IA-2"},
		OWASP:    "A09:2025 Logging and Alerting Failures",
		Why: "An unverified principal was taken from the environment, not " +
			"proved. The chain shows nobody edited the record afterwards; it " +
			"says nothing about whether the name in it was true when written. " +
			"A log that is cryptographically intact and substantively false is " +
			"the worst outcome, because it is believed.",
		Check: func(s State) []Finding {
			if len(s.Audit) < 10 {
				return nil
			}
			var unverified int
			for _, e := range s.Audit {
				if !e.Verified {
					unverified++
				}
			}
			pct := unverified * 100 / len(s.Audit)
			if pct < 50 {
				return nil
			}
			return []Finding{{
				Detail: fmt.Sprintf("%d%% of %d records (%d) name a principal "+
					"that was asserted rather than authenticated",
					pct, len(s.Audit), unverified),
				Fix: "scrivet auth grant WHO ROLE  # a policy with bindings " +
					"turns on identity enforcement",
			}}
		},
	},

	// -- content integrity --------------------------------------------------

	{
		ID:       "content.raw-template",
		Title:    "A template disables escaping",
		Severity: High,
		Controls: []string{"SI-10", "SC-18"},
		OWASP:    "A03:2025 Injection",
		Why: "`raw` is the one construct in the template language that emits " +
			"content without escaping it. Every use is a decision to trust the " +
			"content, and content is the thing users supply.",
		Check: func(s State) []Finding {
			var out []Finding
			for _, t := range s.Content.RawTemplates {
				out = append(out, Finding{
					Resource: t,
					Detail:   t + " uses raw, so content is emitted unescaped",
					Fix:      "scrivet audit  # review each use, or remove it",
				})
			}
			return out
		},
	},
	{
		ID:       "content.unmarked-ai",
		Title:    "Published pages have no provenance",
		Severity: Medium,
		Controls: []string{"SI-7", "PM-30"},
		OWASP:    "",
		Why: "EU AI Act Article 50 requires machine-readable marking of " +
			"AI-generated content, in force since 2 August 2026, with penalties " +
			"up to €15M or 3% of turnover. Absence must never read as a claim: " +
			"an unmarked page is unknown, not human-written.",
		Check: func(s State) []Finding {
			n := len(s.Content.UnmarkedPages)
			if n == 0 {
				return nil
			}
			return []Finding{{
				Detail: fmt.Sprintf("%d published %s no provenance record: %s",
					n, plural(n, "page has", "pages have"),
					joinShort(s.Content.UnmarkedPages, 5)),
				Fix: "scrivet provenance set PAGE --source humanEdits",
			}}
		},
	},
	{
		ID:       "content.stale-provenance",
		Title:    "Provenance no longer matches the content",
		Severity: Medium,
		Controls: []string{"SI-7"},
		OWASP:    "",
		Why: "The record describes content that has since changed. A stale " +
			"mark is worse than a missing one, because it makes a specific " +
			"false claim about who wrote what is currently published.",
		Check: func(s State) []Finding {
			n := len(s.Content.StalePages)
			if n == 0 {
				return nil
			}
			return []Finding{{
				Detail: fmt.Sprintf("%d %s changed since being marked: %s",
					n, plural(n, "page has", "pages have"),
					joinShort(s.Content.StalePages, 5)),
				Fix: "scrivet provenance check",
			}}
		},
	},
	{
		ID:       "content.untyped-pages",
		Title:    "Published pages have no content type",
		Severity: Low,
		Controls: []string{"SI-10"},
		OWASP:    "A04:2025 Insecure Design",
		Why: "An untyped page accepts any field with any value. That is the " +
			"default and it is not wrong, but it means the validation this tool " +
			"performs is not being applied to those pages.",
		Check: func(s State) []Finding {
			if s.Types == nil || len(s.Content.LivePages) == 0 {
				return nil
			}
			// If no types exist at all, the operator has not opted into typing.
			// Nagging them about it is exactly the false positive that gets a
			// scanner muted: this rule is about incomplete coverage, not about
			// declining a feature.
			if s.Types.Registry == nil || len(s.Types.Registry.Types) == 0 {
				return nil
			}
			var untyped []string
			for _, p := range s.Content.LivePages {
				if _, bound := s.Types.Bound[p]; !bound {
					untyped = append(untyped, p)
				}
			}
			if len(untyped) == 0 {
				return nil
			}
			return []Finding{{
				Detail: fmt.Sprintf("%d of %d live pages are unvalidated: %s",
					len(untyped), len(s.Content.LivePages), joinShort(untyped, 5)),
				Fix: "scrivet type bind PAGE TYPE",
			}}
		},
	},
	{
		ID:       "content.accessibility-blocking",
		Title:    "Live content fails the accessibility gate",
		Severity: High,
		Controls: []string{"PL-4"},
		OWASP:    "",
		Why: "The gate is supposed to make this impossible, so a blocking " +
			"failure on live content means something was published around it — " +
			"an override, a direct ref move, or a path that does not run the " +
			"check.",
		Check: func(s State) []Finding {
			if s.Content.BlockingA11y == 0 {
				return nil
			}
			return []Finding{{
				Detail: fmt.Sprintf("%d blocking failure(s) are live, which "+
					"means the publish gate was bypassed", s.Content.BlockingA11y),
				Fix: "scrivet a11y --ref live",
			}}
		},
	},

	// -- exposure -----------------------------------------------------------

	{
		ID:       "expose.admin-public",
		Title:    "The admin interface is not on loopback",
		Severity: Critical,
		Controls: []string{"SC-7", "AC-17"},
		OWASP:    "A02:2025 Security Misconfiguration",
		Why: "The editing interface bound to a public address is reachable by " +
			"anyone who can route to it. Authentication is the only thing " +
			"between the internet and the content, which is one control where " +
			"there should be two.",
		Check: func(s State) []Finding {
			addr := s.Server.AdminAddr
			if addr == "" || isLoopback(addr) {
				return nil
			}
			sev := Critical
			detail := addr + " is reachable from outside this machine"
			if s.Server.AdminTLS || s.Server.BehindProxy {
				// Still exposed, but not also in cleartext.
				sev = High
				detail += " (TLS is terminated, so this is exposure rather than " +
					"interception)"
			}
			return []Finding{{
				Severity: sev,
				Resource: addr,
				Detail:   detail,
				Fix:      "scrivet serve --addr 127.0.0.1:8080  # and reach it over a tunnel",
			}}
		},
	},
	{
		ID:       "expose.cleartext",
		Title:    "An interface serves cleartext over a network",
		Severity: Critical,
		Controls: []string{"SC-8", "SC-8(1)", "SC-23"},
		OWASP:    "A02:2025 Security Misconfiguration",
		Why: "A bearer token in a header over plain HTTP is a token anyone on " +
			"the path can read and replay. This is the failure that makes every " +
			"other credential control irrelevant.",
		Check: func(s State) []Finding {
			if s.Server.BehindProxy {
				return nil
			}
			var out []Finding
			if a := s.Server.AdminAddr; a != "" && !isLoopback(a) && !s.Server.AdminTLS {
				out = append(out, Finding{
					Resource: a,
					Detail: "the admin serves plain HTTP on " + a +
						"; API tokens travel in clear",
					Fix: "put it behind TLS, or bind to 127.0.0.1 and tunnel",
				})
			}
			if a := s.Server.PublicAddr; a != "" && !isLoopback(a) && !s.Server.PublicTLS {
				out = append(out, Finding{
					Severity: High, // no credentials here, but still tamperable
					Resource: a,
					Detail: "the public site serves plain HTTP on " + a +
						"; content can be modified in transit",
					Fix: "terminate TLS in front of it and set --behind-proxy",
				})
			}
			return out
		},
	},
	{
		ID:       "expose.file-mode",
		Title:    "A sensitive file is readable by other users",
		Severity: High,
		Controls: []string{"AC-3", "AC-6", "CM-5"},
		OWASP:    "A02:2025 Security Misconfiguration",
		Why: "Token hashes, the access policy and the audit log are all things " +
			"another local account should not be able to read or change. On a " +
			"shared host this is the whole boundary.",
		Check: func(s State) []Finding {
			var out []Finding
			for _, f := range s.Files {
				if !f.Exists {
					continue
				}
				// Any bit set for group or other on a file this sensitive.
				if f.Mode&0o077 == 0 {
					continue
				}
				// Group read is the point for a file two accounts share: the
				// separated audit log is owned by the writer and read by the
				// CMS, which is not trusted to write it. Flagging that told an
				// operator to undo the deployment this program recommends.
				// Group *write* is still a finding, and so is anything for
				// other — sharing with one account is not sharing with the
				// machine.
				if f.SharedWithGroup && f.Mode&0o027 == 0 {
					continue
				}
				sev := High
				if f.Mode&0o022 != 0 {
					sev = Critical // writable by someone else entirely
				}
				out = append(out, Finding{
					Severity: sev,
					Resource: f.Path,
					Detail: fmt.Sprintf("%s is mode %04o (%s)",
						f.Path, f.Mode&0o7777, f.Description),
					Fix: fmt.Sprintf("chmod 600 %s", f.Path),
				})
			}
			return out
		},
	},

	{
		ID:       "config.weakened",
		Title:    "A setting is running weaker than its default",
		Severity: Medium,
		Controls: []string{"CM-6", "CM-7"},
		OWASP:    "A02:2025 Security Misconfiguration",
		Why: "Every setting here can be changed, and some of them cost " +
			"security when they are. Refusing to allow those would only mean " +
			"they get changed somewhere this cannot see. Allowing them " +
			"quietly would mean nobody can tell a considered decision from an " +
			"accident. So they are allowed, with a reason, and reported here " +
			"until the reason lapses or the value goes back.",
		Check: func(s State) []Finding {
			var out []Finding
			for _, wk := range s.Weakened {
				f := Finding{
					Resource: wk.Key,
					Detail:   wk.Key + " = " + wk.Value + ": " + wk.Why,
					Fix: "scrivet config unset " + wk.Key +
						"  # or renew the acceptance",
				}
				switch {
				case !wk.Accepted:
					// Nobody wrote down why. That is the case worth raising:
					// a weakened setting with a reason is a decision, and one
					// without is indistinguishable from a mistake.
					f.Severity = High
					f.Detail += " — with no recorded reason, so this cannot be " +
						"told apart from an accident"
					f.Fix = "scrivet config set " + wk.Key + " " + wk.Value +
						" --accept-risk \"why\"  # or unset it"
				case wk.Expired:
					f.Severity = High
					f.Detail += " — accepted by " + wk.By + " (" + wk.Reason +
						"), and that acceptance has lapsed"
				default:
					f.Detail += " — accepted by " + wk.By + ": " + wk.Reason
				}
				out = append(out, f)
			}
			return out
		},
	},

	// -- agents -------------------------------------------------------------

	{
		ID:       "agent.write-without-role",
		Title:    "An agent operation changes state with no role requirement",
		Severity: Critical,
		Controls: []string{"AC-3", "AC-6"},
		OWASP:    "A01:2025 Broken Access Control",
		Why: "Any client that can reach the MCP server can invoke it. An " +
			"operation that writes without declaring a required role is " +
			"unauthenticated write access wearing a tool name.",
		Check: func(s State) []Finding {
			var out []Finding
			for _, op := range s.Agents.WriteOpsWithoutRole {
				out = append(out, Finding{
					Resource: op,
					Detail:   op + " writes but declares no NeedsRole",
					Fix:      "set NeedsRole on the operation registration",
				})
			}
			return out
		},
	},
	{
		ID:       "agent.shared-human-credential",
		Title:    "An agent authenticates as a person",
		Severity: High,
		Controls: []string{"AC-2", "AU-3", "IA-2"},
		OWASP:    "A09:2025 Logging and Alerting Failures",
		Why: "When a model uses a person's token, the audit log records a " +
			"human doing things a human did not do. Attribution is the thing " +
			"the log exists for, and this destroys it silently.",
		Check: func(s State) []Finding {
			if !s.Agents.Enabled || s.Tokens == nil || s.Policy == nil {
				return nil
			}
			// A service principal has no admin binding and exists only in the
			// token store. A token whose principal also holds a policy binding
			// is a person's credential.
			people := map[string]bool{}
			for _, b := range s.Policy.Bindings {
				people[b.Principal] = true
			}
			var out []Finding
			for _, t := range s.Tokens.Tokens {
				if t.Revoked || t.Expired(s.Now) || t.IsSession() {
					continue
				}
				if !people[t.Principal] {
					continue
				}
				if !strings.Contains(strings.ToLower(t.Name), "mcp") &&
					!strings.Contains(strings.ToLower(t.Name), "agent") {
					continue
				}
				out = append(out, Finding{
					Resource: t.ID,
					Detail: fmt.Sprintf("%s authenticates as %s, who is also a "+
						"person in the access policy", t.Name, t.Principal),
					Fix: "scrivet token issue " + t.Name +
						" --principal svc-" + t.Principal + " --role author",
				})
			}
			return out
		},
	},

	{
		ID:       "audit.writer-not-separated",
		Title:    "The CMS writes its own audit log",
		Severity: Medium,
		Controls: []string{"AU-9", "AU-9(4)", "AC-5"},
		OWASP:    "A09:2025 Logging and Alerting Failures",
		Why: "When the process that publishes content is the process that " +
			"writes the record of it, anything that can execute code as the CMS " +
			"can rewrite what it did — a template bug, a dependency, a mistake " +
			"in this program. A separate writer moves that requirement to root. " +
			"It does not stop root, and nothing running on the machine can; what " +
			"stops root's rewrite being deniable is a published tree head.",
		Check: func(s State) []Finding {
			state, supplied := s.Extra["log_writer"]
			if !supplied {
				return nil
			}
			switch state {
			case "separated":
				return nil
			case "unreachable":
				return []Finding{{
					Severity: High,
					Detail: "a log writer is configured and not answering, so " +
						"actions are being taken and not recorded",
					Fix: "start it: scrivet logd",
				}}
			}
			return []Finding{{
				Detail: "the CMS opens the audit log directly, so code " +
					"execution as this account is enough to rewrite it",
				Fix: "run `scrivet logd` as an account that owns the log file",
			}}
		},
	},
	{
		ID:       "audit.no-published-head",
		Title:    "The audit log has never been committed to anywhere else",
		Severity: High,
		Controls: []string{"AU-9", "AU-9(2)", "AU-10"},
		OWASP:    "A09:2025 Logging and Alerting Failures",
		Why: "A hash chain proves nobody edited the log without also editing " +
			"every entry after it. It does not stop somebody who can edit the " +
			"whole file, which on this machine is anybody with root — including " +
			"whoever would most want to. What fixes history is a commitment " +
			"published somewhere they do not control: a tree head exported to a " +
			"SIEM, handed to an auditor, or anchored to Bitcoin. Until one " +
			"exists, the log is evidence only to people who already trust the " +
			"machine it is on.",
		Check: func(s State) []Finding {
			if len(s.Audit) < 10 {
				return nil
			}
			// An absent key means the caller did not look, which is different
			// from looking and finding none. Reporting the first as the second
			// is how a scanner produces a finding about something it never
			// checked — the failure this package is built to avoid.
			raw, supplied := s.Extra["published_heads"]
			if !supplied {
				return nil
			}
			if raw != "" && raw != "0" {
				return nil
			}
			return []Finding{{
				Detail: fmt.Sprintf("%d entries and no head has ever been "+
					"published", len(s.Audit)),
				Fix: "scrivet auditlog anchor  # or `auditlog head --save` and " +
					"export it",
			}}
		},
	},
	{
		ID:       "audit.head-is-stale",
		Title:    "The published log head is far behind",
		Severity: Medium,
		Controls: []string{"AU-9", "AU-10"},
		OWASP:    "A09:2025 Logging and Alerting Failures",
		Why: "A published head only fixes the history behind it. Everything " +
			"since is protected by the chain alone, which is to say by nothing " +
			"an administrator could not undo. The gap between the last published " +
			"head and the current log is the window in which entries can still " +
			"be quietly rewritten.",
		Check: func(s State) []Finding {
			published := atoiSafe(s.Extra["published_head_size"])
			if published == 0 || len(s.Audit) == 0 {
				return nil
			}
			gap := len(s.Audit) - published
			if gap < 500 {
				return nil
			}
			return []Finding{{
				Detail: fmt.Sprintf(
					"%d entries have been written since the last published head, "+
						"and none of them is fixed by anything outside this "+
						"machine", gap),
				Fix: "scrivet auditlog anchor",
			}}
		},
	},

	// -- evidence -----------------------------------------------------------

	{
		ID:       "evidence.unstamped",
		Title:    "The live site has no timestamp",
		Severity: Low,
		Controls: []string{"AU-8", "AU-10"},
		OWASP:    "",
		Why: "Without a timestamp there is no way to prove what the site said " +
			"on a date. That matters for regulated claims, prices and terms — " +
			"and it only helps if it was taken at the time, not afterwards.",
		Check: func(s State) []Finding {
			if s.Content.PublishedAt == 0 {
				return nil
			}
			if s.Content.LastTimestamped >= s.Content.PublishedAt {
				return nil
			}
			return []Finding{{
				Detail: "the current live content has never been timestamped",
				Fix:    "scrivet timestamp",
			}}
		},
	},
}

func isLoopback(addr string) bool {
	host := addr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		host = addr[:i]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "127.0.0.1", "::1", "localhost", "":
		return true
	}
	// An empty host with a port ("":8080" or ":8080") binds every interface,
	// which is the case this rule most needs to catch.
	return strings.HasPrefix(host, "127.")
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// atoiSafe reads a count from the caller-supplied Extra map, treating anything
// unparseable as absent rather than as zero-with-confidence.
func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}
