package codescan

import (
	"regexp"
	"strings"
)

// The rules, as data.
//
// Every one names a control and says what to do, because a finding nobody can
// act on is noise and noise is how a scanner ends up permanently disabled in
// CI. Anything that would fire on a page *about* the thing it looks for is
// limited by Kind, which is most of the difference between a scanner people
// keep and one they turn off in the first week.
var rules = []Rule{
	// -- cross-site scripting -------------------------------------------------
	{
		ID: "xss.raw-output", Severity: High,
		Kinds:    []Kind{Template},
		Pattern:  regexp.MustCompile(`\{%\s*raw\s+[^%]*%\}`),
		Controls: []string{"SI-10"},
		OWASP:    "A03:2025 Injection",
		Detail: "this emits a value without escaping it, so whatever is in " +
			"that field becomes markup — and if an author can write the " +
			"field, an author can write a script tag",
		Fix: "drop the raw, or bind the page to a content type so the field " +
			"is validated before it is stored",
	},
	{
		ID: "xss.event-handler", Severity: High,
		Kinds:   []Kind{Template, Content},
		Pattern: regexp.MustCompile(`(?i)\son(click|error|load|mouseover|focus|submit|change|input)\s*=`),
		OWASP:   "A03:2025 Injection",
		Detail: "an inline event handler runs script. Under the generated " +
			"Content-Security-Policy it will not execute, which means it is " +
			"either dead markup or the policy is the only thing stopping it",
		Fix: "move the behaviour into a script file served from this origin",
	},
	{
		ID: "xss.script-in-content", Severity: Critical,
		Kinds:   []Kind{Content},
		Pattern: regexp.MustCompile(`(?i)<\s*(script|iframe|object|embed)\b`),
		OWASP:   "A03:2025 Injection",
		Detail: "a content field contains an executable or embedding tag. " +
			"Content is data; when it carries its own markup, whoever can " +
			"edit the content can change what the page does",
		Fix: "remove it, or use a field of a type that is escaped on output",
	},
	{
		ID: "xss.javascript-url", Severity: Critical,
		Pattern: regexp.MustCompile(`(?i)(?:href|src|action|formaction)\s*=\s*["']?\s*(?:javascript|vbscript|data:text/html)\s*:`),
		OWASP:   "A03:2025 Injection",
		Detail: "an executable URL scheme in a link or source attribute runs " +
			"when a visitor clicks it",
		Fix: "use an http(s) or relative URL",
	},
	{
		ID: "xss.srcdoc", Severity: High,
		Pattern: regexp.MustCompile(`(?i)\bsrcdoc\s*=`),
		OWASP:   "A03:2025 Injection",
		Detail: "srcdoc puts markup inside a frame, which is a second document " +
			"with its own scripts and is easy to miss when reviewing a page",
		Fix: "load the frame from a URL, so the content has an origin",
	},
	{
		ID: "xss.dangerous-sink", Severity: High,
		Kinds:   []Kind{Template, Content},
		Pattern: regexp.MustCompile(`\b(innerHTML|outerHTML|document\.write|eval|setTimeout\s*\(\s*["'])`),
		OWASP:   "A03:2025 Injection",
		Detail: "this assigns text to a place the browser parses as markup or " +
			"code, which turns any value that reaches it into script",
		Fix: "use textContent, or a template, rather than assigning markup",
	},

	// -- injection into somebody else's system --------------------------------
	//
	// There is no SQL in this program: the store is content-addressed files,
	// with no database, no query builder and no driver. A rule matching SELECT
	// statements would fire on an article about SQL and never on anything
	// exploitable. What is real is a connection string in the content, because
	// that is a credential leaving through the CMS.
	{
		ID: "secret.connection-string", Severity: Critical,
		Pattern:  regexp.MustCompile(`(?i)\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@`),
		Controls: []string{"IA-5", "SC-28"},
		OWASP:    "A05:2025 Security Misconfiguration",
		Detail: "a database connection string with a password in it. This " +
			"program has no database — which means this is somebody else's " +
			"credential, stored in content that gets published",
		Fix: "remove it and rotate the credential; it should be in the " +
			"environment of whatever connects, not in a page",
	},
	{
		ID: "injection.template-in-content", Severity: Medium,
		Kinds:   []Kind{Content},
		Pattern: regexp.MustCompile(`\{\{[^}]*\}\}|\{%[^%]*%\}|\$\{[^}]*\}|<%[^%]*%>`),
		OWASP:   "A03:2025 Injection",
		Detail: "a content field contains template syntax. This program does " +
			"not evaluate content as a template, so it is inert here — but it " +
			"is not inert in whatever consumes the API, and server-side " +
			"template injection in the consumer is remote code execution",
		Fix: "escape it, or confirm the consumer treats API values as data",
	},

	// -- credentials -----------------------------------------------------------
	{
		ID: "secret.private-key", Severity: Critical,
		Pattern:  regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----`),
		Controls: []string{"IA-5", "SC-12"},
		OWASP:    "A05:2025 Security Misconfiguration",
		Detail: "a private key, in a file that is stored forever and probably " +
			"published. Whatever it authenticated to should be treated as " +
			"compromised from the moment this was written",
		Fix: "remove it and rotate the key; it is in the published history for good",
	},
	{
		ID: "secret.quilzo-token", Severity: Critical,
		Pattern:  regexp.MustCompile(`\bqz_[a-z0-9]{40,}\b`),
		Controls: []string{"IA-5"},
		Detail: "a quilzo token. Tokens are shown once and stored as a hash " +
			"precisely so they do not end up in files",
		Fix: "quilzo token revoke <id>, then issue a new one",
	},
	{
		ID: "secret.cloud-key", Severity: Critical,
		// The formats that are genuinely recognisable. A prefix and a length
		// is a real signal; "looks random" is not, and the rules below are
		// where that distinction is enforced.
		Pattern:  regexp.MustCompile(`\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{32,}|glpat-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})\b`),
		Controls: []string{"IA-5"},
		OWASP:    "A05:2025 Security Misconfiguration",
		Detail:   "a credential for a third-party service",
		Fix:      "revoke it at the provider and remove it from the content",
	},
	{
		ID: "secret.assignment", Severity: High,
		// The catch-all, and the one that needs confirming. A bare
		// high-entropy string is as likely to be a hash, an id or a base64
		// thumbnail as a key.
		Pattern:  regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|passwd|password|credential|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*["'` + "`" + `]?[A-Za-z0-9+/_=-]{16,}`),
		Confirm:  looksSecret,
		Controls: []string{"IA-5"},
		OWASP:    "A05:2025 Security Misconfiguration",
		Detail: "this looks like a credential assigned to a name, and the " +
			"value has enough entropy not to be a placeholder",
		Fix: "move it out of the content; if it was ever committed, rotate it",
	},

	// -- what the content points at -------------------------------------------
	{
		ID: "network.internal-url", Severity: High,
		Pattern:  regexp.MustCompile(`(?i)https?://(127\.0\.0\.1|localhost|169\.254\.169\.254|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|\[::1\])`),
		Controls: []string{"SC-7"},
		OWASP:    "A10:2025 Server-Side Request Forgery",
		Detail: "content pointing at an internal address. Published, it is a " +
			"broken link; fetched by something server-side, it is a request " +
			"to the inside of the network made on an attacker's behalf",
		Fix: "use the address the content is actually reachable at",
	},
	{
		ID: "network.cleartext-url", Severity: Low,
		Kinds:   []Kind{Content, Config},
		Pattern: regexp.MustCompile(`\bhttp://[a-z0-9.-]+\.[a-z]{2,}`),
		OWASP:   "A02:2025 Security Misconfiguration",
		Detail: "a plain-HTTP link. It can be modified in transit, and under " +
			"the generated policy a mixed-content image will not load",
		Fix: "use https, or confirm the host genuinely has no TLS",
	},

	// -- CSS, which HTML escaping does not cover ------------------------------
	//
	// A value interpolated into a style attribute is escaped for HTML and that
	// is the wrong escaping. `50; background-image: url(https://elsewhere/x)`
	// contains nothing HTML-escaping touches and is a CSS injection — and the
	// policy this program builds cannot see it, because it walks content for
	// URLs and does not parse CSS.
	//
	// The fix is not a sanitiser. It is a filter that cannot return anything
	// but a number: `round` refuses a non-numeric value outright, so the
	// render fails instead of the property being set to something else. Every
	// chart in the shipped layouts goes through it, and this rule is what makes
	// that a property of anybody's layout rather than a habit of ours.
	{
		ID: "css.unfiltered-interpolation", Severity: High,
		Kinds:    []Kind{Template},
		Pattern:  regexp.MustCompile(`(?i)style\s*=\s*["'][^"']*\{\{[^}]*\}\}`),
		Controls: []string{"SI-10"},
		OWASP:    "A03:2025 Injection",
		Confirm:  needsNumericFilter,
		Detail: "a value is interpolated into a style attribute without a " +
			"filter that guarantees a number. HTML escaping is not CSS " +
			"escaping: a field holding `50; background-image: url(...)` " +
			"becomes a declaration, and the generated policy cannot help " +
			"because it reads content for URLs and does not parse CSS",
		Fix: "put the value through a numeric filter — style=\"--pct:{{ x | " +
			"round }}\" — which refuses anything that is not a number, or use " +
			"a class from a closed-set field instead of a raw value",
	},

	// -- the template's own escaping ------------------------------------------
	{
		ID: "template.autoescape-off", Severity: Critical,
		Kinds:   []Kind{Template},
		Pattern: regexp.MustCompile(`(?i)(autoescape\s*(=|:)\s*(off|false|0)|\|\s*safe\b|\|\s*raw\b)`),
		OWASP:   "A03:2025 Injection",
		Detail: "escaping is switched off. This is not a directive this " +
			"program's templates have, which means the file was written for a " +
			"different engine and will not do what its author expects here",
		Fix: "use {% raw field %} if unescaped output is genuinely intended",
	},
}

// needsNumericFilter reports whether a style interpolation is unguarded.
//
// A match is only a finding when the expression does not end in a filter that
// can return nothing but a number. `round` and `count` both refuse or convert,
// so a value that reaches the property through either is a numeral or the render
// already failed — which is the outcome this rule wants and should not then
// complain about.
func needsNumericFilter(match string) bool {
	for _, guard := range []string{"|round", "| round", "|count", "| count"} {
		if strings.Contains(match, guard) {
			return false
		}
	}
	return true
}

// Rules returns every rule, for `quilzo scan --rules`.
func Rules() []Rule { return append([]Rule(nil), rules...) }
