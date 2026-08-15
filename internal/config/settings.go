package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Every setting, in one table.
//
// A table rather than scattered constants for the same reason the privilege
// table is one: a knob nobody can find is a knob nobody can audit, and
// `scrivet config list` has to be able to print all of them. Adding a setting
// anywhere else in the program is a setting that does not appear here, and a
// test refuses that.
//
// The Weaker functions are the interesting column. They are not "is this
// number bigger" — weaker is not always a direction. A longer token life is
// weaker because a stolen credential lasts longer. A longer lockout is also
// weaker, in the other direction, because it hands an attacker a way to lock
// real users out by failing their logins for them. Both are written out.
var settings = []Setting{
	// -- authentication throttling -------------------------------------------
	{
		Key: "auth.throttle", Kind: Bool, Default: "true",
		Summary:  "slow down repeated authentication failures",
		Controls: []string{"IA-5", "AC-7"},
		OWASP:    "A07:2025 Authentication Failures",
		Why: "NIST SP 800-63B-4 says a verifier SHALL rate-limit failed " +
			"authentication attempts, and it is the single control that " +
			"turns a guessable credential from a certainty into a cost. " +
			"Turning it off means an attacker gets unlimited attempts at " +
			"every token in the store.",
		Weaker: offIsWeaker("failed authentication attempts become unlimited"),
	},
	{
		Key: "auth.throttle.after", Kind: Int, Default: "5",
		Summary:  "failures before delays begin",
		Controls: []string{"AC-7"},
		Why: "ASVS 5.0 asks that more than five failures in an hour on one " +
			"account triggers a reaction. Five is that number. Raising it " +
			"buys tolerance for people who mistype, at the cost of giving an " +
			"attacker that many free attempts per window.",
		Weaker: atMost(10, "an attacker gets %s free attempts before anything "+
			"slows them down; NIST suggests no more than 10"),
	},
	{
		Key: "auth.throttle.ceiling", Kind: Int, Default: "100",
		Summary:  "failures per hour after which nothing is accepted",
		Controls: []string{"AC-7", "IA-5"},
		Why: "ASVS 5.0 puts the ceiling at 100 failed attempts per hour on a " +
			"single account. Past this the account stops answering for the " +
			"rest of the window however long the caller waits.",
		Weaker: atMost(100, "%s failures an hour is above the 100 ASVS 5.0 "+
			"allows, which is enough attempts to matter against a weak secret"),
	},
	{
		Key: "auth.throttle.base", Kind: Duration, Default: "1s",
		Summary: "the first delay, doubling with each further failure",
		Why: "The delay doubles: 1s, 2s, 4s, and so on to the maximum. A " +
			"person who mistyped waits a second; a script trying a dictionary " +
			"is stopped by the same rule without anybody deciding it is an " +
			"attack.",
		Weaker: atLeastDur(time.Second, "a first delay of %s is short enough "+
			"that an attacker barely notices it"),
	},
	{
		Key: "auth.throttle.max", Kind: Duration, Default: "15m",
		Summary:  "the longest a soft lockout lasts",
		Controls: []string{"AC-7"},
		Why: "The delay stops doubling here. This is deliberately not very " +
			"long, because the delay is a cost imposed on whoever is failing " +
			"and an attacker can be failing on somebody else's behalf.",
		Weaker: atMostDur(time.Hour, "a %s soft lockout is long enough to be "+
			"worth triggering deliberately: an attacker who can fail your "+
			"logins for you can keep you out for that long"),
	},
	{
		Key: "auth.lockout.hard", Kind: Bool, Default: "false",
		Summary:  "lock an account outright instead of slowing it down",
		Controls: []string{"AC-7"},
		OWASP:    "A07:2025 Authentication Failures",
		Why: "Off by default, and this is a considered choice rather than a " +
			"weaker one. ASVS 5.0 requires documenting how a design prevents " +
			"malicious account lockout, and a hard lockout is the mechanism " +
			"that makes it possible: anyone who knows a principal's name can " +
			"lock them out by failing authentication on their behalf. The " +
			"soft lockout above costs an attacker the same time and cannot be " +
			"aimed at somebody else. Some compliance regimes ask for a hard " +
			"lockout by name, which is why it is here.",
		// Deliberately not marked weaker. It is a real trade rather than a
		// reduction, and the audit finding it deserves belongs in the posture
		// scan where the DoS consequence can be explained in full.
	},
	{
		Key: "auth.lockout.alert", Kind: Int, Default: "5",
		Summary:  "failures in an hour that raise an audit alert",
		Controls: []string{"AU-6", "SI-4"},
		Why: "ASVS 5.0: more than five failures per hour on one account " +
			"should trigger some reaction. Here the reaction is an audit " +
			"record a SIEM rule can match, because this program does not send " +
			"email and pretending otherwise would be worse.",
		Weaker: atMost(20, "at %s failures an hour, a slow credential-stuffing "+
			"run stays under the alert and is never reported"),
	},

	// -- tokens ---------------------------------------------------------------
	{
		Key: "token.ttl.default", Kind: Duration, Default: "720h",
		Summary:  "how long a new token lasts when no --ttl is given",
		Controls: []string{"IA-5(1)", "AC-2"},
		Why: "Thirty days. Long enough that people are not reissuing weekly, " +
			"short enough that a credential leaked into a shell history stops " +
			"working within a quarter.",
		Weaker: atMostDur(365*24*time.Hour, "a %s default means a leaked "+
			"token stays useful for that long, and nobody rotates what has "+
			"not expired"),
	},
	{
		Key: "token.ttl.max", Kind: Duration, Default: "8760h",
		Summary:  "the longest life any token may be issued with",
		Controls: []string{"IA-5(1)"},
		Why: "A ceiling on --ttl, so a long-lived credential is a decision " +
			"somebody made against a limit rather than a number typed once.",
		Weaker: atMostDur(365*24*time.Hour, "%s is longer than a year, which "+
			"is longer than most people stay in a role"),
	},
	{
		Key: "token.api.ttl.default", Kind: Duration, Default: "1h",
		Summary: "default life of a token scoped for API use",
		Why: "Short, because an API token is issued to a program that can ask " +
			"for another one. This is the setting that makes `--api` tokens " +
			"short-lived without anybody remembering to pass --ttl.",
		Weaker: atMostDur(24*time.Hour, "an API token living %s is a long-"+
			"lived credential in a config file somewhere"),
	},

	// -- the HTTP API ---------------------------------------------------------
	{
		Key: "api.rate.per_minute", Kind: Int, Default: "120",
		Summary:  "requests per minute per token",
		Controls: []string{"SC-5"},
		Why: "Enough for a site build to read every page and its items; not " +
			"enough for one credential to be the load. Raise it for a busy " +
			"integration, and prefer raising it to turning it off.",
		Weaker: atMost(6000, "%s a minute is high enough that one token can "+
			"saturate the server, which is a denial of service with a "+
			"credential attached"),
	},
	{
		Key: "api.rate.burst", Kind: Int, Default: "20",
		Summary: "how far a client may run ahead of the steady rate",
		Why: "A client fetching a listing and then its items in parallel is " +
			"behaving normally and should not be punished for it.",
	},
	{
		Key: "api.page.max", Kind: Int, Default: "100",
		Summary: "the largest page size a listing will answer",
		Why: "Refused rather than clamped when a client asks for more, so a " +
			"client asking for a thousand does not receive a hundred and " +
			"believe it has everything.",
		Weaker: atMost(1000, "a page of %s items is a large response one "+
			"request can ask for repeatedly"),
	},
	{
		Key: "api.body.max_bytes", Kind: Int, Default: "1048576",
		Summary: "the largest request body a write will read",
		Why:     "One megabyte. A page is text; anything larger is a mistake or a probe.",
		Weaker: atMost(16*1024*1024, "%s bytes of request body per call is "+
			"memory an unauthenticated-until-parsed request can ask for"),
	},

	// -- gates ----------------------------------------------------------------
	{
		Key: "publish.require_a11y", Kind: Bool, Default: "true",
		Summary:  "block publishing on accessibility failures",
		Controls: []string{"SI-10"},
		Why: "ATAG Part B asks that an authoring tool help authors produce " +
			"accessible content, and a report printed after publishing helps " +
			"nobody. This is the setting behind --no-a11y-check; turning it " +
			"off here is the same decision made once instead of per command.",
		Weaker: offIsWeaker("inaccessible content publishes without anything " +
			"stopping it, which is a legal exposure in most of the markets " +
			"this will be sold in"),
	},
	{
		Key: "publish.require_types", Kind: Bool, Default: "true",
		Summary:  "content must satisfy its bound type before it is stored",
		Controls: []string{"SI-10"},
		OWASP:    "A03:2025 Injection",
		Why: "The store is immutable, so an invalid page that lands in it is " +
			"in the history for good.",
		Weaker: offIsWeaker("unvalidated content is stored permanently"),
	},
	{
		Key: "review.required_approvals", Kind: Int, Default: "0",
		Summary:  "people who must approve a draft before it publishes",
		Controls: []string{"AC-5", "CM-3"},
		Why: "Zero means no four-eyes requirement, which is right for a " +
			"single-author site and wrong for a regulated one. Two is the " +
			"usual answer where separation of duties is required; authors " +
			"cannot approve their own work at any setting.",
		// Raising it is stronger, lowering it to zero is the default. Nothing
		// to mark.
	},

	// -- the public site ------------------------------------------------------
	{
		Key: "site.csp.mode", Kind: Text, Default: "enforce",
		Summary:  "enforce | report-only | off",
		Controls: []string{"SC-18"},
		OWASP:    "A03:2025 Injection",
		Why: "A Content-Security-Policy is the control that turns a content " +
			"injection into a blocked request instead of script execution. " +
			"report-only is for the week you are working out what your " +
			"content actually references; off is for when something else in " +
			"front is setting the header.",
		Weaker: func(v string) (bool, string) {
			switch v {
			case "off":
				return true, "no Content-Security-Policy is sent, so an " +
					"injected script runs"
			case "report-only":
				return true, "the policy is reported and not enforced, so an " +
					"injected script still runs — this is a migration state, " +
					"not a destination"
			}
			return false, ""
		},
	},
	{
		Key: "site.csp.extra_img", Kind: List, Default: "",
		Summary: "extra hosts permitted in img-src",
		Why: "Generated policies come from what the content references. This " +
			"is for hosts that are referenced by something the generator " +
			"cannot see, such as markup inside a rich text field.",
	},
	{
		Key: "site.csp.extra_frame", Kind: List, Default: "",
		Summary: "extra hosts permitted in frame-src",
		Why: "Embeds the generator cannot see. It reads URL fields and finds " +
			"a YouTube link; it cannot read the inside of a rich text field " +
			"and find an iframe somebody pasted there. Naming the host here " +
			"is narrower than widening frame-src to everything, which is the " +
			"other way people solve this.",
	},
	{
		Key: "site.hsts", Kind: Duration, Default: "0s",
		Summary:  "Strict-Transport-Security max-age; 0 disables the header",
		Controls: []string{"SC-8", "SC-23"},
		Why: "Off by default because this server is usually behind something " +
			"that terminates TLS and should set it there, and because a " +
			"wrongly-set HSTS on a host that later needs plain HTTP is not " +
			"quickly undone. Set it here when this process is the edge.",
	},

	// -- media ----------------------------------------------------------------
	{
		Key: "media.max_width", Kind: Int, Default: "2400",
		Summary: "widest an uploaded image is stored at; 0 keeps the original",
		Why: "A six-thousand-pixel photograph shown in an eight-hundred-pixel " +
			"column is the actual page weight, and no codec recovers it. 2400 " +
			"is generous for a hero image on a high-density display and still " +
			"a fraction of what a modern camera produces.",
	},
	{
		Key: "media.max_height", Kind: Int, Default: "2400",
		Summary: "tallest an uploaded image is stored at; 0 keeps the original",
		Why: "The other dimension, so a very tall image is bounded too. " +
			"Aspect ratio is always preserved.",
	},
	{
		Key: "media.jpeg_quality", Kind: Int, Default: "82",
		Summary: "JPEG quality when an image is re-encoded",
		Why: "82 is where most viewers stop being able to tell and the file is " +
			"roughly half the size of 95. Raise it for photography, lower it " +
			"for thumbnails.",
	},
	{
		Key: "media.webp", Kind: Bool, Default: "false",
		Summary: "convert to WebP when an external encoder is available",
		Why: "Off because it depends on cwebp being installed, and a setting " +
			"that silently does nothing is worse than one that is off. Neither " +
			"WebP nor AVIF is in Go's standard library, so this cannot be done " +
			"in-process without a dependency this program does not have. " +
			"Metadata stripping and resizing happen either way, and between " +
			"them they are usually the larger saving.",
	},
	{
		Key: "media.strip_metadata", Kind: Bool, Default: "true",
		Summary:  "remove EXIF and other embedded metadata from images",
		Controls: []string{"SI-12", "PM-30"},
		Why: "A photograph from a phone carries GPS coordinates, a device " +
			"serial number, and often a full-size embedded thumbnail that " +
			"survives cropping. Publishing an author's home address alongside " +
			"their article is a worse failure than serving a file that is 20% " +
			"too large, and it is the one nobody notices.",
		Weaker: offIsWeaker("uploaded photographs keep their GPS coordinates " +
			"and device identifiers, which are then published"),
	},

	// -- extensions -----------------------------------------------------------
	{
		Key: "ext.enabled", Kind: Bool, Default: "false",
		Summary:  "run extensions",
		Controls: []string{"CM-7", "SI-7"},
		Why: "Off until somebody turns it on. An extension is third-party " +
			"code running beside the content store, and the honest default " +
			"for that is not-running.",
	},
	{
		Key: "ext.timeout", Kind: Duration, Default: "5s",
		Summary: "how long an extension may take before it is killed",
		Why: "An extension that hangs must not hang a publish. The operation " +
			"continues without it and the failure is recorded.",
		Weaker: atMostDur(60*time.Second, "an extension may hold an operation "+
			"for %s, which is long enough to be a denial of service by "+
			"accident"),
	},
	{
		Key: "ext.max_output_bytes", Kind: Int, Default: "1048576",
		Summary: "the largest response an extension may return",
		Why:     "Bounded, because the extension chooses how much to send back.",
	},
	{
		Key: "ext.require_pinned", Kind: Bool, Default: "true",
		Summary:  "extensions must match a recorded hash",
		Controls: []string{"SI-7", "CM-14"},
		OWASP:    "A08:2025 Software and Data Integrity Failures",
		Why: "The binary that runs is the binary that was reviewed. Without " +
			"this, replacing the file on disk replaces the code with no " +
			"record and no signal.",
		Weaker: offIsWeaker("an extension binary can be swapped on disk and " +
			"will run without anybody being told"),
	},
}

// -- the shapes a floor takes ------------------------------------------------

func offIsWeaker(cost string) func(string) (bool, string) {
	return func(v string) (bool, string) {
		if b, err := strconv.ParseBool(v); err == nil && !b {
			return true, cost
		}
		return false, ""
	}
}

func atMost(limit int, format string) func(string) (bool, string) {
	return func(v string) (bool, string) {
		n, err := strconv.Atoi(v)
		if err != nil || n <= limit {
			return false, ""
		}
		return true, fmt.Sprintf(format, v)
	}
}

func atMostDur(limit time.Duration, format string) func(string) (bool, string) {
	return func(v string) (bool, string) {
		d, err := time.ParseDuration(v)
		if err != nil || d <= limit {
			return false, ""
		}
		return true, fmt.Sprintf(format, d)
	}
}

func atLeastDur(limit time.Duration, format string) func(string) (bool, string) {
	return func(v string) (bool, string) {
		d, err := time.ParseDuration(v)
		if err != nil || d >= limit {
			return false, ""
		}
		return true, fmt.Sprintf(format, d)
	}
}

// -- lookup -------------------------------------------------------------------

// Lookup finds a setting by key.
func Lookup(key string) (Setting, bool) {
	for _, s := range settings {
		if s.Key == key {
			return s, true
		}
	}
	return Setting{}, false
}

// All returns every setting.
func All() []Setting { return append([]Setting(nil), settings...) }

// Validate checks a value against a setting's kind.
func (s Setting) Validate(v string) error {
	switch s.Kind {
	case Int:
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%q is not a number", v)
		}
		if n < 0 {
			return fmt.Errorf("%d is negative", n)
		}
	case Duration:
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%q is not a duration (try 30s, 15m, 720h)", v)
		}
		if d < 0 {
			return fmt.Errorf("%s is negative", d)
		}
	case Bool:
		if _, err := strconv.ParseBool(v); err != nil {
			return fmt.Errorf("%q is not true or false", v)
		}
	case Text:
		if s.Key == "site.csp.mode" {
			switch v {
			case "enforce", "report-only", "off":
			default:
				return fmt.Errorf("%q is not enforce, report-only or off", v)
			}
		}
	case List:
		for _, p := range strings.Split(v, ",") {
			if strings.ContainsAny(p, " \t\r\n;'\"") {
				return fmt.Errorf("%q contains a character that cannot appear "+
					"in a list entry", p)
			}
		}
	}
	return nil
}

// IsWeaker reports whether a value gives up security relative to the default.
func (s Setting) IsWeaker(v string) (bool, string) {
	if s.Weaker == nil {
		return false, ""
	}
	return s.Weaker(v)
}
