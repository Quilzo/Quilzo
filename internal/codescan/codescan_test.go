package codescan

import (
	"strings"
	"testing"
)

func scan(kind Kind, body string) []Finding {
	return Scan([]Input{{Name: "x", Kind: kind, Body: body}})
}

func has(f []Finding, rule string) *Finding {
	for i := range f {
		if f[i].Rule == rule {
			return &f[i]
		}
	}
	return nil
}

// -- what it must find --------------------------------------------------------

func TestItFindsTheWaysAValueBecomesScript(t *testing.T) {
	for _, tc := range []struct {
		rule string
		kind Kind
		body string
	}{
		{"xss.raw-output", Template, `<div>{% raw page.body_html %}</div>`},
		{"xss.event-handler", Template, `<img src=x onerror="steal()">`},
		{"xss.script-in-content", Content, `Hello <script>alert(1)</script>`},
		{"xss.javascript-url", Content, `<a href="javascript:alert(1)">x</a>`},
		{"xss.srcdoc", Template, `<iframe srcdoc="<script>x</script>">`},
		{"xss.dangerous-sink", Template, `el.innerHTML = value`},
		{"template.autoescape-off", Template, `{{ value | safe }}`},
	} {
		if has(scan(tc.kind, tc.body), tc.rule) == nil {
			t.Errorf("%s did not fire on: %s", tc.rule, tc.body)
		}
	}
}

func TestItFindsCredentials(t *testing.T) {
	for _, tc := range []struct {
		rule string
		body string
	}{
		{"secret.private-key", "-----BEGIN RSA PRIVATE KEY-----"},
		{"secret.quilzo-token", "token: qz_6zukocv7ecidrejjyojgsdn7ekl3w2v3qph3ef6ylsm6usaqbtdq"},
		{"secret.cloud-key", "aws: AKIAIOSFODNN7EXAMPLE"},
		{"secret.cloud-key", "gh: ghp_16CharsAndThenSomeMoreCharacters1234"},
		{"secret.connection-string", "postgres://admin:hunter2ButLonger@db.internal/app"},
		{"secret.assignment", `api_key = "9f8Xq2LmR7vT4wZ1pK6nD3sB5yH0jC8e"`},
	} {
		if has(scan(Config, tc.body), tc.rule) == nil {
			t.Errorf("%s did not fire on: %s", tc.rule, tc.body)
		}
	}
}

func TestItFindsInternalAddressesInContent(t *testing.T) {
	for _, body := range []string{
		"See http://169.254.169.254/latest/meta-data/",
		"http://localhost:8080/admin",
		"https://10.1.2.3/internal",
	} {
		if has(scan(Content, body), "network.internal-url") == nil {
			t.Errorf("no finding for %q", body)
		}
	}
}

// -- what it must NOT find ----------------------------------------------------
//
// This half matters more. A scanner that cries wolf is a scanner somebody
// disables in CI, and then it finds nothing at all.

func TestPlaceholdersAreNotCredentials(t *testing.T) {
	for _, body := range []string{
		`api_key = "your-api-key-here"`,
		`secret: "changeme-please-change-me"`,
		`token = "{{ env.API_TOKEN }}"`,
		`password = "<redacted for the docs>"`,
		`api_key = "EXAMPLE_KEY_DO_NOT_USE"`,
		`secret = "${VAULT_SECRET}"`,
		`token = "short"`,
	} {
		if f := has(scan(Config, body), "secret.assignment"); f != nil {
			t.Errorf("a placeholder was reported as a credential: %s", body)
		}
	}
}

// An article about HTML is not an XSS finding. This is the distinction that
// decides whether a content scanner is usable at all on a CMS, whose entire
// purpose is storing text about things.
func TestProseAboutMarkupIsNotAFinding(t *testing.T) {
	body := "To embed a video, paste the URL into the field. Avoid onclick " +
		"handlers and never use innerHTML with untrusted values."
	f := scan(Content, body)
	for _, x := range f {
		if strings.HasPrefix(x.Rule, "xss.") && x.Rule != "xss.dangerous-sink" {
			t.Errorf("prose produced %s: %s", x.Rule, x.Excerpt)
		}
	}
}

// A template legitimately containing the word "script" in text is fine; only
// an actual tag in a *content field* is a finding.
func TestATemplateMayMentionScriptTags(t *testing.T) {
	if has(scan(Template, `<p>Use the &lt;script&gt; tag carefully</p>`),
		"xss.script-in-content") != nil {
		t.Error("escaped markup in a template was reported")
	}
}

// -- the secret is never printed ----------------------------------------------

// Printing the secret copies it into the CI log, which is read by more people
// than the file it came from and kept longer.
func TestACredentialIsNeverEchoedBack(t *testing.T) {
	secret := "9f8Xq2LmR7vT4wZ1pK6nD3sB5yH0jC8e"
	f := scan(Config, `api_key = "`+secret+`"`)
	if len(f) == 0 {
		t.Fatal("nothing found")
	}
	for _, x := range f {
		if strings.Contains(x.Excerpt, secret) {
			t.Errorf("the scanner printed the credential it found: %s", x.Excerpt)
		}
		if !strings.Contains(x.Excerpt, "redacted") {
			t.Errorf("the excerpt does not show it was redacted: %q", x.Excerpt)
		}
	}
	// The same for tokens matched as a whole rather than as an assignment.
	f = scan(Config, "qz_6zukocv7ecidrejjyojgsdn7ekl3w2v3qph3ef6ylsm6usaqbtdq")
	for _, x := range f {
		if strings.Contains(x.Excerpt, "qz_6zuk") {
			t.Errorf("a token was echoed: %s", x.Excerpt)
		}
	}
}

// -- shape --------------------------------------------------------------------

func TestEveryFindingSaysWhatToDo(t *testing.T) {
	for _, r := range Rules() {
		if len(r.Detail) < 25 {
			t.Errorf("%s does not explain itself", r.ID)
		}
		if len(r.Fix) < 10 {
			t.Errorf("%s has no fix; a finding nobody can act on is noise", r.ID)
		}
		if r.Pattern == nil {
			t.Errorf("%s has no pattern", r.ID)
		}
		if !strings.Contains(r.ID, ".") {
			t.Errorf("%s is not namespaced", r.ID)
		}
	}
}

func TestFindingsAreOrderedWorstFirst(t *testing.T) {
	f := Scan([]Input{
		{Name: "a", Kind: Content, Body: "http://example.com/x"},
		{Name: "b", Kind: Content, Body: "<script>alert(1)</script>"},
	})
	if len(f) < 2 {
		t.Fatalf("%d findings", len(f))
	}
	if f[0].Severity != Critical {
		t.Errorf("the worst finding is not first: %s", f[0].Severity)
	}
	if Worst(f) != Critical {
		t.Errorf("Worst reported %s", Worst(f))
	}
	if n := len(AtLeast(f, High)); n != 1 {
		t.Errorf("AtLeast(High) returned %d", n)
	}
}

func TestFindingsCarryTheLineNumber(t *testing.T) {
	f := scan(Content, "clean\nclean\n<script>alert(1)</script>")
	if len(f) == 0 {
		t.Fatal("nothing found")
	}
	if f[0].Line != 3 {
		t.Errorf("reported line %d, want 3", f[0].Line)
	}
}
