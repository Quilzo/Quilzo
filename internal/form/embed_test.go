package form

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// The markup the screen hands out has to be markup that works.
//
// This is the test that would have caught the original bug, which was not a
// broken check but a missing instruction: a form needs two fields nobody
// declares, both are refused when absent, and their names appeared nowhere
// outside this package's source. A form built entirely through the interface
// could not be made to work, and the error a person got was the one written for
// spam scripts.
//
// So the snippet is parsed back out and fed to the thing that judges real
// submissions. If a field name is renamed here and not there, this fails.

var reNamed = regexp.MustCompile(`name="([^"]+)"`)

func TestTheEmbedSnippetSatisfiesTheChecksItDescribes(t *testing.T) {
	f := &Form{
		Name: "message", Label: "Send a message",
		Notice: "Kept for 90 days.",
		Fields: []Field{
			{Name: "name", Label: "Your name", Kind: Line, Required: true},
			{Name: "email", Label: "Email", Kind: Email, Required: true},
			{Name: "subject", Label: "About", Kind: Choice,
				Choices: []string{"a photo", "something else"}},
			{Name: "body", Label: "Message", Kind: Para},
			{Name: "agree", Label: "I agree", Kind: Agree},
		},
	}
	snippet := Embed(f)

	// Every name the snippet submits, as a browser would send them.
	values := map[string]string{}
	for _, m := range reNamed.FindAllStringSubmatch(snippet, -1) {
		values[m[1]] = ""
	}
	for _, fl := range f.Fields {
		if _, there := values[fl.Name]; !there {
			t.Fatalf("the snippet never submits %q", fl.Name)
		}
	}
	// The two that are the whole point.
	if _, there := values[Honeypot]; !there {
		t.Fatalf("the snippet has no honeypot, so every submission using it "+
			"is refused and nothing says why (want a field named %q)", Honeypot)
	}
	if _, there := values[StampField]; !there {
		t.Fatalf("the snippet has no timestamp, so every submission using it "+
			"is refused and nothing says why (want a field named %q)", StampField)
	}

	// Fill it in the way a person would and submit it to the real check.
	now := time.Now()
	values["name"] = "Ada"
	values["email"] = "ada@example.org"
	values["subject"] = "a photo"
	values["body"] = "Is the harbour one for sale?"
	values["agree"] = "true"
	values[Honeypot] = ""
	values[StampField] = itoa(now.Add(-time.Minute).Unix())

	sub, err := Accept(f, values, "192.0.2.1", now)
	if err != nil {
		t.Fatalf("a submission built from the snippet this product hands out "+
			"was refused: %v", err)
	}
	if sub.Values["name"] != "Ada" {
		t.Errorf("the accepted submission lost a value: %v", sub.Values)
	}
	// The honeypot is not stored: it is not a declared field.
	if _, kept := sub.Values[Honeypot]; kept {
		t.Error("the honeypot was stored as if it were content")
	}
}

// The instructions in the snippet have to be true, not decorative.
func TestTheSnippetSaysWhatTheChecksActuallyRequire(t *testing.T) {
	f := &Form{Name: "x", Fields: []Field{{Name: "a", Kind: Line}}}
	s := Embed(f)

	if !strings.Contains(s, `action="/form/x"`) {
		t.Error("the snippet does not post to the form's own endpoint")
	}
	// A honeypot hidden with display:none is hidden from a screen reader too,
	// so its user fills it in and is silently refused. The snippet must not do
	// that — checked on the style attributes it actually emits, because the
	// comment above them names display:none in order to warn against it and a
	// substring search cannot tell advice from instruction.
	for _, m := range regexp.MustCompile(`style="([^"]*)"`).
		FindAllStringSubmatch(s, -1) {
		if strings.Contains(strings.ReplaceAll(m[1], " ", ""), "display:none") {
			t.Errorf("the snippet hides something with display:none (%q), which "+
				"hides it from people using a screen reader too — they fill it "+
				"in and are refused with no explanation", m[1])
		}
	}
	if !strings.Contains(s, `aria-hidden="true"`) {
		t.Error("the honeypot is not hidden from assistive technology")
	}
	// The stated wait has to be the enforced wait.
	if !strings.Contains(s, itoa(int64(MinFillSeconds))) {
		t.Errorf("the snippet does not state the %d second minimum it is "+
			"describing", MinFillSeconds)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
