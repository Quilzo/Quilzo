package starter

import "testing"

// The attribute scanner is the thing standing between a real breakout and a
// green test, so it needs its own. A check that never fires passes for the
// wrong reason, and this is exactly the shape of test that does that.
func TestTheAttributeScannerTellsInertTextFromALiveHandler(t *testing.T) {
	cases := []struct {
		name  string
		html  string
		fires bool
	}{
		{"escaped quote in a value is inert",
			`<time datetime="&#34; onmouseover=&#34;alert(1)">x</time>`, false},
		{"the same characters in text are inert",
			`<p>" onmouseover="alert(1)</p>`, false},
		{"an unescaped quote closing the value is a breakout",
			`<time datetime="" onmouseover="alert(1)">x</time>`, true},
		{"single-quoted values too",
			`<a href='' onclick='alert(1)'>x</a>`, true},
		{"a handler written directly is a breakout",
			`<img src="x" onerror="alert(1)">`, true},
		{"an attribute merely starting with on is not a handler",
			`<div once="yes" only="no">x</div>`, false},
		{"nothing at all",
			`<p class="lead">Ordinary text.</p>`, false},
	}
	for _, c := range cases {
		got := handlerInTag(c.html) != ""
		if got != c.fires {
			t.Errorf("%s: fired=%v, wanted %v\n  %s", c.name, got, c.fires, c.html)
		}
	}
}
