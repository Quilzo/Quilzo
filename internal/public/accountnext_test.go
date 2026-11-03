// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// After a member signs in, the page goes where ?next= says only when that is
// on this site.
//
// The script checked the value as text: one slash, not two, no backslash.
// The browser's URL parser drops tabs and newlines before it looks for a
// host, so "/\t/evil.example/phish" passed the check and was then read as
// "//evil.example/phish", another site, straight after a real sign-in: a
// link to the genuine site that ends on a page asking for a card number. So
// this runs the shipped script, the bytes the page carries, under Node,
// presses sign in with the passkey prompt and the server stood in for, and
// resolves where the page was sent the way location.assign does.
func TestSigningInGoesOnlyToThisSite(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is not installed, and CI must run this test")
		}
		t.Skip("node is not installed; CI runs this")
	}
	cases := map[string]string{
		"/shop?colour=red#sizes": "https://shop.example/shop?colour=red#sizes",
		"":                       "https://shop.example/account",
		"//evil.example":         "https://shop.example/account",
		"/\\evil.example":        "https://shop.example/account",
		"https://evil.example/":  "https://shop.example/account",
		"/\t/evil.example/phish": "",
		"/\n/evil.example":       "",
		"/\r/evil.example":       "",
		"/.//evil.example":       "",
		"/sh\top":                "",
	}
	var nexts []string
	for n := range cases {
		nexts = append(nexts, n)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "account.js"), []byte(accountJS), 0o600); err != nil {
		t.Fatal(err)
	}
	cj, _ := json.Marshal(nexts)
	if err := os.WriteFile(filepath.Join(dir, "cases.json"), cj, 0o600); err != nil {
		t.Fatal(err)
	}
	harness := `const fs = require("fs"), vm = require("vm"), path = require("path");
const dir = process.argv[2];
const script = fs.readFileSync(path.join(dir, "account.js"), "utf8");
const nexts = JSON.parse(fs.readFileSync(path.join(dir, "cases.json"), "utf8"));
function one(next) {
  return new Promise(function (resolve) {
    const page = new URL("https://shop.example/account");
    if (next !== "") page.searchParams.set("next", next);
    let press = null;
    const said = { textContent: "" };
    const button = { disabled: false, addEventListener: function (type, f) { if (type === "click") press = f; } };
    const g = {
      URL: URL, URLSearchParams: URLSearchParams, atob: atob, btoa: btoa,
      PublicKeyCredential: function () {},
      document: {
        getElementById: function (id) { return id === "signin-button" ? button : id === "account-msg" ? said : null; },
        body: { getAttribute: function () { return null; } }
      },
      location: {
        href: page.href, origin: page.origin, search: page.search,
        assign: function (to) { resolve({ next: next, went: new URL(to, page.href).href }); }
      },
      navigator: { credentials: { get: function () {
        return Promise.resolve({ id: "key", response: {
          clientDataJSON: new ArrayBuffer(1), authenticatorData: new ArrayBuffer(1), signature: new ArrayBuffer(1) } });
      } } },
      fetch: function () {
        return Promise.resolve({ ok: true, json: function () { return Promise.resolve({ challenge: "AAAA", rpId: "shop.example" }); } });
      }
    };
    g.window = g;
    vm.runInNewContext(script, g);
    press();
    setTimeout(function () { resolve({ next: next, went: "", said: said.textContent }); }, 2000);
  });
}
Promise.all(nexts.map(one)).then(function (out) {
  process.stdout.write(JSON.stringify(out), function () { process.exit(0); });
});
`
	if err := os.WriteFile(filepath.Join(dir, "harness.js"), []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, filepath.Join(dir, "harness.js"), dir).Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var got []struct{ Next, Went, Said string }
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("the harness printed %q: %v", out, err)
	}
	if len(got) != len(cases) {
		t.Fatalf("%d answers for %d cases", len(got), len(cases))
	}
	for _, g := range got {
		if g.Went == "" {
			t.Errorf("next=%q: signing in went nowhere (%s)", g.Next, g.Said)
			continue
		}
		u, err := url.Parse(g.Went)
		if err != nil || u.Scheme != "https" || u.Host != "shop.example" {
			t.Errorf("next=%q: signing in sent the member to %s, another site", g.Next, g.Went)
			continue
		}
		if want := cases[g.Next]; want != "" && g.Went != want {
			t.Errorf("next=%q: signing in went to %s, want %s", g.Next, g.Went, want)
		}
	}
}
