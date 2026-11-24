// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/pay"
	"github.com/quilzo/quilzo/internal/schedule"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// A terminal is not a text box.
//
// Content is written by whoever can write content, which on a site with
// contributors is not the person running the command. A string carrying ESC
// sequences can move the cursor, clear the line above, or change what is
// already on screen — so a page whose body begins with the right escape makes
// `quilzo search` print something other than what is in the store, and the
// operator reading the output has no way to tell.
func TestContentCannotDriveTheTerminal(t *testing.T) {
	attacks := map[string]string{
		"clear the line above": "\x1b[1A\x1b[2Kall clear, nothing to see",
		"colour the output":    "\x1b[31mFAILED\x1b[0m",
		"set the window title": "\x1b]0;something else\x07",
		"carriage return":      "real text\rforged text",
		"a bare escape":        "\x1bZ",
		"a C1 escape":          "\u009bJ",
		"a null":               "text\x00more",
	}
	for name, payload := range attacks {
		got := forTerminal(payload)
		for _, r := range got {
			if (r < 0x20 && r != '\t' && r != '\n') || r == 0x7f ||
				(r >= 0x80 && r <= 0x9f) {
				t.Errorf("%s: %q still carries control character %U",
					name, got, r)
			}
		}
	}
}

// The text itself survives, which is the point of printing it.
func TestOrdinaryContentIsUnchanged(t *testing.T) {
	for _, s := range []string{
		"a perfectly ordinary excerpt",
		"indigo, woad and madder — dyed in a railway arch",
		"a tab\tand a newline\nsurvive",
		"日本語のテキストも",
		"emoji stay too 🪴",
	} {
		if got := forTerminal(s); got != s {
			t.Errorf("ordinary text was changed:\n  in:  %q\n  out: %q", s, got)
		}
	}
}

// A control character is replaced rather than dropped, because content that
// contained one is a fact worth seeing — dropping it hides both the escape and
// the reason somebody put it there.
func TestAStrippedEscapeLeavesAMark(t *testing.T) {
	got := forTerminal("before\x1b[31mafter")
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Fatalf("the surrounding text was lost: %q", got)
	}
	if got == "beforeafter" {
		t.Error("the escape vanished without trace; a reader cannot tell " +
			"the content carried one")
	}
}

// A value printed inside a line cannot start a line of its own.
func TestAValuePrintedInsideALineStaysOnIt(t *testing.T) {
	got := onOneLine("missing alt text\nlive is now deadbeef\r\x1b[2K ok")
	if strings.ContainsAny(got, "\n\r\x1b") {
		t.Errorf("a line break or an escape survived: %q", got)
	}
	if !strings.Contains(got, "missing alt text") || !strings.Contains(got, "deadbeef") {
		t.Errorf("the text itself was lost: %q", got)
	}
	if onOneLine("an ordinary sentence, with a tab\there") != "an ordinary sentence, with a tab\there" {
		t.Error("an ordinary value was changed")
	}
}

// A rendered page written to a file is the page, byte for byte. Only a
// person's terminal gets the control characters made visible.
func TestARenderedPageIsWrittenExactlyWhenItIsNotForAPerson(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "page")
	if err != nil {
		t.Fatal(err)
	}
	page := "<p>a\x1b]0;owned\x07 page</p>\n"
	writeRendered(f, page)
	f.Close()
	got, _ := os.ReadFile(f.Name())
	if string(got) != page {
		t.Errorf("written to a file the page became %q", got)
	}
}

// forged is what somebody else writes to make a line of the owner's
// terminal say something else: up a line, clear it, retitle the window,
// and a C1 escape that clears the screen.
const forged = "\x1b[1A\x1b[2K\x1b]0;owned\x07\u009b2J"

// mustPrintAsText runs a command for a person and fails if what it printed
// carries a control character (controlIn), or lost the words around it.
func mustPrintAsText(t *testing.T, what, want string, run func() error) {
	t.Helper()
	got, err := humanOutput(t, run)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if c := controlIn(got); c != "" {
		t.Errorf("%s printed the control character %s from what somebody else wrote:\n%q", what, c, got)
	}
	if !strings.Contains(got, want) {
		t.Errorf("%s lost %q:\n%q", what, want, got)
	}
}

// What somebody else wrote reaches the owner's terminal as text.
//
// An anonymous visitor's question that a chatbot could not answer, a
// colleague's note on the page they claimed, the page and the name it was
// claimed under, the message a draft was saved with and the note an
// approval was given with, and the note a publish was scheduled with,
// were each printed as they were kept. So an escape in any of them, typed
// into the public chatbot or saved by anybody who can claim a page or
// write a draft, cleared a line of `quilzo assistant gaps`, `lock list`,
// `lock`, the notice a write gives of somebody's claim, `review status` or
// `schedule list`, and wrote another in its place.
func TestWhatOthersWroteCannotDriveTheTerminal(t *testing.T) {
	root := publishedShop(t)
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help"}); err != nil {
		t.Fatal(err)
	}
	keepGaps(t, root)
	gapKeeper(root)("help", "Are you open on Sunday?"+forged+" asks the owner")
	mustPrintAsText(t, "assistant gaps", "Are you open on Sunday?", func() error {
		return cmdAssistant(root, []string{"gaps", "help"})
	})

	until := time.Now().Add(time.Hour).Unix()
	if err := saveJSON(locksPath(root), &collab.Locks{Locks: []collab.Lock{
		{Page: "about", Holder: "pat", Note: "rewriting it" + forged, Since: time.Now().Unix(), Until: until},
		{Page: "contact" + forged, Holder: "pat" + forged, Note: "x", Since: time.Now().Unix(), Until: until},
	}}); err != nil {
		t.Fatal(err)
	}
	mustPrintAsText(t, "lock list", "rewriting it", func() error { return cmdLock(root, []string{"list"}) })
	mustPrintAsText(t, "lock", "rewriting it", func() error {
		return cmdLock(root, []string{"about", "--note", "fixing a typo"})
	})
	mustPrintAsText(t, "a write's notice of a claim", "has claimed contact", func() error {
		sayClaims(claimsByOthers(root, "dana", []string{"contact" + forged}))
		return nil
	})

	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := site.PagesAt(s, site.RefLive)
	if err != nil {
		t.Fatal(err)
	}
	pages["returns"] = map[string]any{"title": "Returns", "body": "Unopened items within 60 days."}
	draft, err := site.SaveDraft(s, pages, "Longer returns"+forged, "pat")
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(proposalsPath(root), &proposalFile{Proposals: []collab.Proposal{{
		Content: draft, Author: "pat", AuthorKind: "human", Message: "Longer returns" + forged,
		Approvals: []collab.Approval{{Content: draft, By: "kit", At: time.Now().Unix(), Note: "read it" + forged}},
	}}}); err != nil {
		t.Fatal(err)
	}
	mustPrintAsText(t, "review status", "Longer returns", func() error {
		return cmdReview(root, []string{"status"})
	})

	if err := saveJSON(schedulePath(root), &schedule.Schedule{Entries: []schedule.Entry{{
		Commit: draft, At: time.Now().Add(48 * time.Hour).Unix(), By: "pat" + forged,
		Note: "for the sale" + forged, UnmarkedReason: "imported" + forged,
	}}}); err != nil {
		t.Fatal(err)
	}
	mustPrintAsText(t, "schedule list", "for the sale", func() error { return scheduleList(root) })
}

// A buyer's name, address and email are what they typed at the provider's
// checkout, and `quilzo pay orders` printed them as the provider sent
// them, so an escape in the name a buyer gave cleared the line above.
func TestABuyersDetailsCannotDriveTheTerminal(t *testing.T) {
	root, prov := shopStore(t)
	on, err := requestPay(root, dual.PayChange{Provider: pay.ProviderStripe, ShipTo: []string{"GB"}}, "", asAdmin("dana"))
	if err != nil || !on {
		t.Fatalf("turning payments on: %v %v", on, err)
	}
	prov.orders = []pay.Order{{Ref: "cs_1", Amount: 2400, Currency: "GBP", Paid: true, Link: "plink_1",
		Name: "Ana Diaz" + forged, Email: "ana@example.com" + forged, Ship: "4 Mill Lane" + forged}}
	mustPrintAsText(t, "pay orders", "Ana Diaz", func() error {
		return payOrders(root, nil, asAdmin("dana"))
	})
}
