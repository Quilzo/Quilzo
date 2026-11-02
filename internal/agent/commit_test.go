// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import "testing"

// What a reason says an action does is read in the form a reason says it
// ("it submits a form", "a form that sends", "it deletes") as well as the
// form a control's name says it ("Submit", "Send", "Delete"). These are
// the reasons the browser, the shell and the desktop cell write.
func TestAReasonIsReadInTheFormItIsWrittenIn(t *testing.T) {
	for _, c := range []struct {
		op, why, want string
	}{
		// A form sent with POST, and a press that sends one however it is
		// reached: a button, a list in it, or Enter in a field of it.
		{"browser_click", `it presses button "Search" on shop.example, and it submits a form`, "sends"},
		{"browser_choose", `it chooses in combobox "Size" on x, and the list belongs to a form that sends, or acts as soon as it changes`, "sends"},
		{"browser_choose", `it chooses in combobox "Size" on x, and the list belongs to a form that sends, and may send it as soon as it changes`, "sends"},
		{"browser_key", `it presses Enter in textbox "Name" on host, and that submits the form it is in`, "sends"},
		{"browser_key", `it presses Enter in textbox "Name" on host, and it submits a form`, "sends"},
		{"browser_key", `with Enter in textbox "Name", it presses button "Go" on host, and it submits a form`, "sends"},
		{"browser_download", `it presses link "Report" on host, and it leads to other.example; this run has read what is not published (crm), and this would send to other.example`, "sends"},
		{"browser_click", `it presses button "Next" on host, and it posts the comment`, "sends"},
		{"browser_click", `it presses button "Next" on host, and it publishes the draft`, "sends"},
		{"browser_click", `it presses button "Next" on host, and it shares the folder`, "sends"},
		{"browser_click", `it presses button "Next" on host, and it invites them`, "sends"},
		{"browser_click", `it presses button "Next" on host, and it signs in`, "sends"},
		{"desktop_key", `it presses Enter in textbox "To", which sends or confirms whatever that control's default is`, "sends"},

		// A form sent with GET only asks for a page, and says so without
		// saying it submits anything; a list that acts on a change acts.
		{"browser_click", `it presses button "Search" on shop.example, and it runs a search: the form only asks for a page, as a link does`, "acts"},
		{"browser_key", `it presses Enter in searchbox "Search" on shop.example, and it runs a search: the form only asks for a page, as a link does`, "acts"},
		{"browser_choose", `it chooses in combobox "Sort by" on shop.example, and the list acts as soon as it changes`, "acts"},

		{"browser_click", `it presses button "Next" on host, and it pays the invoice`, "pays"},
		{"browser_click", `it presses button "Next" on host, and it purchases the plan`, "pays"},
		{"browser_click", `it presses button "Next" on host, and it subscribes to the plan`, "pays"},
		{"browser_click", `it presses button "Next" on host, and it transfers the balance`, "pays"},
		{"browser_click", `it presses button "Next" on host, and it renews the domain`, "pays"},

		{"browser_click", `it presses button "Next" on host, and it deletes the draft`, "deletes"},
		{"browser_click", `it presses button "Next" on host, and it removes the member`, "deletes"},
		{"browser_click", `it presses button "Next" on host, and it cancels the booking`, "deletes"},
		{"browser_click", `it presses button "Next" on host, and it erases the history`, "deletes"},
		{"browser_click", `it presses button "Next" on host, and it deactivates the account`, "deletes"},
		{"browser_click", `it presses button "Next" on host, and it unsubscribes`, "deletes"},
		{"shell_run", "it runs rm -rf build: it deletes or rewrites history, which nothing brings back", "deletes"},

		// Words that name more than they do: a host, a department, a folder.
		{"browser_click", `it presses button "Search" on books.google.com, and it runs a search: the form only asks for a page, as a link does`, "acts"},
		{"browser_click", `it presses button "Search" on booking.example, and it runs a search: the form only asks for a page, as a link does`, "acts"},
		{"browser_click", `it presses button "My orders" on shop.example, and it runs a search: the form only asks for a page, as a link does`, "acts"},
		{"browser_click", `it presses switch "Sent" on mail.example, and it is a switch, which usually takes effect as it is pressed`, "acts"},
		{"shell_run", "it runs sed -i s/a/b/ shared.go: it changes the workspace", "writes"},
	} {
		if got := CommitOf(Action{Op: c.op}, c.why, WaitAsk, false); got != c.want {
			t.Errorf("%s %q commits to %q, not %q", c.op, c.why, got, c.want)
		}
	}
}

// Submitting a form is decided on its own and never earned; a search is
// an action, which may be approved with others and earned. That is the
// whole point of filing the press correctly.
func TestAFormThatSendsIsNeitherBatchedNorEarned(t *testing.T) {
	click := Action{Op: "browser_click", Input: map[string]any{"ref": "e4"}}
	post := `it presses button "Search" on shop.example, and it submits a form`
	get := `it presses button "Search" on shop.example, and it runs a search: the form only asks for a page, as a link does`
	if c := CommitOf(click, post, WaitAsk, false); Batchable(c) || Earnable(click, post, WaitAsk, false) {
		t.Errorf("a press that submits a form (%s) can be batched or earned", c)
	}
	if c := CommitOf(click, get, WaitAsk, false); !Batchable(c) || !Earnable(click, get, WaitAsk, false) {
		t.Errorf("a search (%s) cannot be batched or earned", c)
	}
	enter := Action{Op: "browser_key", Input: map[string]any{"key": "Enter"}}
	if why := `it presses Enter in textbox "Name" on host, and that submits the form it is in`; Earnable(enter, why, WaitAsk, false) {
		t.Error("Enter that submits a form can be earned")
	}
	rm := Action{Op: "shell_run", Input: map[string]any{"argv": []any{"rm", "-rf", "build"}}}
	if Earnable(rm, "it runs rm -rf build: it deletes or rewrites history, which nothing brings back", WaitAsk, false) {
		t.Error("rm -rf can be earned")
	}
}
