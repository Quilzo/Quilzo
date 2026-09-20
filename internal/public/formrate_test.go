// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/throttle"
)

// rateSite is a site with one form and a limiter, and nothing else.
func rateSite(t *testing.T, policy throttle.Policy) (*Site, *form.Store) {
	t.Helper()
	st, _ := setup(t)
	f := &form.Form{
		Name: "enquiry", Label: "Enquiry",
		Notice: "What you send is kept for thirty days and read by one person.",
		Fields: []form.Field{
			{Name: "who", Label: "Who", Kind: form.Line, Required: true},
		},
	}
	set := &form.Set{}
	if err := set.Add(*f); err != nil {
		t.Fatal(err)
	}
	store, err := form.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st.Forms = &Forms{
		Set:   func() (*form.Set, error) { return set, nil },
		Store: store,
		Limit: throttle.New(policy),
	}
	return st, store
}

// valid posts a submission that passes every check a form has.
//
// The honeypot left empty and a timestamp old enough — which is what a script
// that loaded the page once and kept the stamp sends, indefinitely.
func valid(st *Site, who string) *httptest.ResponseRecorder {
	body := url.Values{
		"who":           {who},
		form.Honeypot:   {""},
		form.StampField: {fmt.Sprint(time.Now().Add(-time.Hour).Unix())},
	}
	req := httptest.NewRequest(http.MethodPost, "/form/enquiry",
		strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.7:5555"
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	return w
}

// The hole. Only rejected submissions counted against the limiter, so a
// script that loaded the form once, kept the timestamp and posted VALID
// submissions in a loop was never slowed at all.
//
// Measured against the demo before this was fixed: eighty valid submissions
// from one address were eighty accepted and none refused.
func TestValidSubmissionsAreRateLimited(t *testing.T) {
	policy := throttle.Default()
	policy.After = 3
	st, store := rateSite(t, policy)

	accepted, limited := 0, 0
	for i := 0; i < 30; i++ {
		switch valid(st, fmt.Sprintf("bot %d", i)).Code {
		case http.StatusTooManyRequests:
			limited++
		default:
			accepted++
		}
	}
	if limited == 0 {
		t.Fatalf("%d valid submissions from one address, none limited: the "+
			"honeypot and the timing stamp both pass for anything that read "+
			"the page once, and they were the only defences", accepted)
	}
	// And the free allowance is honoured, so a person is not refused for
	// submitting one enquiry.
	if accepted > policy.After+2 {
		t.Errorf("%d were accepted against an allowance of %d",
			accepted, policy.After)
	}
	// The ones that were limited must not be in the postbag.
	all, err := store.List("enquiry")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != accepted {
		t.Errorf("%d submissions stored, %d accepted", len(all), accepted)
	}
}

// The first submission from an address still works. A rate limit that refuses
// the first enquiry is a contact form that does not work.
func TestTheFirstSubmissionIsNotRefused(t *testing.T) {
	st, _ := rateSite(t, throttle.Default())
	if got := valid(st, "a person").Code; got == http.StatusTooManyRequests {
		t.Fatalf("the first submission was rate-limited (%d)", got)
	}
}

// A refused submission is told when to come back, rather than only that it
// was refused.
func TestARateLimitedSubmissionSaysWhenToRetry(t *testing.T) {
	policy := throttle.Default()
	policy.After = 1
	st, _ := rateSite(t, policy)

	var limited *httptest.ResponseRecorder
	for i := 0; i < 10 && limited == nil; i++ {
		if res := valid(st, fmt.Sprint(i)); res.Code == http.StatusTooManyRequests {
			limited = res
		}
	}
	if limited == nil {
		t.Fatal("nothing was limited")
	}
	if limited.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on a rate-limited submission")
	}
}

// Spend and Fail are the same counter under two names. A limiter with a
// second, separate window would let an attacker spend both.
func TestSpendAndFailShareTheCounter(t *testing.T) {
	policy := throttle.Default()
	policy.After = 2
	l := throttle.New(policy)
	sub := throttle.Subject{Source: "198.51.100.4"}

	l.Spend(sub)
	l.Fail(sub)
	l.Spend(sub)

	if d := l.Check(sub); d.Allowed {
		t.Errorf("three attempts against an allowance of two were allowed "+
			"(%d on record)", d.Failures)
	}
}

// A limiter switched off allows everything, which is what it is for.
func TestAnOffLimiterRefusesNothing(t *testing.T) {
	policy := throttle.Default()
	policy.On = false
	st, _ := rateSite(t, policy)
	for i := 0; i < 20; i++ {
		if got := valid(st, fmt.Sprint(i)).Code; got == http.StatusTooManyRequests {
			t.Fatalf("submission %d was limited with the throttle off", i)
		}
	}
}

// And no limiter at all is the same, rather than a nil dereference.
func TestNoLimiterIsNotACrash(t *testing.T) {
	st, _ := rateSite(t, throttle.Default())
	st.Forms.Limit = nil
	for i := 0; i < 5; i++ {
		if got := valid(st, fmt.Sprint(i)).Code; got == http.StatusTooManyRequests {
			t.Fatalf("submission %d was limited with no limiter", i)
		}
	}
}

// /share gets a harder limit than a form, which its own comment has claimed
// for some time and which was not true: it used Forms.Limit, the same limiter
// under the same policy.
//
// A share has one fewer defence than a form. The honeypot and the timing stamp
// both need a page this server rendered, and a share arrives from the
// operating system's share sheet having loaded none — so the harder limit is
// the whole of what replaces them.
func TestShareUsesItsOwnHarderLimiter(t *testing.T) {
	st, _ := rateSite(t, throttle.Default())
	forms := st.Forms.Limit

	// Its own, tighter.
	tight := throttle.Default()
	tight.After = 0
	st.Share = &ShareTarget{
		Form: "enquiry", TitleField: "who", Limit: throttle.New(tight),
	}

	if got := st.Share.limiter(st.Forms); got == forms {
		t.Fatal("the share route is using the form limiter")
	}

	// And a share spends the share limiter, not the form one, so filling the
	// share allowance leaves the form working.
	sub := throttle.Subject{Source: "203.0.113.9"}
	for i := 0; i < 5; i++ {
		st.Share.Limit.Spend(sub)
	}
	if d := st.Share.Limit.Check(sub); d.Allowed {
		t.Error("five shares against an allowance of none were allowed")
	}
	if d := forms.Check(sub); !d.Allowed {
		t.Error("spending the share allowance also spent the form's")
	}
}

// With no limiter of its own it falls back to the form's, which is the
// previous behaviour and better than no limit at all.
func TestShareFallsBackToTheFormLimiter(t *testing.T) {
	st, _ := rateSite(t, throttle.Default())
	st.Share = &ShareTarget{Form: "enquiry", TitleField: "who"}
	if got := st.Share.limiter(st.Forms); got != st.Forms.Limit {
		t.Error("a share target with no limiter did not fall back")
	}
}

// And with neither, nothing panics.
func TestShareWithNoLimiterAtAll(t *testing.T) {
	var target *ShareTarget
	if got := target.limiter(nil); got != nil {
		t.Error("a nil share target produced a limiter")
	}
	target = &ShareTarget{Form: "enquiry"}
	if got := target.limiter(nil); got != nil {
		t.Error("a share target with no forms produced a limiter")
	}
}
