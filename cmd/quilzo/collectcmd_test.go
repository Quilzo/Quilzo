// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/connector"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// fakeTool answers a connector's requests from a function, and remembers
// what it was asked.
type fakeTool struct {
	answer func(r *http.Request) (int, string, http.Header)
	asked  []string
}

func (f *fakeTool) Do(r *http.Request) (*http.Response, error) {
	f.asked = append(f.asked, r.URL.Path+"?"+r.URL.RawQuery)
	code, body, h := f.answer(r)
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{StatusCode: code, Header: h,
		Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

// collectSite is a store with the Okta connector installed and a fake Okta
// behind it.
func collectSite(t *testing.T, tool *fakeTool) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdConnect(root, []string{"add", "okta", "--org", "acme"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_CONNECT_SECRET", "00abcdefghijklmnopqrstuvwxyz0123456789ABCD")
	if err := cmdConnect(root, []string{"secret", "okta-api-token"}); err != nil {
		t.Fatal(err)
	}
	saved := connectDoer
	connectDoer = func(time.Duration) connector.Doer { return tool }
	connectSleep = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() { connectDoer = saved; connectSleep = nil })
	return root
}

func oktaEvent(id, who, result string, at time.Time) string {
	return fmt.Sprintf(`{"uuid":%q,"published":%q,"eventType":"user.session.start",`+
		`"displayMessage":"User login to Okta","actor":{"id":%q,"alternateId":%q},`+
		`"outcome":{"result":%q},"client":{"ipAddress":"203.0.113.9",`+
		`"geographicalContext":{"country":"NL"}},"target":[{"id":"app1"}]}`,
		id, at.UTC().Format("2006-01-02T15:04:05.000Z"), "00u"+who, who+"@acme.com", result)
}

func readText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func storedEvents(t *testing.T, root string) []telemetry.Event {
	t.Helper()
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	var out []telemetry.Event
	_ = sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		out = append(out, e)
		return nil
	})
	return out
}

func TestCollectingReadsWhatIsNewMapsItAndStoresItOnce(t *testing.T) {
	now := time.Now().UTC()
	page := "[" + oktaEvent("e1", "dana", "SUCCESS", now.Add(-2*time.Hour)) + "," +
		oktaEvent("e2", "sam", "FAILURE", now.Add(-time.Hour)) + "]"
	tool := &fakeTool{answer: func(r *http.Request) (int, string, http.Header) {
		if r.URL.Path != "/api/v1/logs" {
			return 200, "[]", nil
		}
		return 200, page, nil
	}}
	root := collectSite(t, tool)
	if err := cmdCollect(root, []string{"run", "okta/system"}); err != nil {
		t.Fatal(err)
	}
	got := storedEvents(t, root)
	if len(got) != 2 {
		t.Fatalf("%d events stored of two returned", len(got))
	}
	e := got[1]
	if e.Source != "okta/system" || e.Actor.String() != "okta:00usam" ||
		e.Disposition != telemetry.DispositionFailed || e.Raw["country"] != "NL" ||
		e.Target.Value != "app1" || len(e.Of(telemetry.ObservableIP)) != 1 {
		t.Errorf("the second event: %+v", e)
	}
	// The first read asked for the last day, and only of this endpoint.
	first := tool.asked[0]
	if !strings.Contains(first, "since=") || !strings.HasPrefix(first, "/api/v1/logs?") {
		t.Errorf("the first request: %s", first)
	}
	for _, asked := range tool.asked {
		if strings.HasPrefix(asked, "/api/v1/users") {
			t.Error("collecting the log also read the directory")
		}
	}
	// The next read asks from where this one stopped, and a record the
	// tool returns again is not stored again.
	tool.asked = nil
	if err := cmdCollect(root, []string{"run"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tool.asked[0], "since="+strings.ReplaceAll(
		now.Add(-time.Hour).Format("2006-01-02T15"), ":", "%3A")) {
		t.Errorf("the second read did not start at the checkpoint: %s", tool.asked[0])
	}
	if got = storedEvents(t, root); len(got) != 2 {
		t.Errorf("%d events after the same page was returned twice", len(got))
	}
	status, _ := loadCollectStatus(root)
	if st := status["okta/system"]; st.Known != 2 || st.Stored != 0 || st.Error != "" {
		t.Errorf("the second read: %+v", st)
	}
	// The tool fails once. What was remembered is kept, so when it answers
	// again the same records are still known.
	good := tool.answer
	tool.answer = func(*http.Request) (int, string, http.Header) { return 500, "{}", nil }
	if err := cmdCollect(root, []string{"run"}); err != nil {
		t.Fatal(err)
	}
	tool.answer = good
	if err := cmdCollect(root, []string{"run"}); err != nil {
		t.Fatal(err)
	}
	if got = storedEvents(t, root); len(got) != 2 {
		t.Errorf("%d events after a failed read in between", len(got))
	}
	events, _ := audit.Read(auditPath(root))
	runs := 0
	for _, ev := range events {
		if ev.Action == "collect.run" {
			runs++
			for _, v := range ev.Detail {
				if strings.Contains(v, "acme.com") || strings.Contains(v, "203.0.113") {
					t.Errorf("the record of a read carries what was read: %q", v)
				}
			}
		}
	}
	if runs != 4 {
		t.Errorf("%d reads on the record", runs)
	}
}

// A vendor renames a field: the records stop mapping, and that is said,
// with the field, instead of the source going quiet.
func TestARenamedFieldIsAMissWithItsNameAndNotAQuietSource(t *testing.T) {
	now := time.Now().UTC()
	renamed := strings.ReplaceAll(oktaEvent("e1", "dana", "SUCCESS", now),
		`"published"`, `"publishedAt"`)
	tool := &fakeTool{answer: func(*http.Request) (int, string, http.Header) {
		return 200, "[" + renamed + "]", nil
	}}
	root := collectSite(t, tool)
	if err := cmdCollect(root, []string{"run"}); err != nil {
		t.Fatal(err)
	}
	status, _ := loadCollectStatus(root)
	st := status["okta/system"]
	if st.Records != 1 || st.Stored != 0 || st.Missed != 1 || st.Field != "published" {
		t.Errorf("%+v", st)
	}
	if len(storedEvents(t, root)) != 0 {
		t.Error("a record with no time was stored")
	}
	// The tool refusing is an error on the source, and what was remembered
	// of earlier reads is kept.
	tool.answer = func(*http.Request) (int, string, http.Header) {
		return 401, `{"errorCode":"E0000011"}`, nil
	}
	if err := cmdCollect(root, []string{"run"}); err != nil {
		t.Fatal(err)
	}
	status, _ = loadCollectStatus(root)
	if status["okta/system"].Error == "" {
		t.Error("a refused read was recorded as a read of nothing")
	}
	if cmdCollect(root, []string{"run", "okta/nothing"}) == nil {
		t.Error("a source nothing is installed for was read")
	}
	if cmdCollect(root, []string{"status"}) != nil {
		t.Error("status")
	}
}

// An application of the organisation's own: a mapping is installed only
// once it has mapped real records, and then its file is collected.
func TestAnApplicationOfYourOwnGetsAMappingAndIsCollectedFromAFile(t *testing.T) {
	root := collectSite(t, &fakeTool{answer: func(*http.Request) (int, string, http.Header) {
		return 200, "[]", nil
	}})
	dir := t.TempDir()
	mapping := put(t, filepath.Join(dir, "billing.json"), `{
	 "issuer":"billing","tool":"Billing","stream":"admin","class":6003,"activity":1,
	 "time":"at","layout":"2006-01-02T15:04:05Z07:00","actor":"user","target":"invoice",
	 "message":"action","outcome":"result","failed":["denied"],
	 "observables":{"1":"ip"},"require":["at","user","action"],"keep":["action","amount"],
	 "lateness":60000000000}`)
	records := put(t, filepath.Join(dir, "records.jsonl"),
		`{"at":"2026-09-30T10:00:00Z","user":"dana","action":"refund","invoice":"INV-7","result":"ok","ip":"203.0.113.9","amount":"9000"}`+"\n"+
			`{"at":"2026-09-30T10:01:00Z","user":"sam","action":"refund","invoice":"INV-8","result":"denied","ip":"198.51.100.7"}`+"\n")
	wrong := put(t, filepath.Join(dir, "wrong.json"), `[{"when":"x","who":"y"}]`)

	if cmdSource(root, nil) != nil {
		t.Fatal("source list")
	}
	if cmdSource(root, []string{"add", mapping}) == nil {
		t.Error("a mapping was installed without being shown to map anything")
	}
	if cmdSource(root, []string{"add", mapping, "--sample", wrong}) == nil {
		t.Error("a mapping that mapped none of its sample was installed")
	}
	if err := cmdSource(root, []string{"add", mapping, "--sample", records}); err != nil {
		t.Fatal(err)
	}
	if err := cmdCollect(root, []string{"file", "billing/admin", records}); err != nil {
		t.Fatal(err)
	}
	var mine []telemetry.Event
	for _, e := range storedEvents(t, root) {
		if e.Source == "billing/admin" {
			mine = append(mine, e)
		}
	}
	if len(mine) != 2 || mine[0].Actor.String() != "billing:dana" ||
		mine[1].Disposition != telemetry.DispositionFailed ||
		mine[0].Raw["amount"] != "9000" {
		t.Fatalf("%+v", mine)
	}
	// The same file again stores nothing twice.
	if err := cmdCollect(root, []string{"file", "billing/admin", records}); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range storedEvents(t, root) {
		if e.Source == "billing/admin" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d events after the same file twice", n)
	}
	// It cannot take a built-in's name, and a file that maps nothing is an
	// error and not an empty success.
	clash := put(t, filepath.Join(dir, "okta.json"), strings.ReplaceAll(strings.ReplaceAll(
		readText(t, mapping), `"billing"`, `"okta"`), `"admin"`, `"system"`))
	if cmdSource(root, []string{"add", clash, "--sample", records}) == nil {
		t.Error("a mapping replaced a built-in one")
	}
	if cmdCollect(root, []string{"file", "billing/admin", wrong}) == nil {
		t.Error("a file that mapped nothing was collected cleanly")
	}
	if cmdCollect(root, []string{"file", "nobody/knows", records}) == nil {
		t.Error("a file was collected with no mapping")
	}
	// A cloud trail's file, which wraps its records.
	trail := put(t, filepath.Join(dir, "trail.json"), `{"Records":[{"eventTime":"2026-09-30T10:00:00Z",
	 "eventName":"PutBucketPolicy","eventSource":"s3.amazonaws.com","sourceIPAddress":"203.0.113.9",
	 "userIdentity":{"arn":"arn:aws:iam::1:user/deploy"}}]}`)
	if err := cmdCollect(root, []string{"file", "aws/cloudtrail", trail}); err != nil {
		t.Fatal(err)
	}
}

func TestTheScheduleIsSetByAPersonAndReadsOnItsInterval(t *testing.T) {
	now := time.Now().UTC()
	calls := 0
	tool := &fakeTool{answer: func(*http.Request) (int, string, http.Header) {
		calls++
		return 200, "[" + oktaEvent("e1", "dana", "SUCCESS", now) + "]", nil
	}}
	root := collectSite(t, tool)
	job := collectJob(root)
	if n, err := job.Do(now); n != 0 || err != nil || calls != 0 {
		t.Fatalf("with no schedule the job read something: %d %v", n, err)
	}
	for _, bad := range []string{"1m", "48h", "soon"} {
		if cmdCollect(root, []string{"auto", bad}) == nil {
			t.Errorf("an interval of %s was accepted", bad)
		}
	}
	if err := cmdCollect(root, []string{"auto", "15m"}); err != nil {
		t.Fatal(err)
	}
	if n, err := job.Do(now); n != 1 || err != nil {
		t.Fatalf("the first scheduled read stored %d: %v", n, err)
	}
	before := calls
	if n, _ := job.Do(now.Add(5 * time.Minute)); n != 0 || calls != before {
		t.Error("it read again before the interval had passed")
	}
	if _, err := job.Do(now.Add(20 * time.Minute)); err != nil || calls == before {
		t.Errorf("it did not read after the interval: %v", err)
	}
	if err := cmdCollect(root, []string{"auto", "off"}); err != nil {
		t.Fatal(err)
	}
	before = calls
	if _, _ = job.Do(now.Add(2 * time.Hour)); calls != before {
		t.Error("switched off, it still read")
	}
}

// One person is known by a different identifier on each platform. The
// address they share is carried on every event, learned where a platform
// gives it and said by a person where it does not.
func TestOnePersonIsJoinedAcrossPlatformsByTheAddressTheyShare(t *testing.T) {
	now := time.Now().UTC()
	withAddress := oktaEvent("e1", "dana", "SUCCESS", now.Add(-2*time.Hour))
	// The same identifier, in a record that carries no address.
	without := strings.Replace(oktaEvent("e2", "dana", "FAILURE", now.Add(-time.Hour)),
		`,"alternateId":"dana@acme.com"`, "", 1)
	tool := &fakeTool{answer: func(*http.Request) (int, string, http.Header) {
		return 200, "[" + withAddress + "," + without + "]", nil
	}}
	root := collectSite(t, tool)
	if err := cmdCollect(root, []string{"run"}); err != nil {
		t.Fatal(err)
	}
	got := storedEvents(t, root)
	if len(got) != 2 {
		t.Fatalf("%d events", len(got))
	}
	for n, e := range got {
		if e.Raw["person"] != "dana@acme.com" {
			t.Errorf("event %d carries person %q", n, e.Raw["person"])
		}
		// The platform's identifier is still who acted.
		if e.Actor.String() != "okta:00udana" {
			t.Errorf("event %d: the actor became %s", n, e.Actor)
		}
	}
	// GitHub knows a login and no address. A person says whose it is.
	for _, bad := range [][]string{{"link", "github:dana-gh"},
		{"link", "dana-gh", "dana@acme.com"}, {"link", "github:dana-gh", "dana"},
		{"unlink", "github:nobody"}} {
		if cmdIdentity(root, bad) == nil {
			t.Errorf("identity %v was accepted", bad)
		}
	}
	if err := cmdIdentity(root, []string{"link", "github:dana-gh", "Dana@Acme.com"}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	audit := put(t, filepath.Join(dir, "gh.json"), fmt.Sprintf(
		`[{"@timestamp":%d,"action":"protected_branch.destroy","actor":"dana-gh","repo":"acme/shop","actor_ip":"203.0.113.9"},`+
			`{"@timestamp":%d,"action":"repo.create","actor":"stranger","repo":"acme/x"}]`,
		now.UnixMilli(), now.UnixMilli()))
	if err := cmdCollect(root, []string{"file", "github/audit", audit}); err != nil {
		t.Fatal(err)
	}
	people := map[string]string{}
	for _, e := range storedEvents(t, root) {
		if e.Source == "github/audit" {
			people[e.Actor.Value] = e.Raw["person"]
		}
	}
	if people["dana-gh"] != "dana@acme.com" || people["stranger"] != "" {
		t.Errorf("github events: %v", people)
	}
	aliases, _ := loadAliases(root)
	byPerson := peopleOf(aliases)
	if strings.Join(byPerson["dana@acme.com"], ",") != "github:dana-gh,okta:00udana" {
		t.Errorf("dana is known as %v", byPerson["dana@acme.com"])
	}
	// What a person said is not overwritten by what a log says later.
	e := telemetry.Event{Actor: telemetry.ID{Issuer: "github", Value: "dana-gh"},
		Raw: map[string]string{"person": "someone-else@acme.com"}}
	if personOf(&e, aliases, now) || aliases["github:dana-gh"].Person != "dana@acme.com" ||
		e.Raw["person"] != "dana@acme.com" {
		t.Errorf("a learned address replaced a link a person made: %+v %v",
			aliases["github:dana-gh"], e.Raw)
	}
	// What was learned follows the platform when it changes.
	e = telemetry.Event{Actor: telemetry.ID{Issuer: "okta", Value: "00udana"},
		Raw: map[string]string{"person": "dana.lee@acme.com"}}
	if !personOf(&e, aliases, now) || aliases["okta:00udana"].Person != "dana.lee@acme.com" {
		t.Error("a changed address was not learned")
	}
	if err := cmdIdentity(root, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdIdentity(root, []string{"unlink", "github:dana-gh"}); err != nil {
		t.Fatal(err)
	}
}
