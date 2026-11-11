// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
)

// bulkRecords is a Data screen over a collection of n records named
// "row-000" upwards, and their ids in the order the screen lists them.
func bulkRecords(t *testing.T, n int) (*Server, string, []string) {
	t.Helper()
	srv, token := setup(t)
	recs := make([]collection.Record, n)
	for i := range recs {
		recs[i] = collection.Record{Fields: map[string]any{"name": fmt.Sprintf("row-%03d", i)}}
	}
	tree, stored, err := collection.PutMany(srv.Store, "", "bulk", recs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv.Data = &Data{Tree: func() (string, error) { return tree, nil },
		Commit: func(next, msg, by string) error { tree = next; return nil }}
	ids := make([]string, 0, n)
	for _, r := range stored {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return srv, token, ids
}

// rowIDs are the record ids a Data screen lists, as their edit links name them.
var rowIDs = regexp.MustCompile(`edit=([0-9a-f]+)#write`)

// Every record of a collection can be reached from the Data screen.
//
// It listed the first hundred, in id order, under "3001 records", with no
// way to the other two thousand nine hundred: no Next, no "1 to 100 of".
func TestTheDataScreenPagesThroughEveryRecord(t *testing.T) {
	srv, token, ids := bulkRecords(t, 230)

	seen := map[string]bool{}
	at, pages := "/records?c=bulk", 0
	for at != "" {
		pages++
		if pages > 10 {
			t.Fatal("the Next links do not come to an end")
		}
		w := get(t, srv, at, token)
		if w.Code != http.StatusOK {
			t.Fatalf("%s answered %d", at, w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, "230 records in bulk") {
			t.Errorf("%s does not say how many there are", at)
		}
		for _, m := range rowIDs.FindAllStringSubmatch(body, -1) {
			seen[m[1]] = true
		}
		at = ""
		if m := nextLink.FindStringSubmatch(body); m != nil {
			at = html.UnescapeString(m[1])
		}
	}
	if len(seen) != len(ids) {
		t.Errorf("paging reached %d of %d records in %d screens", len(seen), len(ids), pages)
	}
	if first := get(t, srv, "/records?c=bulk", token).Body.String(); !strings.Contains(first, "1 to 100 of 230") {
		t.Error("the first screen does not say which records it shows")
	}
}

// Find looks through the whole collection and counts what it finds.
//
// It filtered the hundred records already on the screen and then put the
// number it kept where the total was: the record with the last id was
// "0 records in bulk", and a word every record shares was "100 records".
func TestFindSearchesTheWholeCollection(t *testing.T) {
	srv, token, ids := bulkRecords(t, 230)
	srvTree, _ := srv.Data.Tree()
	last, err := collection.Get(srv.Store, srvTree, "bulk", ids[len(ids)-1])
	if err != nil || last == nil {
		t.Fatal(err)
	}
	name := last.Fields["name"].(string)

	body := get(t, srv, "/records?c=bulk&find="+url.QueryEscape(name), token).Body.String()
	if !strings.Contains(body, "1 record in bulk") || !strings.Contains(body, "edit="+last.ID+"#write") {
		t.Errorf("finding %q, the record with the last id, did not find it", name)
	}
	body = get(t, srv, "/records?c=bulk&find=ROW-", token).Body.String()
	if !strings.Contains(body, "230 records in bulk") {
		t.Error("finding what every record says does not count every record")
	}
	// And its pages keep what was found.
	m := nextLink.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("what was found has no Next")
	}
	next, _ := url.Parse(html.UnescapeString(m[1]))
	if next.Query().Get("find") != "ROW-" || next.Query().Get("from") != "100" {
		t.Errorf("Next from what was found goes to %s", next)
	}
}
