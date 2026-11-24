// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/quilzo/quilzo/internal/register"
)

// osquery and Fleet query results.
//
// Three shapes are read: osquery's result log, a JSON object a line, either
// a differential row (name, hostIdentifier, columns, action) or a snapshot
// (name, hostIdentifier, snapshot); and a Fleet query report, the export of
// one query's latest results across hosts (query_id, results of host_name
// and columns).
//
// Each host is a device, by the identifier osquery or Fleet knows it by.
// A query that returned one row for a host is a fact for each column,
// osquery.QUERY.COLUMN, which is how a posture query (is the disk
// encrypted, is the firewall on) reads; a query that returned several rows
// for a host is one fact, osquery.QUERY.rows, how many. A row a differential
// log says was removed is not a fact that holds now, and is not read.

func init() { readers[FormatOsquery] = readOsquery }

// hostRows is the rows one query returned for one host, with where the
// first was read.
type hostRows struct {
	host, query, place string
	rows               []map[string]any
}

func readOsquery(rd *reader) error {
	docs, err := jsonDocs(rd.in.Body)
	if err != nil {
		return err
	}
	byKey := map[string]*hostRows{}
	var keys []string
	add := func(host, query, place string, row map[string]any) {
		k := host + "\x00" + query
		hr := byKey[k]
		if hr == nil {
			hr = &hostRows{host: host, query: query, place: place}
			byKey[k] = hr
			keys = append(keys, k)
		}
		hr.rows = append(hr.rows, row)
	}
	removed := 0
	for i, doc := range docs {
		d := obj(doc)
		place := "/" + strconv.Itoa(i)
		if d == nil {
			return fmt.Errorf("%w: %s is not a query result", ErrUnreadable, place)
		}
		switch {
		case d["query_id"] != nil && d["results"] != nil:
			query := "fleet-query-" + str(d["query_id"])
			for j, r := range arr(d["results"]) {
				ro := obj(r)
				host := firstText(str(ro["host_name"]), str(ro["host_id"]))
				if host == "" || obj(ro["columns"]) == nil {
					continue
				}
				add(host, query, fmt.Sprintf("%s/results/%d", place, j), obj(ro["columns"]))
			}
		case d["snapshot"] != nil:
			host, query := str(d["hostIdentifier"]), str(d["name"])
			if host == "" || query == "" {
				return fmt.Errorf("%w: the snapshot at %s names no host or no query", ErrUnreadable, place)
			}
			rows := arr(d["snapshot"])
			if len(rows) == 0 {
				add(host, query, place+"/snapshot", nil)
			}
			for j, r := range rows {
				add(host, query, fmt.Sprintf("%s/snapshot/%d", place, j), obj(r))
			}
		case d["columns"] != nil:
			host, query := str(d["hostIdentifier"]), str(d["name"])
			if host == "" || query == "" {
				return fmt.Errorf("%w: the result at %s names no host or no query", ErrUnreadable, place)
			}
			if str(d["action"]) == "removed" {
				removed++
				continue
			}
			add(host, query, place+"/columns", obj(d["columns"]))
		default:
			return fmt.Errorf("%w: %s is neither an osquery result nor a Fleet query report", ErrUnreadable, place)
		}
	}
	if removed > 0 {
		rd.note("%d row(s) the log says were removed were not read", removed)
	}
	for _, k := range keys {
		hr := byKey[k]
		id, err := rd.asset("device", hr.host, hr.host, hr.place)
		if err != nil {
			return err
		}
		var rows []map[string]any
		for _, r := range hr.rows {
			if r != nil {
				rows = append(rows, r)
			}
		}
		if len(rows) != 1 {
			if err := rd.observe(id, factName("osquery", hr.query, "rows"), register.NumberValue(float64(len(rows))), hr.place, ""); err != nil {
				return err
			}
			continue
		}
		cols := make([]string, 0, len(rows[0]))
		for c := range rows[0] {
			cols = append(cols, c)
		}
		sort.Strings(cols)
		for _, c := range cols {
			ok, text, _ := scalarJSON(rows[0][c])
			if !ok || text == "" {
				continue
			}
			if err := rd.observe(id, factName("osquery", hr.query, c), scalarOf(text), hr.place+"/"+escapeToken(c), ""); err != nil {
				return err
			}
		}
	}
	return nil
}
