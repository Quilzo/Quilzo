// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/source"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// What a fetched record means.
//
// internal/connector fetches from an arbitrary tool. This is the half
// after: which OCSF class the records are, which field is the identity a
// join hangs off, and how far behind the source runs.
//
// Every SIEM ships two hundred integrations and the integrations are the
// weakest part of the product, for one reason: when a source changes
// shape, the mapping does not break. It keeps working and produces events
// with empty fields, and the detection written against the field that is
// now empty quietly stops firing.
//
// `source list` shows what is mapped. `source check` runs a mapping
// against real records and says what it would do with them.

func cmdSource(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return sourceList()
	case "check":
		return sourceCheck(args[1:])
	default:
		return fmt.Errorf("unknown source command %q; try list or check",
			args[0])
	}
}

func sourceList() error {
	all := source.Known()
	if w.JSON(map[string]any{
		"sources": all, "issuers": source.Issuers(),
	}) {
		return nil
	}
	byClass := map[string][]source.Source{}
	for _, s := range all {
		k := categoryWord(s.Class.Category())
		byClass[k] = append(byClass[k], s)
	}
	names := make([]string, 0, len(byClass))
	for n := range byClass {
		names = append(names, n)
	}
	sort.Strings(names)

	w.Human("%s%d source(s) across %d platform(s)%s\n\n", bold, len(all),
		len(source.Issuers()), reset)
	for _, n := range names {
		w.Human("  %s%s%s\n", bold, n, reset)
		for _, s := range byClass[n] {
			w.Human("    %-22s %s%-28s %s behind%s\n",
				s.Issuer+"/"+s.Stream, dim, s.Tool,
				plainClockSpan(s.Lateness), reset)
		}
		w.Human("\n")
	}
	if a := source.Advice(all); a != "" {
		w.Human("  %s%s%s\n\n", yellow, wrapAt(a, 64, "  "), reset)
	}
	w.Human("  %sthe issuer is the namespace every identifier from a "+
		"source joins\n  on. Two spellings of one platform breaks every "+
		"join in the estate\n  and produces no error anywhere, which is "+
		"why they are checked%s\n", dim, reset)
	return nil
}

// categoryWord names an OCSF category.
//
// Local rather than a String method on telemetry.Category: that type is
// OCSF's category_uid and prints as its number where an export needs one,
// and giving it a String would quietly change those.
func categoryWord(c telemetry.Category) string {
	switch c {
	case telemetry.CategorySystem:
		return "system activity"
	case telemetry.CategoryFindings:
		return "findings"
	case telemetry.CategoryIAM:
		return "identity and access"
	case telemetry.CategoryNetwork:
		return "network activity"
	case telemetry.CategoryDiscovery:
		return "discovery"
	case telemetry.CategoryApplication:
		return "application activity"
	case telemetry.CategoryRemediation:
		return "remediation"
	}
	return fmt.Sprintf("category %d", uint16(c))
}

func sourceCheck(args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	name := fs.String("source", "aws/cloudtrail",
		"which mapping to check, as issuer/stream")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	issuer, stream, ok := strings.Cut(*name, "/")
	if !ok {
		return fmt.Errorf("name a source as issuer/stream")
	}
	s, found := source.Find(issuer, stream)
	if !found {
		return fmt.Errorf("no mapping for %q; try `quilzo source list`",
			*name)
	}

	var docs []any
	if len(pos) == 1 {
		raw, err := os.ReadFile(pos[0])
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &docs); err != nil {
			var one any
			if err2 := json.Unmarshal(raw, &one); err2 != nil {
				return fmt.Errorf("that file is neither a record nor a "+
					"list of them: %w", err)
			}
			docs = []any{one}
		}
	} else {
		var err error
		docs, err = exampleRecords(s)
		if err != nil {
			return err
		}
		w.Human("%sno file given, so this checks %s against built-in "+
			"records — forty of which have had the identity field "+
			"renamed%s\n\n", dim, *name, reset)
	}

	b, err := source.Check(s, docs)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"batch": b, "source": s}) {
		return nil
	}

	w.Human("%s%s · %s%s\n", bold, s.Issuer+"/"+s.Stream, s.Tool, reset)
	w.Human("  %s%d record(s): %d mapped, %d failed%s\n\n", dim, b.Records,
		b.Mapped, b.Missed, reset)

	if why, drifted := b.Drifted(); drifted {
		w.Human("  %schanged shape%s\n", yellow, reset)
		w.Human("    %s%s%s\n\n", dim, wrapAt(why, 62, "    "), reset)
	} else if b.Missed > 0 {
		path, n := b.Worst()
		w.Human("  %s%d failed, most often on %q (%d) — below the "+
			"threshold,\n  which is a few odd records rather than a "+
			"changed source%s\n\n", dim, b.Missed, path, n, reset)
	} else {
		w.Human("  %severy record mapped%s\n\n", green, reset)
	}

	w.Human("  %srequires%s %s\n", dim, reset,
		strings.Join(s.Require, ", "))
	w.Human("  %sidentity%s %s under the issuer %q\n", dim, reset,
		s.Actor, s.Issuer)
	w.Human("  %slateness%s %s, which is what a correlation over this "+
		"has to wait\n", dim, reset, plainClockSpan(s.Lateness))
	return nil
}

// exampleRecords builds a page in the source's own shape, with a share of
// them having had the identity field renamed — which is what a vendor
// changing a field looks like from here.
func exampleRecords(s source.Source) ([]any, error) {
	if s.Issuer != "aws" {
		return nil, fmt.Errorf(
			"built-in records exist for aws/cloudtrail only; give a file " +
				"of real ones for anything else, which is what you should " +
				"be checking a mapping against anyway")
	}
	const rec = `{"eventTime":%q,"eventName":"PutBucketPolicy",
		"eventSource":"s3.amazonaws.com","awsRegion":"eu-west-1",
		"sourceIPAddress":"203.0.113.9","userAgent":"aws-cli/2.15.0",
		"userIdentity":{"type":"IAMUser","%s":"arn:aws:iam::1:user/deploy"}}`
	at := time.Now().UTC()
	var out []any
	for i := range 100 {
		field := "arn"
		if i < 40 {
			field = "principalArn"
		}
		var v any
		if err := json.Unmarshal([]byte(fmt.Sprintf(rec,
			at.Add(-time.Duration(i)*time.Minute).Format(time.RFC3339),
			field)), &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
