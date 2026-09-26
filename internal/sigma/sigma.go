// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package sigma reads detection rules written in the open standard, so a
// team's existing library works here without being retyped.
//
// # Why this and not another rule format
//
// Every security product invents a detection language, and the cost lands
// on the customer: rules written for one tool are worthless in the next,
// which is most of why replacing a SIEM takes a year. Sigma is the
// vendor-neutral answer — a YAML format with a public repository of a few
// thousand community rules and converters into Splunk's SPL, Microsoft
// Sentinel's KQL, Elastic, Chronicle's YARA-L and the rest.
//
// So "bring your own rules" here means the format the rules are already in.
// A rule that runs on somebody's Splunk runs here, and a rule written here
// converts to everywhere else, because it is the same artefact.
//
// # What it refuses to do
//
// It never half-compiles. A Sigma rule using a construct this does not
// implement is reported with the construct named and the rule is not
// loaded, rather than loaded with the unsupported part quietly dropped.
// The second behaviour is the dangerous one: a rule that lost its exclusion
// clause still fires, still looks like it is working, and is now a
// different rule from the one its author reviewed.
//
// # What Sigma gets right that most products leave out
//
// A Sigma rule carries a falsepositives list — the known benign things that
// will trip it. internal/detect has a Blind field for exactly that sort of
// knowledge and observes that nobody ever fills it in. Here it arrives
// filled in, because the standard asks for it. A rule at high or critical
// level whose only stated false positive is "Unknown" is reported: that
// combination is a rule somebody wrote confidently without having run it
// anywhere, and Axelsson's arithmetic in internal/detect is about precisely
// what happens next.
package sigma

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/detect"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Rule is a Sigma rule as written.
type Rule struct {
	Title       string   `json:"title"`
	ID          string   `json:"id,omitempty"`
	Status      string   `json:"status,omitempty"`
	Description string   `json:"description,omitempty"`
	Author      string   `json:"author,omitempty"`
	References  []string `json:"references,omitempty"`
	Date        string   `json:"date,omitempty"`
	Modified    string   `json:"modified,omitempty"`

	LogSource LogSource `json:"logsource"`
	// Detection holds the named selections and the condition that combines
	// them. Kept as read so that a compile failure can quote the original.
	Detection map[string]any `json:"detection"`
	Condition string         `json:"condition"`

	FalsePositives []string `json:"falsepositives,omitempty"`
	Level          string   `json:"level,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Fields         []string `json:"fields,omitempty"`
}

// LogSource says what kind of events a rule is written against.
type LogSource struct {
	Category   string `json:"category,omitempty"`
	Product    string `json:"product,omitempty"`
	Service    string `json:"service,omitempty"`
	Definition string `json:"definition,omitempty"`
}

// Name is the log source as one string, for use as a detect source.
func (l LogSource) Name() string {
	var parts []string
	for _, p := range []string{l.Product, l.Service, l.Category} {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, "/")
}

// Levels in Sigma, mapped to this program's severities.
func level(s string) (telemetry.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return telemetry.SeverityCritical, true
	case "high":
		return telemetry.SeverityHigh, true
	case "medium":
		return telemetry.SeverityMedium, true
	case "low", "informational", "info", "":
		return telemetry.SeverityLow, true
	}
	return telemetry.SeverityLow, false
}

// Read parses a Sigma file into rules.
func Read(in []byte) ([]Rule, error) {
	docs, err := Parse(in)
	if err != nil {
		return nil, err
	}
	var out []Rule
	for i, d := range docs {
		r, err := fromDoc(d)
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", i+1, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func fromDoc(d Doc) (Rule, error) {
	r := Rule{
		Title: str(d["title"]), ID: str(d["id"]),
		Status: str(d["status"]), Description: str(d["description"]),
		Author: str(d["author"]), Date: str(d["date"]),
		Modified: str(d["modified"]), Level: str(d["level"]),
		References:     strs(d["references"]),
		FalsePositives: strs(d["falsepositives"]),
		Tags:           strs(d["tags"]),
		Fields:         strs(d["fields"]),
	}
	if ls, ok := d["logsource"].(map[string]any); ok {
		r.LogSource = LogSource{
			Category: str(ls["category"]), Product: str(ls["product"]),
			Service: str(ls["service"]), Definition: str(ls["definition"]),
		}
	}
	det, ok := d["detection"].(map[string]any)
	if !ok {
		return r, fmt.Errorf("this rule has no detection block")
	}
	r.Detection = map[string]any{}
	for k, v := range det {
		if k == "condition" {
			r.Condition = str(v)
			continue
		}
		if k == "timeframe" {
			continue
		}
		r.Detection[k] = v
	}
	if strings.TrimSpace(r.Condition) == "" {
		return r, fmt.Errorf("the detection block has no condition, so " +
			"there is no way to know how its selections combine")
	}
	if strings.TrimSpace(r.Title) == "" {
		return r, fmt.Errorf("a rule needs a title")
	}
	return r, nil
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func strs(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Unsupported names a construct this does not implement.
//
// Its own type so that a caller can tell "this rule uses something we do
// not do" from "this rule is malformed". The first is a gap in this
// implementation and the second is a gap in the rule, and a team importing
// three thousand rules needs the two lists apart.
type Unsupported struct {
	Rule string
	What string
	Why  string
}

func (u *Unsupported) Error() string {
	return fmt.Sprintf("%s: %s is not implemented here — %s", u.Rule,
		u.What, u.Why)
}

// Compile turns a Sigma rule into one this program can run, with field
// names left as the rule wrote them.
func (r Rule) Compile() (detect.Rule, error) {
	return r.CompileWith(Pipeline{})
}

// CompileWith compiles against a deployment's field mapping.
func (r Rule) CompileWith(pipe Pipeline) (detect.Rule, error) {
	sev, ok := level(r.Level)
	if !ok {
		return detect.Rule{}, fmt.Errorf("%s: %q is not a Sigma level",
			r.Title, r.Level)
	}
	sels := map[string]detect.Predicate{}
	names := make([]string, 0, len(r.Detection))
	for name, body := range r.Detection {
		p, err := selection(pipe, r.Title, name, body)
		if err != nil {
			return detect.Rule{}, err
		}
		sels[name] = p
		names = append(names, name)
	}
	sort.Strings(names)

	when, err := condition(r.Title, r.Condition, sels, names)
	if err != nil {
		return detect.Rule{}, err
	}

	id := r.ID
	if strings.TrimSpace(id) == "" {
		id = slug(r.Title)
	}
	out := detect.Rule{
		ID: id, Title: r.Title, Why: r.Description,
		Blind: strings.Join(r.FalsePositives, "; "),
		When:  when, Severity: sev,
	}
	switch {
	case pipe.Source != "":
		out.Sources = []string{pipe.Source}
	default:
		if src := r.LogSource.Name(); src != "" {
			out.Sources = []string{src}
		}
	}
	for _, t := range r.Tags {
		if strings.HasPrefix(strings.ToLower(t), "attack.t") {
			out.Technique = append(out.Technique,
				strings.ToUpper(strings.TrimPrefix(strings.ToLower(t),
					"attack.")))
		}
	}
	return out, nil
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// Loud reports whether a rule claims a high level without saying what will
// trip it.
//
// Sigma asks for a falsepositives list and the convention when an author
// has not tested the rule anywhere is to write "Unknown". A critical rule
// with an unknown false-positive profile is not a strong detection, it is
// an untested one, and internal/detect's arithmetic says what happens when
// it meets a million events a day.
func (r Rule) Loud() bool {
	sev, _ := level(r.Level)
	if sev != telemetry.SeverityHigh && sev != telemetry.SeverityCritical {
		return false
	}
	if len(r.FalsePositives) == 0 {
		return true
	}
	for _, f := range r.FalsePositives {
		if !strings.EqualFold(strings.TrimSpace(f), "unknown") {
			return false
		}
	}
	return true
}

// b64offsets are the three encodings a string can have inside base64,
// depending on where it starts relative to a three-byte boundary.
//
// Sigma's base64offset modifier exists because an attacker's string is
// rarely at the start of the encoded blob, and a naive encoding matches one
// case in three.
func b64offsets(s string) []string {
	var out []string
	for pad := range 3 {
		enc := base64.StdEncoding.EncodeToString(
			append(make([]byte, pad), s...))
		start := (pad*8 + 5) / 6
		end := len(enc)
		if i := strings.IndexByte(enc, '='); i >= 0 {
			end = i
		}
		// Trim the partial characters at each end, which encode bytes this
		// string does not own.
		if start < end {
			trimmed := enc[start:end]
			if len(trimmed) > 1 {
				out = append(out, trimmed[:len(trimmed)-1])
			}
		}
	}
	return out
}

// dashes are the characters Windows accepts in place of a hyphen on a
// command line, which is how a rule looking for "-enc" misses "/enc".
var dashes = []string{"-", "/", "–", "—", "―"}

func windash(s string) []string {
	if !strings.HasPrefix(s, "-") && !strings.HasPrefix(s, "/") {
		return []string{s}
	}
	rest := s[1:]
	out := make([]string, 0, len(dashes))
	for _, d := range dashes {
		out = append(out, d+rest)
	}
	return out
}
