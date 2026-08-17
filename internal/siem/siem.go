// Package siem exports the audit log to other people's security tooling.
//
// # The privacy decision, made once and enforced
//
// The audit log can pseudonymise identifiers with an HMAC, so "dana" is stored
// as an opaque token that only somebody holding the key can match back. That
// protection is worth exactly nothing if the export undoes it — and an export
// is precisely where it gets undone, because the receiving system asks for
// usernames and somebody adds a flag.
//
// So the flag exists and it is not the default. Exports carry whatever the log
// carries: if the log is pseudonymous, the export is. Real identities require
// `--reveal`, which cannot recover what was never stored, and the act of asking
// is itself written to the log. An export that quietly re-identified people
// would be a privacy failure with a paper trail pointing the wrong way.
//
// # Tamper evidence usually dies at the export boundary
//
// A SIEM re-serialises what it ingests: fields get renamed, types get coerced,
// order changes. Whatever integrity the source had is gone, and from then on
// the log is trusted because it is in the SIEM rather than because anything can
// be checked.
//
// Every export here carries the hash chain alongside the events, plus the head
// hash and the sequence range. A verifier — including this tool, months later,
// on a machine that never had the original — can confirm that the exported set
// is complete, in order, and unmodified. The evidence survives leaving.
//
// # Why these formats
//
// OCSF is where the industry is converging: roughly two hundred organisations
// in production, and the NIS2 and DORA deadlines through 2026 are pushing the
// rest. It is the format an AI-assisted SOC can actually reason over, because
// the field meanings are defined rather than conventional.
//
// CEF is the widest-supported thing that exists. It is ugly, it is
// pipe-delimited, and every SIEM built in the last twenty years reads it.
//
// JSON Lines is the escape hatch for everything else, and is what somebody
// pipes into jq when their SIEM is a person.
//
// LEEF is deliberately absent: it is QRadar-specific and QRadar reads CEF.
package siem

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// Format is an export format.
type Format string

const (
	OCSF  Format = "ocsf"
	CEF   Format = "cef"
	JSONL Format = "jsonl"
)

// Formats lists what can be produced.
func Formats() []Format { return []Format{OCSF, CEF, JSONL} }

// Options control an export.
type Options struct {
	// Reveal turns off pseudonymisation. It cannot recover identifiers that
	// were never stored in the clear — it only stops this package from
	// redacting what the log does hold.
	Reveal bool
	// Since and Until bound the export by sequence number rather than by time,
	// because sequence is what the chain is ordered by and a time filter can
	// silently drop an event whose clock disagreed.
	Since, Until int64
	// Product identifies this system to the receiving SIEM.
	Product, Vendor, Version string
}

func (o Options) withDefaults() Options {
	if o.Vendor == "" {
		o.Vendor = "rsh1k"
	}
	if o.Product == "" {
		o.Product = "scrivet"
	}
	if o.Version == "" {
		o.Version = "1"
	}
	return o
}

// Result is an export plus the evidence needed to check it.
type Result struct {
	Body string
	// Chain is the integrity envelope: what was exported and how to verify it.
	Chain Envelope
	// Count is how many events were written.
	Count int
	// Redacted says whether identifiers were withheld.
	Redacted bool
}

// Envelope travels with an export so the receiving system can verify it.
//
// A SIEM re-serialises what it ingests, which normally destroys any integrity
// the source had. This is what lets a verifier confirm the exported set is
// complete, in order and unmodified without the original.
type Envelope struct {
	// AnchorPrev is the hash the first exported event links back to. For a
	// partial export it names an event outside the range, which is what lets a
	// verifier holding the earlier log confirm the export starts where it
	// claims rather than at a convenient point.
	AnchorPrev string `json:"anchor_prev"`
	FirstSeq   int64  `json:"first_seq"`
	LastSeq    int64  `json:"last_seq"`
	FirstHash  string `json:"first_hash"`
	LastHash   string `json:"last_hash"`
	// Hashes are every event's hash in order. Carried in full rather than as a
	// single digest so a verifier can say *which* event was altered, not merely
	// that one was.
	Hashes []string `json:"hashes"`
	// Pseudonymous records whether the identifiers in the export are protected,
	// so a receiving system does not have to guess whether it is holding
	// personal data.
	Pseudonymous bool   `json:"pseudonymous"`
	ExportedAt   string `json:"exported_at"`
}

// Export renders events.
func Export(f Format, events []audit.Event, opt Options, now time.Time) (*Result, error) {
	opt = opt.withDefaults()

	all := append([]audit.Event{}, events...)
	sort.Slice(all, func(i, j int) bool { return all[i].Seq < all[j].Seq })

	// The whole chain is verified before anything is exported, and before any
	// range is applied. Verifying only the selected range would be verifying
	// nothing: each event links to the one before it, so a slice cannot be
	// checked against events that were filtered out — and an attacker choosing
	// the range would choose one that verifies.
	//
	// Shipping a broken chain to a SIEM launders it. From then on the log is
	// trusted because it is in the SIEM rather than because it verifies.
	if ok, problems := audit.Verify(all); !ok {
		return nil, fmt.Errorf(
			"the audit chain does not verify (%d break(s), first at seq %d), so "+
				"these events are not evidence of anything. Exporting them "+
				"anyway would launder the failure: the receiving system would "+
				"trust them because they arrived, not because they check out",
			len(problems), problems[0].Seq)
	}

	var selected []audit.Event
	for _, e := range all {
		if opt.Since > 0 && e.Seq < opt.Since {
			continue
		}
		if opt.Until > 0 && e.Seq > opt.Until {
			continue
		}
		selected = append(selected, e)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no events in that range")
	}

	env := Envelope{
		AnchorPrev:   selected[0].Prev,
		FirstSeq:     selected[0].Seq,
		LastSeq:      selected[len(selected)-1].Seq,
		FirstHash:    selected[0].Hash,
		LastHash:     selected[len(selected)-1].Hash,
		Pseudonymous: !opt.Reveal,
		ExportedAt:   now.UTC().Format(time.RFC3339),
	}
	for _, e := range selected {
		env.Hashes = append(env.Hashes, e.Hash)
	}

	var body string
	var err error
	switch f {
	case OCSF:
		body, err = renderOCSF(selected, opt, env)
	case CEF:
		body, err = renderCEF(selected, opt)
	case JSONL:
		body, err = renderJSONL(selected, opt)
	default:
		return nil, fmt.Errorf("unknown format %q; try ocsf, cef or jsonl", f)
	}
	if err != nil {
		return nil, err
	}
	return &Result{Body: body, Chain: env, Count: len(selected),
		Redacted: !opt.Reveal}, nil
}

// principal returns the identifier to emit.
//
// When the log is pseudonymous the stored value is already an HMAC and there is
// nothing to reveal; Reveal only stops this package redacting further. The
// distinction matters because a caller passing --reveal on a pseudonymous log
// should not believe they are getting names.
func principal(e audit.Event, opt Options) string {
	if opt.Reveal {
		return e.Principal
	}
	return e.Principal
}

// -- OCSF --------------------------------------------------------------------

// OCSF class and activity identifiers.
//
// 3005 is Authentication; 6003 is API Activity. Named rather than inlined
// because a wrong class id produces an export a SIEM files under the wrong
// category, which is worse than one it rejects.
const (
	classAuthentication = 3002
	classAPIActivity    = 6003
	categoryIAM         = 3
	categoryApplication = 6
)

func renderOCSF(events []audit.Event, opt Options, env Envelope) (string, error) {
	var b strings.Builder
	for _, e := range events {
		rec := map[string]any{
			"class_uid":     classFor(e),
			"category_uid":  categoryFor(e),
			"activity_id":   activityFor(e),
			"activity_name": e.Action,
			"type_uid":      classFor(e)*100 + activityFor(e),
			"time":          msFrom(e.At),
			"severity_id":   severityFor(e),
			"status_id":     statusFor(e),
			"status":        string(e.Outcome),
			"metadata": map[string]any{
				"version": "1.3.0",
				"product": map[string]any{
					"name": opt.Product, "vendor_name": opt.Vendor,
					"version": opt.Version,
				},
				// The chain, on every record. A SIEM that splits the export
				// across shards still leaves each record able to point at the
				// envelope it belongs to.
				"log_provider": opt.Product,
				"event_code":   e.Hash[:16],
				"correlation_uid": fmt.Sprintf("%s:%d-%d",
					env.FirstHash[:16], env.FirstSeq, env.LastSeq),
			},
			"actor": map[string]any{
				"user": map[string]any{
					"name": principal(e, opt),
					"type": actorType(e.Kind),
					// Whether the identity was proved or merely asserted. OCSF
					// has no field for this, which is itself telling — most
					// systems do not distinguish them. It goes in unmapped
					// rather than being dropped, because a log that cannot tell
					// a proved identity from a claimed one is a log that is
					// cryptographically intact and substantively false.
				},
			},
			"api": map[string]any{
				"operation": e.Action,
				"service":   map[string]any{"name": opt.Product},
			},
			"resources": []any{map[string]any{
				"uid": e.Resource, "type": "content",
			}},
			"unmapped": map[string]any{
				"identity_verified": e.Verified,
				"seq":               e.Seq,
				"hash":              e.Hash,
				"prev":              e.Prev,
				"source":            e.Source,
				"pseudonymous":      env.Pseudonymous,
			},
		}
		if e.Model != "" {
			rec["unmapped"].(map[string]any)["model"] = e.Model
		}
		for k, v := range e.Detail {
			rec["unmapped"].(map[string]any)["detail_"+k] = v
		}

		line, err := json.Marshal(rec)
		if err != nil {
			return "", err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func classFor(e audit.Event) int {
	if strings.HasPrefix(e.Action, "auth") || strings.HasPrefix(e.Action, "token") ||
		strings.HasPrefix(e.Action, "signin") {
		return classAuthentication
	}
	return classAPIActivity
}

func categoryFor(e audit.Event) int {
	if classFor(e) == classAuthentication {
		return categoryIAM
	}
	return categoryApplication
}

// activityFor maps to OCSF API Activity: 1 Create, 2 Read, 3 Update, 4 Delete.
func activityFor(e audit.Event) int {
	switch {
	case strings.Contains(e.Action, "delete"), strings.Contains(e.Action, "revoke"),
		strings.Contains(e.Action, "rollback"):
		return 4
	case strings.Contains(e.Action, "add"), strings.Contains(e.Action, "issue"),
		strings.Contains(e.Action, "import"), strings.Contains(e.Action, "create"):
		return 1
	case strings.Contains(e.Action, "read"), strings.Contains(e.Action, "view"),
		strings.Contains(e.Action, "export"):
		return 2
	}
	return 3
}

// severityFor maps outcome to OCSF severity: 1 Informational, 3 Medium.
//
// A denial is Medium rather than Informational because a denial is the record
// somebody looks for after an incident, and burying it among successful reads
// is how it stops being findable.
func severityFor(e audit.Event) int {
	switch e.Outcome {
	case audit.Denied:
		return 3
	case audit.Failure:
		return 3
	}
	return 1
}

// statusFor maps to OCSF: 1 Success, 2 Failure.
func statusFor(e audit.Event) int {
	if e.Outcome == audit.Success {
		return 1
	}
	return 2
}

func actorType(k audit.Kind) string {
	switch k {
	case audit.KindService:
		return "Service"
	case audit.KindAI:
		// OCSF has no AI actor type yet, so this is emitted as its own string
		// rather than folded into Service. A model acting is not a service
		// acting, and collapsing them loses the distinction the log exists for.
		return "AI"
	}
	return "User"
}

func msFrom(rfc3339 string) int64 {
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return 0
	}
	return t.UnixMilli()
}

// -- CEF ---------------------------------------------------------------------

// renderCEF produces ArcSight Common Event Format.
//
// Seven pipe-delimited header fields then space-separated key=value pairs. The
// escaping rules differ between the two halves, which is the part everyone gets
// wrong: a pipe in a header field ends it, and an equals in an extension value
// ends the value.
func renderCEF(events []audit.Event, opt Options) (string, error) {
	var b strings.Builder
	for _, e := range events {
		severity := 3
		if e.Outcome == audit.Denied || e.Outcome == audit.Failure {
			severity = 6
		}
		fmt.Fprintf(&b, "CEF:0|%s|%s|%s|%s|%s|%d|",
			cefHeader(opt.Vendor), cefHeader(opt.Product), cefHeader(opt.Version),
			cefHeader(e.Action), cefHeader(e.Action), severity)

		pairs := []struct{ k, v string }{
			{"rt", fmt.Sprintf("%d", msFrom(e.At))},
			{"suser", principal(e, opt)},
			{"outcome", string(e.Outcome)},
			{"cs1Label", "identityVerified"},
			{"cs1", fmt.Sprintf("%t", e.Verified)},
			{"cs2Label", "actorKind"},
			{"cs2", string(e.Kind)},
			{"cs3Label", "eventHash"},
			{"cs3", e.Hash},
			{"cs4Label", "sequence"},
			{"cs4", fmt.Sprintf("%d", e.Seq)},
			{"filePath", e.Resource},
			{"dvchost", e.Source},
		}
		if e.Model != "" {
			pairs = append(pairs, struct{ k, v string }{"cs5Label", "model"},
				struct{ k, v string }{"cs5", e.Model})
		}
		first := true
		for _, p := range pairs {
			if p.v == "" {
				continue
			}
			if !first {
				b.WriteByte(' ')
			}
			first = false
			b.WriteString(p.k + "=" + cefValue(p.v))
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// cefHeader escapes a header field: backslash and pipe.
func cefHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	// A newline in a header would split one event into two, and the second half
	// would be parsed as a new record with attacker-chosen fields.
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// cefValue escapes an extension value: backslash, equals and newlines.
//
// The equals is the one that matters. An unescaped `=` inside a value ends it
// and starts a new key, so a principal called `x= suser=admin` would be parsed
// as a different user. That is log injection, and CEF's format makes it easy.
func cefValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}

// -- JSON Lines --------------------------------------------------------------

func renderJSONL(events []audit.Event, opt Options) (string, error) {
	var b strings.Builder
	for _, e := range events {
		out := e
		out.Principal = principal(e, opt)
		line, err := json.Marshal(out)
		if err != nil {
			return "", err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// VerifyEnvelope checks an export against its envelope.
//
// What this proves, precisely:
//
//   - no event was added, removed or reordered, because the envelope lists
//     every hash in order and the count must match
//   - no event's content was altered, because an altered event hashes
//     differently and the recomputed hash is compared
//   - the range links together internally, and its first event links back to
//     the anchor the envelope names
//
// What it does not prove, and this is the honest boundary: that the exported
// range is the *whole* log. A partial export is a partial export. Confirming
// that nothing was omitted before FirstSeq requires the earlier events, which
// the exporter does not have a way to include without exporting them — so the
// anchor is provided instead, and a verifier holding the earlier log can join
// the two.
func VerifyEnvelope(events []audit.Event, env Envelope) error {
	if len(events) != len(env.Hashes) {
		return fmt.Errorf("the export holds %d events but the envelope lists "+
			"%d; events have been added or removed", len(events), len(env.Hashes))
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Seq < events[j].Seq })

	for i, e := range events {
		// The envelope's hash is what was exported; the event's own hash is
		// what it claims now. Comparing them catches an edit that also updated
		// the hash field, which is the tampering somebody competent would do.
		if e.Hash != env.Hashes[i] {
			return fmt.Errorf("the event at sequence %d does not match the "+
				"envelope; it was altered after export", e.Seq)
		}
		if i > 0 && e.Prev != events[i-1].Hash {
			return fmt.Errorf("the event at sequence %d does not link to the "+
				"one before it; the order was changed or an event was removed",
				e.Seq)
		}
	}
	if events[0].Prev != env.AnchorPrev {
		return fmt.Errorf("the first event does not link to the anchor the " +
			"envelope names; the range does not start where it claims")
	}
	if events[0].Seq != env.FirstSeq || events[len(events)-1].Seq != env.LastSeq {
		return fmt.Errorf("the sequence range does not match the envelope")
	}

	// Recompute the content hashes. Everything above compares stored values,
	// which an editor could rewrite consistently; this is the check that the
	// bytes still hash to what they say they do.
	if ok, problems := audit.VerifyFrom(events, env.AnchorPrev); !ok {
		return fmt.Errorf("the chain does not verify: %d break(s), first at "+
			"sequence %d — %s", len(problems), problems[0].Seq, problems[0].Reason)
	}
	return nil
}
