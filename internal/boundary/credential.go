// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package boundary

import (
	"fmt"
	"sort"
	"strings"
)

// Narrowness is how close a platform lets you get to a log-only
// credential.
type Narrowness string

const (
	// LogOnly: the platform has a scope that reads the audit log and
	// nothing else. The good case, and not the common one.
	LogOnly Narrowness = "log-only"
	// ReadOnly: the narrowest credential is read-only across a wider
	// surface. Compromise reads more than the log and writes nothing.
	ReadOnly Narrowness = "read-only"
	// Broader: the narrowest credential carries capabilities beyond
	// reading — usually because the platform's token model inherits an
	// administrator's role rather than granting scopes.
	Broader Narrowness = "broader"
	// Local: no credential at anybody else's system. The log is a file or
	// a stream this deployment already has.
	Local Narrowness = "local"
)

// Costs says what this narrowness means for a compromise of the
// collector.
func (n Narrowness) Costs() string {
	switch n {
	case LogOnly:
		return "an attacker reads the audit log and nothing else"
	case ReadOnly:
		return "an attacker reads more than the log and cannot change " +
			"anything"
	case Broader:
		return "an attacker gets more than reading. This is the case that " +
			"cannot be fixed at this end, and the one worth compensating " +
			"for elsewhere"
	case Local:
		return "there is no credential to steal; the exposure is whatever " +
			"reaches the file"
	}
	return string(n)
}

// Acceptable reports whether a compromise stays within reading.
func (n Narrowness) Acceptable() bool { return n != Broader }

// Credential is what a source needs, and what that reaches beyond its log.
//
// Documented rather than measured, and a deployment verifies each against
// its own tenant — the same caveat internal/source carries about field
// paths, for the same reason: vendors move these and a table that is
// confidently wrong is worse than one that says it needs checking.
//
// What is worth carrying regardless of drift is the Narrowness. Whether a
// platform offers a log-only scope at all is a property of its permission
// model rather than of any particular release, it changes rarely, and it
// is the thing that decides whether the excess can be designed away or has
// to be compensated for.
type Credential struct {
	// Source is the issuer/stream internal/source knows it by.
	Source string `json:"source"`
	// Narrowest is the tightest documented credential that can read the
	// log.
	Narrowest string `json:"narrowest"`
	// Reach is what that credential reads beyond the log itself.
	Reach      string     `json:"reach,omitempty"`
	Narrowness Narrowness `json:"narrowness"`
	// Note carries what catches people out about this one.
	Note string `json:"note,omitempty"`
}

// Credentials is what each source costs to collect.
func Credentials() []Credential {
	return []Credential{
		{
			Source: "aws/cloudtrail", Narrowness: ReadOnly,
			Narrowest: "an IAM role with cloudtrail:LookupEvents, or read " +
				"on the trail's bucket, assumed cross-account",
			Reach: "the trail and nothing else, when scoped to the bucket",
			Note: "the good case: assume a role in a separate log archive " +
				"account with an external id, and the collector holds no " +
				"standing key at all",
		},
		{
			Source: "azure/activity", Narrowness: ReadOnly,
			Narrowest: "the Monitoring Reader role at the subscription",
			Reach:     "metrics and diagnostic settings as well as activity",
		},
		{
			Source: "gcp/audit", Narrowness: ReadOnly,
			Narrowest: "roles/logging.viewer, or a Pub/Sub subscriber on a " +
				"log sink",
			Reach: "every log in the project, not only the audit one",
			Note: "the sink is narrower than the viewer role: a sink with " +
				"a filter exports only what matches, so the subscriber " +
				"reads only that",
		},
		{
			Source: "entra/signin", Narrowness: LogOnly,
			Narrowest: "the Graph application permission AuditLog.Read.All",
			Note: "one of the few platforms where the audit log genuinely " +
				"has its own permission",
		},
		{
			Source: "workspace/login", Narrowness: LogOnly,
			Narrowest: "a service account with domain-wide delegation, " +
				"scoped to admin.reports.audit.readonly",
			Note: "the scope is log-only and the delegation is not: a " +
				"service account with domain-wide delegation is a standing " +
				"capability at the domain, and the scope is what bounds it",
		},
		{
			Source: "okta/system", Narrowness: Broader,
			Narrowest: "an OAuth service app with okta.logs.read, where " +
				"available; otherwise an API token, which inherits the " +
				"role of the administrator who created it",
			Reach: "with a token rather than a scoped app, everything that " +
				"administrator can do — including writes",
			Note: "the case this table exists for. If the tenant cannot " +
				"use a scoped application, there is no way to hold a " +
				"read-only credential, and the compensating control is " +
				"where the token lives rather than what it can do",
		},
		{
			Source: "duo/auth", Narrowness: ReadOnly,
			Narrowest: "an Admin API application with grant read log",
			Reach:     "the logs it grants, and not administration",
		},
		{
			Source: "crowdstrike/detections", Narrowness: ReadOnly,
			Narrowest: "an API client with read on detections or event " +
				"streams",
			Reach: "detections across the whole tenant",
			Note: "worth scoping to read: the same client model also " +
				"offers host containment, which is a write that stops a " +
				"machine working",
		},
		{
			Source: "jamf/events", Narrowness: ReadOnly,
			Narrowest: "an API role with read on the objects the webhook " +
				"reports",
			Reach: "device inventory",
		},
		{
			Source: "github/audit", Narrowness: LogOnly,
			Narrowest: "a token with read:audit_log",
			Note: "this scope did not exist until it was asked for: " +
				"pulling the audit log previously meant holding admin:org, " +
				"which is the shape of the problem across this table",
		},
		{
			Source: "kubernetes/audit", Narrowness: Local,
			Narrowest: "none; the audit log is a file or a webhook the " +
				"API server writes",
			Note: "the webhook backend is the better of the two, because a " +
				"file on the control plane is readable by whatever else " +
				"reaches that node",
		},
		{
			Source: "cloudflare/firewall", Narrowness: ReadOnly,
			Narrowest: "an API token with Logs Read, scoped to one zone",
			Reach:     "that zone's logs",
			Note: "scoping to a zone rather than an account is the " +
				"difference between one site and all of them",
		},
		{
			Source: "salesforce/login", Narrowness: Broader,
			Narrowest: "a user with View Event Log Files and API Enabled",
			Reach: "whatever else that user's profile grants, because the " +
				"permission attaches to a user rather than to a token",
			Note: "UNC6395 is what this looks like when it goes wrong: an " +
				"integration's tokens were used to query Salesforce across " +
				"seven hundred organisations, and the access was the " +
				"integration's rather than an attacker's own",
		},
		{
			Source: "slack/audit", Narrowness: LogOnly,
			Narrowest: "an org-level app with auditlogs:read",
			Note: "enterprise grid only; there is no audit log below it, " +
				"so on a lesser plan this source does not exist rather " +
				"than being harder to scope",
		},
		{
			Source: "snowflake/logins", Narrowness: ReadOnly,
			Narrowest: "a dedicated role with imported privileges on the " +
				"shared account usage database",
			Reach: "every account usage view, which describes the whole " +
				"warehouse's activity",
			Note: "there is no per-view grant on the share, so reading " +
				"login history means being able to read the rest of it",
		},
		{
			Source: "auditd/events", Narrowness: Local,
			Narrowest: "none; a local file somebody ships",
			Note: "the exposure is whatever can read the file on that " +
				"host, which is a question about the host rather than " +
				"about a credential",
		},
	}
}

// Credential finds one by source.
func CredentialFor(source string) (Credential, bool) {
	for _, c := range Credentials() {
		if strings.EqualFold(c.Source, source) {
			return c, true
		}
	}
	return Credential{}, false
}

// Concentration is what the collector holds across a set of sources.
//
// The number worth putting in front of somebody before they turn on the
// sixteenth connector. Each one is a reasonable decision and the sum of
// them is the largest concentration of authority in the estate.
type Concentration struct {
	Sources  int `json:"sources"`
	LogOnly  int `json:"log_only"`
	ReadOnly int `json:"read_only"`
	Broader  int `json:"broader"`
	Local    int `json:"local"`
	// Unfixable names the sources whose narrowest credential still
	// carries more than reading, because that is the part no care at this
	// end changes.
	Unfixable []string `json:"unfixable,omitempty"`
}

// Across measures the concentration over a set of source names.
func Across(sources []string) Concentration {
	var c Concentration
	for _, s := range sources {
		cred, ok := CredentialFor(s)
		if !ok {
			continue
		}
		c.Sources++
		switch cred.Narrowness {
		case LogOnly:
			c.LogOnly++
		case ReadOnly:
			c.ReadOnly++
		case Broader:
			c.Broader++
			c.Unfixable = append(c.Unfixable, s)
		case Local:
			c.Local++
		}
	}
	sort.Strings(c.Unfixable)
	return c
}

// Remote is how many sources need a credential at somebody else's system.
func (c Concentration) Remote() int { return c.Sources - c.Local }

// Why describes a concentration in the sentence worth reading.
func (c Concentration) Why() string {
	if c.Sources == 0 {
		return "nothing is being collected, so the collector holds nothing"
	}
	out := fmt.Sprintf(
		"collecting from %d source(s) means holding credentials at %d "+
			"platform(s). Compromising the collector reads all of them",
		c.Sources, c.Remote())
	if c.Broader == 0 {
		return out + ". Every one of those credentials is read-only or " +
			"narrower, so a compromise reads and does not change anything"
	}
	return out + fmt.Sprintf(
		". %d of them (%s) cannot be narrowed to reading alone, because "+
			"the platform offers no scope that does. That excess is not a "+
			"configuration mistake and cannot be fixed at this end — it is "+
			"the reason the collector belongs somewhere a bug in the "+
			"application cannot reach", c.Broader,
		strings.Join(c.Unfixable, ", "))
}

// Worst is the sources whose credentials reach furthest, for the list
// somebody works down.
func Worst() []Credential {
	out := append([]Credential(nil), Credentials()...)
	rank := map[Narrowness]int{
		Broader: 0, ReadOnly: 1, LogOnly: 2, Local: 3,
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Narrowness] != rank[out[j].Narrowness] {
			return rank[out[i].Narrowness] < rank[out[j].Narrowness]
		}
		return out[i].Source < out[j].Source
	})
	return out
}
