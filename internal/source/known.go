// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package source

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// Known is the mapping for each platform most estates already have.
//
// These are the documented shapes of each API's records, and a deployment
// verifies them against its own tenant rather than trusting this list: a
// vendor adds fields freely and moves them occasionally, and the whole
// design of this package is that the second case is caught rather than
// absorbed. Run a shape check against a real page before turning one on.
//
// What is worth carrying here regardless of drift is the part that is not
// guesswork: which OCSF class each stream is, which field is the identity
// and therefore what a join hangs off, and how far behind each source runs.
func Known() []Source {
	return []Source{
		// Cloud control planes: who did what to the infrastructure.
		cloudTrail(), azureActivity(), gcpAudit(),
		// Identity: who signed in, and whether it worked.
		entraSignIn(), workspaceLogin(), oktaSystem(), duoAuth(),
		// Endpoint and device: what is running, and on whose machine.
		crowdstrikeDetections(), jamfEvents(),
		// The software supply chain and what runs from it.
		githubAudit(), kubernetesAudit(),
		// Network and the edge.
		cloudflareFirewall(),
		// The applications the business actually keeps its data in.
		salesforceLogin(), slackAudit(), snowflakeLogins(),
		// On-premise, where there is no API and a line of text arrives.
		linuxAuditd(),
	}
}

// cloudTrail is AWS's API audit trail.
func cloudTrail() Source {
	return Source{
		Issuer: "aws", Tool: "AWS CloudTrail", Stream: "cloudtrail",
		Class: telemetry.ClassAPIActivity, Activity: 1,
		Time: "eventTime", Layout: time.RFC3339,
		// The ARN rather than the user name: a name is reused across
		// accounts and an ARN is not, and workforce joins on what is
		// unique.
		Actor:   "userIdentity.arn",
		Target:  "eventSource",
		Message: "eventName",
		// CloudTrail reports failure by the presence of an error code
		// rather than by a status field: neither list is set, so any
		// value at all means it did not work and an absent one means it
		// did.
		Outcome: "errorCode",
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableIP:        "sourceIPAddress",
			telemetry.ObservableUserAgent: "userAgent",
		},
		Require: []string{"eventTime", "eventName", "userIdentity.arn"},
		Keep: []string{"eventName", "eventSource", "awsRegion",
			"errorCode", "recipientAccountId", "userIdentity.type",
			"readOnly"},
		// Delivery is documented as typically within about fifteen
		// minutes of an API call, and batches rather than streams.
		Lateness: 15 * time.Minute,
	}
}

// entraSignIn is Microsoft Entra's sign-in log.
func entraSignIn() Source {
	return Source{
		Issuer: "entra", Tool: "Microsoft Entra ID", Stream: "signin",
		Class: telemetry.ClassAuthentication, Activity: 1,
		Time: "createdDateTime", Layout: time.RFC3339,
		// The object id, not the user principal name: a principal name
		// changes when somebody marries and the object id does not.
		Actor:   "userId",
		Target:  "appDisplayName",
		Device:  "deviceDetail.deviceId",
		Message: "appDisplayName",
		// Zero is success in this log and the failure codes number in the
		// hundreds, so the success value is the one worth naming.
		Outcome: "status.errorCode", Succeeded: []string{"0"},
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableIP: "ipAddress",
		},
		Require: []string{"createdDateTime", "userId", "status.errorCode"},
		Keep: []string{"userPrincipalName", "appDisplayName",
			"clientAppUsed", "conditionalAccessStatus",
			"riskLevelDuringSignIn", "location.countryOrRegion",
			"status.errorCode", "status.failureReason"},
		Lateness: 10 * time.Minute,
	}
}

// workspaceLogin is Google Workspace's login audit.
func workspaceLogin() Source {
	return Source{
		Issuer: "workspace", Tool: "Google Workspace", Stream: "login",
		Class: telemetry.ClassAuthentication, Activity: 1,
		From: "events.name",
		Activities: map[string]uint8{
			"login_success": 1, "login_failure": 1, "logout": 2,
		},
		Time: "id.time", Layout: time.RFC3339,
		// The profile id rather than the email, for the same reason as
		// Entra: an address is reassigned and a profile id is not.
		Actor:   "actor.profileId",
		Message: "events.name",
		Outcome: "events.name",
		Failed:  []string{"login_failure"},
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableIP:    "ipAddress",
			telemetry.ObservableEmail: "actor.email",
		},
		Require: []string{"id.time", "actor.profileId", "events.name"},
		Keep: []string{"actor.email", "id.applicationName", "events.name",
			"events.type"},
		Lateness: 30 * time.Minute,
	}
}

// oktaSystem is Okta's system log.
func oktaSystem() Source {
	return Source{
		Issuer: "okta", Tool: "Okta", Stream: "system",
		Class: telemetry.ClassAuthentication, Activity: 1,
		Time: "published", Layout: time.RFC3339,
		Actor: "actor.id", Target: "target.id",
		Message: "displayMessage",
		Outcome: "outcome.result", Failed: []string{"FAILURE", "DENY"},
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableIP:        "client.ipAddress",
			telemetry.ObservableUserAgent: "client.userAgent.rawUserAgent",
			telemetry.ObservableEmail:     "actor.alternateId",
		},
		Require: []string{"published", "actor.id", "eventType",
			"outcome.result"},
		Keep: []string{"eventType", "outcome.result", "outcome.reason",
			"actor.alternateId", "securityContext.isProxy",
			"client.geographicalContext.country"},
		Lateness: 5 * time.Minute,
	}
}

// azureActivity is the Azure resource activity log.
func azureActivity() Source {
	return Source{
		Issuer: "azure", Tool: "Microsoft Azure", Stream: "activity",
		Class: telemetry.ClassAPIActivity, Activity: 1,
		Time: "eventTimestamp", Layout: time.RFC3339,
		Actor:   "caller",
		Target:  "resourceId",
		Message: "operationName.localizedValue",
		Outcome: "status.value",
		Failed:  []string{"Failed", "Failure"},
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableIP: "httpRequest.clientIpAddress",
		},
		Require: []string{"eventTimestamp", "caller", "resourceId",
			"status.value"},
		Keep: []string{"operationName.value", "status.value", "level",
			"resourceGroupName", "subscriptionId", "category.value"},
		Lateness: 20 * time.Minute,
	}
}

// Find looks a source up by issuer and stream.
func Find(issuer, stream string) (Source, bool) {
	for _, s := range Known() {
		if strings.EqualFold(s.Issuer, issuer) &&
			strings.EqualFold(s.Stream, stream) {
			return s, true
		}
	}
	return Source{}, false
}

// Issuers is every namespace the built-in sources write identifiers under.
//
// The list internal/workforce needs to know it can join across, and the
// list to check when adding a source: a new mapping that spells an existing
// issuer differently breaks every join with no error.
func Issuers() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range Known() {
		if !seen[s.Issuer] {
			seen[s.Issuer] = true
			out = append(out, s.Issuer)
		}
	}
	sort.Strings(out)
	return out
}

// Slowest is the largest declared lateness across a set of sources.
//
// What a correlation over several of them has to wait for. A window closed
// on the fastest source's watermark is a window that never sees the slowest
// one, which is internal/correlate's failure arriving through the back door.
func Slowest(in []Source) (Source, time.Duration) {
	var worst Source
	var at time.Duration
	for _, s := range in {
		if s.Lateness > at {
			worst, at = s, s.Lateness
		}
	}
	return worst, at
}

// Advice says what a correlation across these sources has to wait for.
func Advice(in []Source) string {
	worst, at := Slowest(in)
	if at == 0 {
		return ""
	}
	return fmt.Sprintf(
		"a correlation across these has to wait %s, which is %s/%s — the "+
			"slowest of them. Closing on anything less is a window that "+
			"never sees it", plainly(at), worst.Issuer, worst.Stream)
}

// gcpAudit is Google Cloud's audit log.
func gcpAudit() Source {
	return Source{
		Issuer: "gcp", Tool: "Google Cloud", Stream: "audit",
		Class: telemetry.ClassAPIActivity, Activity: 1,
		Time: "timestamp", Layout: time.RFC3339,
		Actor:   "protoPayload.authenticationInfo.principalEmail",
		Target:  "protoPayload.resourceName",
		Message: "protoPayload.methodName",
		// A status with no code is success: Google omits the field
		// entirely on the ordinary path rather than writing a zero.
		Outcome: "protoPayload.status.code",
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableIP: "protoPayload.requestMetadata.callerIp",
			telemetry.ObservableUserAgent: "protoPayload.requestMetadata." +
				"callerSuppliedUserAgent",
		},
		Require: []string{"timestamp", "protoPayload.methodName",
			"protoPayload.authenticationInfo.principalEmail"},
		Keep: []string{"protoPayload.methodName",
			"protoPayload.serviceName", "protoPayload.status.message",
			"resource.type", "severity", "logName"},
		Lateness: 10 * time.Minute,
	}
}

// duoAuth is Duo's authentication log.
func duoAuth() Source {
	return Source{
		Issuer: "duo", Tool: "Duo", Stream: "auth",
		Class: telemetry.ClassAuthentication, Activity: 1,
		Time: "isotimestamp", Layout: time.RFC3339,
		Actor: "user.key", Target: "application.name",
		Device:  "access_device.hostname",
		Message: "reason",
		Outcome: "result", Succeeded: []string{"success"},
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableIP: "access_device.ip.address",
		},
		Require: []string{"isotimestamp", "user.key", "result"},
		Keep: []string{"result", "reason", "factor", "user.name",
			"application.name", "access_device.location.country"},
		Lateness: 5 * time.Minute,
	}
}

// crowdstrikeDetections is Falcon's detection stream.
func crowdstrikeDetections() Source {
	return Source{
		Issuer: "crowdstrike", Tool: "CrowdStrike Falcon",
		Stream: "detections",
		// A detection rather than an activity: this source has already
		// decided something is wrong, which is a different claim from a
		// log line and belongs in a different class.
		Class: telemetry.ClassDetection, Activity: 1,
		Time: "created_timestamp", Layout: time.RFC3339,
		Actor: "device.hostname", Target: "behaviors.filename",
		Device:  "device.device_id",
		Message: "behaviors.description",
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableHash:    "behaviors.sha256",
			telemetry.ObservableProcess: "behaviors.filename",
			telemetry.ObservableIP:      "device.external_ip",
		},
		Require: []string{"created_timestamp", "device.device_id",
			"behaviors.description"},
		Keep: []string{"max_severity_displayname", "status",
			"behaviors.tactic", "behaviors.technique",
			"behaviors.pattern_disposition", "device.platform_name"},
		Lateness: 2 * time.Minute,
	}
}

// jamfEvents is Jamf Pro's device event stream.
func jamfEvents() Source {
	return Source{
		Issuer: "jamf", Tool: "Jamf Pro", Stream: "events",
		Class: telemetry.ClassAccountChange, Activity: 1,
		Time: "eventTimestamp", Layout: time.RFC3339,
		Actor: "event.username", Device: "event.udid",
		Message: "webhook.webhookEvent",
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableHostname: "event.deviceName",
		},
		Require: []string{"eventTimestamp", "event.udid",
			"webhook.webhookEvent"},
		Keep: []string{"webhook.webhookEvent", "event.deviceName",
			"event.osVersion", "event.model", "event.serialNumber"},
		Lateness: 10 * time.Minute,
	}
}

// githubAudit is an organisation's audit log.
//
// Worth having for a reason beyond completeness: a repository is where
// the code and the pipeline credentials live, so a change to who can
// reach it is a change to what an attacker inherits.
func githubAudit() Source {
	return Source{
		Issuer: "github", Tool: "GitHub", Stream: "audit",
		Class: telemetry.ClassAPIActivity, Activity: 1,
		// GitHub writes milliseconds since the epoch rather than a
		// formatted time, and the layout says so instead of a mapping
		// quietly producing 1970.
		Time: "@timestamp", Layout: LayoutEpochMilli,
		Actor: "actor", Target: "repo", Message: "action",
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableIP: "actor_ip",
		},
		Require:  []string{"@timestamp", "actor", "action"},
		Keep:     []string{"action", "repo", "org", "business", "actor_ip"},
		Lateness: 5 * time.Minute,
	}
}

// kubernetesAudit is the API server's audit log.
func kubernetesAudit() Source {
	return Source{
		Issuer: "kubernetes", Tool: "Kubernetes", Stream: "audit",
		Class: telemetry.ClassAPIActivity, Activity: 1,
		Time: "requestReceivedTimestamp", Layout: time.RFC3339Nano,
		Actor: "user.username", Target: "objectRef.resource",
		Message: "verb",
		// The HTTP status: two hundreds are the ordinary path and
		// enumerating them is shorter than enumerating the rest.
		Outcome:   "responseStatus.code",
		Succeeded: []string{"200", "201", "202", "204"},
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableIP: "sourceIPs",
		},
		Require: []string{"requestReceivedTimestamp", "user.username",
			"verb"},
		Keep: []string{"verb", "objectRef.resource",
			"objectRef.namespace", "objectRef.name",
			"responseStatus.code", "annotations"},
		Lateness: 2 * time.Minute,
	}
}

// cloudflareFirewall is the edge's view of what was turned away.
func cloudflareFirewall() Source {
	return Source{
		Issuer: "cloudflare", Tool: "Cloudflare", Stream: "firewall",
		Class: telemetry.ClassHTTPActivity, Activity: 1,
		Time: "datetime", Layout: time.RFC3339,
		Target: "clientRequestPath", Message: "ruleId",
		Outcome: "action", Succeeded: []string{"allow", "log", "skip"},
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableIP:        "clientIP",
			telemetry.ObservableUserAgent: "userAgent",
			telemetry.ObservableHostname:  "clientRequestHTTPHost",
		},
		Require: []string{"datetime", "clientIP", "action"},
		Keep: []string{"action", "ruleId", "source",
			"clientCountry", "clientAsn", "clientRequestHTTPMethodName"},
		Lateness: 3 * time.Minute,
	}
}

// salesforceLogin is Salesforce's login history.
//
// In the list because of UNC6395: in August 2025 OAuth tokens stolen from
// one integration vendor were used to query Salesforce across more than
// seven hundred organisations. The tell was in this log, and most of those
// organisations were not reading it.
func salesforceLogin() Source {
	return Source{
		Issuer: "salesforce", Tool: "Salesforce", Stream: "login",
		Class: telemetry.ClassAuthentication, Activity: 1,
		Time: "LoginTime", Layout: time.RFC3339,
		Actor: "UserId", Target: "Application",
		Message: "LoginType",
		Outcome: "Status", Succeeded: []string{"Success"},
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableIP: "SourceIp",
		},
		Require: []string{"LoginTime", "UserId", "Status"},
		Keep: []string{"Status", "LoginType", "Application",
			"ApiType", "Browser", "Platform", "CountryIso"},
		Lateness: 15 * time.Minute,
	}
}

// slackAudit is an enterprise grid's audit log.
func slackAudit() Source {
	return Source{
		Issuer: "slack", Tool: "Slack", Stream: "audit",
		Class: telemetry.ClassAPIActivity, Activity: 1,
		Time: "date_create", Layout: LayoutEpochSecond,
		Actor: "actor.user.id", Target: "entity.type",
		Message: "action",
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableIP:    "context.ip_address",
			telemetry.ObservableEmail: "actor.user.email",
		},
		Require:  []string{"date_create", "actor.user.id", "action"},
		Keep:     []string{"action", "entity.type", "context.ua"},
		Lateness: 10 * time.Minute,
	}
}

// snowflakeLogins is the data warehouse's login history.
//
// Here because a warehouse is where the copies of everything end up, so a
// credential that works against it is worth more than most.
func snowflakeLogins() Source {
	return Source{
		Issuer: "snowflake", Tool: "Snowflake", Stream: "logins",
		Class: telemetry.ClassAuthentication, Activity: 1,
		Time: "EVENT_TIMESTAMP", Layout: time.RFC3339,
		Actor: "USER_NAME", Target: "CLIENT_IP",
		Message: "EVENT_TYPE",
		Outcome: "IS_SUCCESS", Succeeded: []string{"YES"},
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableIP: "CLIENT_IP",
		},
		Require: []string{"EVENT_TIMESTAMP", "USER_NAME", "IS_SUCCESS"},
		Keep: []string{"IS_SUCCESS", "ERROR_MESSAGE",
			"FIRST_AUTHENTICATION_FACTOR", "SECOND_AUTHENTICATION_FACTOR",
			"REPORTED_CLIENT_TYPE"},
		Lateness: 30 * time.Minute,
	}
}

// linuxAuditd is a machine with no API, whose lines somebody ships.
//
// The on-premise case, and it is different in kind from the rest: there is
// no vendor to change a field name, and instead the risk is that whoever
// configured the shipper chose different keys from whoever wrote this. The
// requirement list is short for that reason.
func linuxAuditd() Source {
	return Source{
		Issuer: "auditd", Tool: "Linux auditd", Stream: "events",
		Class: telemetry.ClassProcessActivity, Activity: 1,
		From: "type",
		Activities: map[string]uint8{
			"EXECVE": 1, "SYSCALL": 1, "USER_LOGIN": 1, "USER_AUTH": 1,
		},
		Time: "@timestamp", Layout: time.RFC3339,
		Actor: "auid", Device: "host", Message: "type",
		Outcome: "res", Succeeded: []string{"success"},
		Observables: map[telemetry.ObservableKind]string{
			telemetry.ObservableProcess:  "exe",
			telemetry.ObservableHostname: "host",
		},
		Require: []string{"@timestamp", "host", "type"},
		Keep: []string{"type", "exe", "auid", "uid", "res", "key",
			"comm", "tty"},
		Lateness: time.Minute,
	}
}
