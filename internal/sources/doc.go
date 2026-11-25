// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package sources is where the security record's facts come from, and
// whether they are still coming: the connectors that read an identity
// provider or a code host, the pipelines that push their results, and the
// freshness every source declares.
//
// # A source is a record a person made
//
// A Source in the register (internal/register) says how its facts arrive,
// how often it should report, who answers for it, and the kind of actor it
// belongs to, which is the only kind whose facts are filed under it. A
// connector's source also names the recipe it runs, the region of the tool
// and the recipe's parameters, and the exact hosts it may reach; a
// pipeline's names the repository and the workflow whose jobs may push to
// it. Adding one is a write through register.Put like any other, asked of
// the policy gate and recorded in the audit log.
//
// # A recipe is a reviewed manifest and the code that reads its facts
//
// The four recipes (Microsoft Entra ID, GitHub, Google Workspace and Okta)
// are manifests in internal/connector's catalogue: one host for data and
// one for tokens, read-only, every field declared. What each yields as
// facts is code here (entra.go, github.go, workspace.go, okta.go), the
// same every time over the same pages. They are verified against recorded
// responses in testdata, made from the tools' published documentation,
// and not against live tenants, which this project has none of; the
// documentation says so, and asks for problems to be reported.
//
// Each recipe needs least privilege, and asks for it: the permissions are
// listed with the credential it needs (connector.Entry.Credentials,
// Recipe.Privilege), and a credential that turns out to hold more is
// refused before anything is read with it. Graph's token carries its roles
// and the engine refuses any not declared; a GitHub App's installation
// token says what it holds and is refused if that is more than read; a
// Google token's granted scopes are compared with those asked for; an Okta
// API token carries its maker's administrator roles, which are read first
// and refused unless they are Read-Only Administrator alone.
//
// # A run, from credential to fact
//
//  1. The source is read from the register, its recipe's manifest filled
//     for its region and parameters, and every host the manifest names
//     held to the source's own list: a source whose list differs from what
//     its recipe reaches does not run.
//  2. The credentials are read from the vault (credentials.go), sealed
//     under the store's keyring, by the names the manifest gives; they are
//     never in the register, the manifest, a flag or the environment, and a
//     store with no keyring keeps none.
//  3. The engine reads the tool through an HTTP client that reaches only
//     the source's hosts and follows no redirect, and hands every page over
//     as it came.
//  4. The pages are one JSON document (Run), sealed in the raw evidence
//     store before anything reads it, and its recipe reads facts from the
//     sealed bytes: each an Observation graded "connector", with its
//     source, the run's time on the seal and the document's digest, written
//     through Ingester.Collect in internal/evidence, which is Put.
//  5. A run that reads what the last one read writes no fact; its seal is
//     the source's run, and is when the source last reported.
//
// A report the tool's licence does not include (Entra's registration
// details without P1 or P2, Intune without its licence) answers 403, which
// is recorded as a licence gap and not a failure; any other failure writes
// nothing, so a run that stopped half way is never read as an estate with
// half of it missing.
//
// # A pipeline pushes with no stored secret
//
// A job in GitHub Actions or GitLab CI asks its platform for a signed
// identity token, makes a key that lives as long as the job, and exchanges
// the token at /token/exchange for a Quilzo token of minutes bound to that
// key (RFC 9449), under a trust a person declared (internal/federate). It
// then posts its file to /api/v1/evidence/import with a fresh proof made by
// the key. The repository and the workflow its platform signed are carried
// on that token, and the file is written only under a pipeline's source
// that names both (evidence.Push), graded "ci". A token presented without
// its proof is refused, and so is a push for another repository.
//
// # Freshness
//
// Every source declares how many seconds may pass between reports.
// Standing says, for each, when it last reported and whether it is stale;
// the Sources screen and the Posture of record name every stale source with
// its age. The upkeep job mails a stale source's owner once, on the first
// tick that finds it stale, and again only after it has reported and gone
// stale again (Alerts).
package sources
