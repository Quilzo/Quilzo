# Sources

Where the security record's facts come from, and whether they are still
coming: connectors that read an identity provider or a code host, pipelines
that push their results, and the freshness every source declares.

## A source

A source is a record in the register (`Source`), written through
`register.Put` by a person, asked of the policy and recorded in the audit
log. It says:

- how its facts arrive: a connector, a pipeline (`ci`), an import or an
  upload;
- how often it should report (`fresh`, in seconds);
- who answers for it (`owner`, a pseudonym; their address is in the
  subject map, not the register);
- the kind of actor it belongs to (`by`), which is the only kind whose facts
  are filed under it, so a person's table cannot overwrite a connector's
  observations;
- for a connector, the recipe it runs, the tool's region, the recipe's
  parameters and the exact hosts it may reach;
- for a pipeline, the repository and the workflow whose jobs may push to it.

## Connectors

A connector is a manifest (`internal/connector`): one host for data, one for
tokens, GET only, every field it keeps declared, a credential named and never
held. The engine and its tests were copied from a security team's own tools,
whose manifest format Quilzo shares; `testdata/manifest-format.json` is a
manifest in that format, and a test holds it to its digest so the two copies
stay one format. Quilzo's copy adds what reading configuration state needs:
a GitHub App's and a Google service account's signed token requests, a
second per-record key, a list of plain values as one field, and a refusal by
status. A host is one DNS name: a manifest that names a second host, a path
that is a URL, a next page on another host and a redirect anywhere are all
refused.

### The recipes, and the least each needs

| Recipe | Reads | Least privilege |
|---|---|---|
| `entra` | Microsoft Entra ID through Microsoft Graph: accounts, MFA registration (`userRegistrationDetails`), privileged directory roles, Conditional Access with authentication strengths, Intune devices | An app registration of its own with User.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory, Policy.Read.All and DeviceManagementManagedDevices.Read.All, admin consent, nothing else |
| `github` | The organisation's two-factor requirement, members and those without a second factor, owners, every repository's default branch protection by classic protection and by rulesets, Actions permissions | A GitHub App of its own with organisation Members, organisation Administration, repository Administration and repository Metadata, Read-only |
| `google-workspace` | Every account by its primary address: suspended, archived, administrator, 2-Step Verification enrolled and enforced | A service account with domain-wide delegation for `admin.directory.user.readonly` only, acting as an administrator who can read users |
| `okta` | Every user by login, their factors and whether one cannot be phished, administrators and super administrators, sign-on policies | An API token made by an administrator holding Read-Only Administrator and no other role |

A credential that holds more than its recipe needs is refused before it
reads anything: Graph's token carries its roles and one with any other is
refused; a GitHub installation token says what it holds and one with any
other permission, or any at the write level, is refused; a Google token's
granted scopes are compared with those asked for; an Okta token's own roles
are read first. `quilzo source recipes` and the Sources screen show the
same.

**Verified against recorded responses; report problems.** Each recipe is
tested against responses in `internal/sources/testdata`, made from the
tools' published documentation. No live tenant, organisation or domain was
read: none exists for this project. Report a recipe that reads a real tool
wrongly.

### A run

1. The source is read from the register, its recipe's manifest filled for
   its region and parameters, and the hosts that manifest reaches held to
   the source's own list. A source whose list differs does not run.
2. The credentials are read from the vault by the names the manifest gives
   (`quilzo source credential NAME CREDENTIAL`, from standard input). They
   are sealed under the store's keyring beside the store, each bound to its
   source and name; a store with no keyring keeps none (`quilzo vault
   enable` first). They are never in the register, a manifest, a flag or
   the environment.
3. The tool is read through a client that reaches only the source's hosts
   and follows no redirect (egress purpose `sources`). Every page is kept as
   it came.
4. The pages are one JSON document, sealed in the raw evidence store before
   anything reads it, and the recipe reads its facts from the sealed bytes:
   Observations by subject, each graded `connector`, with its source, the
   seal's time and the document's digest, written in one commit as the
   collector, a service that may write facts and nothing else. An account is
   its user principal name, login or address in the subject map, and its
   pseudonym in the register.
5. A run that reads what the last one read is the same document: it writes
   nothing, and its seal says the source reported.

A report the tool's licence does not include (Entra's registration report
without Entra ID P1 or P2, Intune's devices without Intune, GitHub's members
without a second factor for a token that is not an owner's) answers 403, and
is recorded as a licence gap on the tenant or the organisation, not as a
failure. Any other refusal writes nothing, and the run's problem is kept and
shown. GitHub's spent rate limit is waited out, up to two minutes a try.

## Pipelines: evidence pushed with no stored secret

A job in GitHub Actions or GitLab CI pushes a file (SARIF, a bill of
materials, OCSF findings, an advisory) with its platform's signed identity
token and a key it makes for the step, and holds no secret.

1. An administrator declares a trust for the issuer and the repository
   (`quilzo trust add`), whose principal may write the register's area, and
   a person adds the pipeline's source:
   `quilzo source add-pipeline docs-ci --repository octo/docs --workflow .github/workflows/evidence.yml`.
2. The job runs `quilzo evidence push results.sarif --format sarif --to https://quilzo.example.org`,
   or the action `actions/evidence-push` (GitHub, with `permissions:
   id-token: write`) or the job in `actions/evidence-push/gitlab-ci.yml`.
3. It exchanges the identity token at `/token/exchange` with a DPoP proof
   (RFC 9449) for a token of minutes bound to its key. That token keeps what
   the platform signed about the job: its repository and its workflow.
4. It posts the file to `/api/v1/evidence/import` with `Authorization: DPoP`
   and a fresh proof. The file is filed only under the pipeline's source
   that names that repository and that workflow, graded `ci`, and every
   repository the file itself names must be that one.

A push with the token as a bearer, with another key's proof, with a proof
used before, for another repository or from another workflow is refused and
writes nothing. A bound token is taken at that route alone.

## Freshness

A source reports when a file is sealed under it: a connector's run, a
pipeline's push, an upload. A source that has not reported within its window
is stale, and is named with its age, in a line code writes from its record
("Docs pipeline: last reported 3 days ago, on 22 Nov 2026, 10:00 UTC,
expected every 1 day"), first on the Sources screen, by `quilzo source
stale`, `source_stale` and `/api/v1/sources`, for the Posture of record to
show. On the server's upkeep timer each connector runs when half its window
has passed since its last run, and the owner of each stale source is mailed
once, on the first tick that finds it stale, and again only after it has
reported and gone stale again. Each telling, or why it could not be made, is
in the audit log (`source.stale`).

## Surfaces

- `quilzo source list | show NAME | stale | recipes | add | add-pipeline |
  owner | credential | run`, and `quilzo evidence push` in a pipeline's job.
- The admin's **Sources** screens: every source, stale first; one source
  with its hosts, last run, the least its credential needs and which
  credentials the vault keeps; adding a source; keeping a credential; a run.
- The agent interface: `source_list`, `source_stale`, `source_show` and
  `source_recipes`, read.
- The content API: `/api/v1/sources`, `/api/v1/sources/{name}`,
  `/api/v1/sources/recipes`, and `/api/v1/evidence/import`.

## What is and is not verified here

- The recipes are verified against recorded responses only, as above. The
  live run against a test tenant that the plan asked for could not be made.
- The Posture of record is another module's screen; it reads
  `sources.Standings` for the stale sources this page names.
- Mail goes through the relay in `mail.json`; with none, the tick records
  that the owner could not be told, and does not try again until the source
  has reported and gone stale again.
