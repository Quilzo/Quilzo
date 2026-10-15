# Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](../../security/advisories/new)**

That channel is private between you and the maintainers until an advisory is
published. It needs no email address from either side, which is deliberate: a
disclosure process should not depend on anybody publishing a personal address.
Today there is one maintainer, Rashik Adhikari ([@rsh1k](https://github.com/rsh1k)),
who receives every report.

If private reporting is unavailable to you for any reason, open a public issue
containing only the words "security contact requested" and nothing else, and a
maintainer will open a private advisory to continue in.

## What to expect

| | |
|---|---|
| First response | within 5 days |
| Assessment and severity | within 14 days |
| Fix for a confirmed high or critical issue | within 30 days, or a written explanation of why longer |
| Credit | in the advisory, under whatever name you choose, including none |

There is no bounty. This project has no money. What it can offer is that your
report is taken seriously, fixed properly rather than patched around, and
credited.

## What counts

Quilzo makes specific structural claims, and a demonstration that any of them
is false is a vulnerability even without a working exploit:

- **Templates cannot execute.** Any input reaching `tmpl.Render` that causes
  code execution, unbounded resource use, or non-termination.
- **The public process cannot read content it should not.** Any path by which
  `quilzo site` reads a draft, a submission, a token, or a file outside the
  media library.
- **Stored content cannot become executable.** Any content field that reaches
  a browser unescaped without passing through `{% raw %}`.
- **Authorisation is enforced at the action, not the screen.** Any request that
  performs an action the caller's role does not permit, including through the
  API or the agent interface — and any state of the store in which the checks
  stop happening at all. A damaged policy file must refuse, not permit.
- **Tokens are scoped.** Any way a token performs an action outside its scope,
  or a principal's own grant.
- **The store is append-only and verifiable.** Any way to alter stored content
  such that `quilzo verify` still passes.
- **Nothing is executed from content.** Any way a template or an imported
  document causes code to run, or any way content decides what an extension is.

### The agent control plane

The same applies to the claims Quilzo makes about AI agents and the apps and
agents connected to it. A demonstration that any of these is false is a
vulnerability:

- **An agent cannot exceed its declaration.** Any action a run performs that its
  declaration, the agent's own role, or the access of the person who started it
  does not allow, whether a model, the agent's own program, a delegate or a task
  from another agent (A2A) chose it.
- **A model cannot approve its own work.** Any path by which a model or an agent
  approves a step, declares or widens an agent, or publishes without a person.
- **Asking first holds.** Any way the call that runs after approval differs from
  the call a person approved.
- **The exfiltration breaker holds.** Any way a run that holds private material
  and has read content somebody else wrote sends something outside without a
  person deciding.
- **A receipt proves what it says.** Any way to alter, add or leave out a record
  and still have `quilzo agent verify-receipt` accept it against the published
  keys.
- **A program stays in its box.** Any way an agent's program reads the store,
  reaches a host its declaration does not name, or keeps a capability.
- **A connected app acts as one person, and no more.** Any way an app does what
  its scope or its person's access does not allow, or keeps acting after that
  access ended or the connection was revoked.
- **The MCP gateway offers only what was agreed.** Any way a caller reaches a tool
  that is not declared and pinned, gets past its daily limit, or has a held call
  run without a second person.
- **Memory stays with its person.** Any way one person's runs recall what an agent
  learnt about somebody else, a held memory is recalled before a person confirms
  it, or forgotten memory is recalled at all.
- **Personal data stays out of prompts.** Any way a value the privacy guard masks
  reaches a model route that may not receive it.
- **The shield cannot be turned on the inside.** Any way a playbook blocks an
  internal network, locks every administrator out, or protects without ending.
- **A browser reaches only what it declares.** Any request an agent's browser
  makes to a host its declaration does not name, any press or typing that acts
  on a host it may only read, or any password it types reaching a page, a
  model or a record.
- **A command does only its kind.** Any command classed as reading that changes
  the workspace, any command that reaches the network without being classed and
  held as reaching it, or any command that leaves its box or outlives it.
- **A remembered step is held like a decided one.** Any step replayed from the
  action cache that skips the declaration, the breaker or asking first, or that
  replays what was typed in a run for another person.
- **A widening is read before it is allowed.** Any amendment to a declaration
  that lets an agent do more without `--widen` or a person's own hands on the
  agents screen, or a widening allowed and missing from the log.
- **What earns its way out of asking can lose it.** Any action that sends,
  pays, deletes, publishes or signs in going ahead without a person because
  of an earned record, an earned kind of action skipping the exfiltration
  breaker, or an earned record surviving a decline, a reviewer refusal, a
  breaker trip or a regressed evaluation.
- **Approving together stays honest.** Any way the approvals screen lets an
  action through that differs from what each waiting run showed, or batches
  one that writes, sends, pays, deletes or publishes.
- **An agent credential is its holder's alone.** Any way a credential is
  accepted without a fresh proof from the key it is bound to, for a grant it
  does not carry, after it was withdrawn, or for an agent whose sponsor can
  no longer act here.
- **A feature is what its card says.** Any way an installed feature stores,
  collects, shows or sends something its permission card did not list,
  installs on one person's approval when the card asked for two, changes or
  removes a block it did not make, publishes a page, or installs bytes other
  than the ones that were checked; or a signed package accepted without its
  signature checking out. A drafted package holding an agent, a webhook or a
  link to another site, or records imported that do not satisfy their type.
- **A REST operation sends what it declares.** Any way a call through a REST
  integration reaches a host other than the declared one, carries a
  parameter or header its operation does not declare, follows a redirect,
  sends its credential anywhere but the declared host, or runs after its
  declaration changed without being pinned again; or an import that fetches
  anything a document refers to.
- **A fact is replaced only by a fact that may replace it.** Any way a memory
  learnt after reading somebody else's words closes a fact before a person
  confirms it, a fact about one person closes one about another, or a
  replaced fact is recalled.
- **A lesson is advice, adopted on evidence.** Any way a lesson changes what
  an agent may do rather than what its model reads, reaches a run's prompt
  without a person adopting it for that model after a trial that helped,
  adopted while making planted instructions steer more cases, or carries a
  host, an address or a credential into a prompt.
- **The model door spends only for who may use it.** Any way a call at `/v1`
  reaches a model without a token whose person may draft, is charged to
  anyone but that token's person, goes unrecorded, recalls one person's
  memory into another's conversation, or keeps what an agent remembers there
  unheld after the conversation carried a tool's results or a picture.
- **A report states only what was computed and cited.** Any way a number
  reaches a research report's rendered text other than from a computation's
  values.json without the check flagging it, a citation is kept for a work no
  index returned, a computation reads the network or a file it was not given,
  or a model registers or amends a plan.
- **A permission reaches only what it was granted on.** Any way a permission
  granted on one agent or part of the store decides, runs or changes another,
  a model approves what an agent waits for, somebody who may manage an agent
  names its sponsor, or a package installs agents or webhooks for somebody
  who could not declare them.
- **A collection is reached only through a grant on it.** Any way somebody
  granted one collection, or a section of pages, reads, writes or learns the
  name of another collection through any interface.
- **An agent pays only within what a person allowed.** Any way a paying
  call goes ahead without a mandate that covers its payee, currency, tool,
  amount and what is left of the budget, or a person's approval of that one
  payment; any way a model grants, widens or revokes a mandate; any way a
  payment is earned away from asking; or any way a paid call leaves no
  receipt.
- **A shop sells only what its records say, to agents it can name.** Any
  way a price, a total or an availability on the UCP surface comes from a
  request rather than the published records; any way a cart, checkout or
  order is served to a request whose Web Bot Auth signature does not verify
  against a configured key, or a completion whose signature does not cover
  the body's digest; any way an order completes under a mandate whose
  issuer key is not configured, whose checkout_hash is not the hash of this
  shop's signed checkout for that session, or whose payee, amount or
  currency differ from the order; any way one mandate presentation
  completes two orders; or any way an order is recorded that the order book
  does not show.
- **A program's credential is what it was given and no more.** Any way a job
  is admitted by a trust whose issuer, audience or pinned claims its identity
  token does not satisfy, or exchanges one token twice; any way an exchanged
  token is wider, or lasts longer, than what it came from or what the trust
  says; any way a token bound to a key is accepted without a fresh proof made
  by that key, or a proof is accepted for another request, another address
  or a second time; or any way a bearer token that lasts more than an hour
  publishes, rolls back, grants, manages tokens or agents, or installs from
  another machine while token.proof_for_risky is on.
- **A brief carries no figure, link or words the model was not given.** Any
  way the text on Today's brief shows a number, a link or markup the model
  wrote, or anything from what somebody else wrote: an agent's question, a
  visitor's message, a finding's title or a log line.
- **An answer on Today shows only what its asker may read.** Any way a card
  in an answer or a kept view shows a record, a collection or an agent run
  its person may not read at the time it is drawn, or carries markup or a
  value the model wrote; or any way a record's contents reach the model
  answering the question.
- **A role an app declares reaches only that app's blocks.** Any way a role
  in a feature package grants anything beyond the package's own collections,
  pages and agents, or more than reading, writing or publishing them and
  running or approving its agents; any way a package grants a role to
  somebody, or widens a role people hold without somebody who may grant
  access; or any way a role's holder keeps part of it after it is removed.
- **A person's desktop is not used.** Any way a run reaches a person's keyboard
  or pointer. Desktop consent hands the session straight back.

Desktop cells are experimental. Their host side is in scope: anything inside a
cell reaching the host other than through its vsock, or a press or key that
commits to something going ahead without a person. The image and the helper
inside it are the operator's.

### What the extension boundary actually is

An extension is a subprocess. It gets an empty environment, a working directory
in the temporary area, a timeout, a bounded output, and a process group killed
as a unit. Those bound what it inherits and what it costs.

On Linux 5.13 or later it is also confined with Landlock, applied to a locked
thread that is then replaced by the extension itself — a Landlock domain is
inherited across execve, so the program starts already restricted. It may read
only the paths it is granted and its own binary, and from Linux 6.7 it may not
open a TCP connection at all.

What that does **not** cover, said plainly rather than implied away:

- **UDP**, below Landlock ABI 10. A confined extension cannot open TCP and can
  still send datagrams, including DNS.
- **Anything not Linux**, and any kernel without Landlock. There the older
  paragraph still applies: the extension runs with the uid that started it and
  can read the token store, the policy and the key file. `quilzo posture scan`
  reports this as `ext.unconfined` rather than leaving it to be discovered.

Registering an extension is an admin-only action, and on an unconfined host it
should be treated as equivalent to granting whoever wrote it everything this
process can read.

**In scope**: an extension escaping the sandbox, the timeout, the output bound
or the process group; content choosing which extension runs or what it is given;
an extension reaching the store through the application rather than through the
filesystem.

**Not in scope**: an extension reading files its uid can read *on a host with no
Landlock*. That is the documented limit above, and the posture rule exists to
make it visible.

Also in scope: authentication bypass, privilege escalation between roles,
IDOR on any resource, path traversal, SSRF from any fetcher, injection of any
kind, and anything that discloses a submission to somebody who should not read
it.

## What does not count

- Findings against a deployment that has the admin interface on a public
  interface. `quilzo serve` belongs on loopback behind your own authentication;
  the README and the manual both say so.
- Missing hardening headers on a response that carries no content.
- Denial of service by sending very large or very many requests. Rate limiting
  is configurable and the answer is to configure it.
- Automated scanner output with no demonstrated impact. A report saying a
  header is absent, without saying what that permits, will be closed.
- Anything requiring an already-compromised host or an already-valid admin
  credential.

## Supported versions

No release is published yet. Report against `main`, where fixes land.

## Our own claims, tested

The properties above are asserted by the test suite rather than argued for, and
a report is most useful when it makes one of those tests fail. Relevant places:

- `internal/tmpl` — the template language and its fuzz target
- `internal/a11y`, `internal/codescan` — the scanners
- `internal/auth` — roles, permissions, scopes, throttling
- `cmd/quilzo/gate_test.go` — every write surface consults the type gate
- `internal/admin/roles_test.go` — every role can do its own job and no more
- `internal/agent` — the gate, narrowing, the breaker and receipts
- `cmd/quilzo/agent*_test.go` — runs, approvals, could-it and receipts end to end
- `internal/agentbox` — the box an agent's program runs in
- `internal/oauthas`, `cmd/quilzo/agentinterface_test.go` — connected apps
- `cmd/quilzo/mcpgateway_test.go` — the MCP gateway
- `internal/modelapi`, `cmd/quilzo/modeldoor_test.go`, `internal/admin/modeldoor_test.go` — the model door
- `internal/research`, `cmd/quilzo/researchcmd_test.go` — research projects, claims and citations
- `cmd/quilzo/agentpermissions_test.go`, `internal/auth/permission_test.go` — who approves, runs and manages agents
- `internal/memory`, `internal/pii` — governed memory and the privacy guard
- `internal/shield/guardrails_test.go` — what a playbook may never do
- `internal/browser`, `internal/cdp` — the agent's browser and its request rule
- `internal/shell` — workspace commands, their kinds and their box
- `internal/actioncache` — remembered steps
- `internal/cell`, `internal/portal` — desktop cells and desktop consent
