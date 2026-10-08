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

These are on `main` and not yet in a release: report against `main`.

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

Until 1.0 the most recent release line is the supported one. That is v0.3.x.

v0.2.x is the previous line and had the security fixes made since v0.2.1
backported to it, as v0.2.2, on the `release-v0.2` branch. It is where to be if
v0.3 is too new for you; it is not where to stay.

v0.1.x is not supported and cannot usefully be. v0.2.0 was itself a security
release — an attribute-context escape, a replayable inbox request, an
unenforced `--own-only`, twenty of twenty-three agent operations checking no
authority — and a patch on top of v0.1.0 would leave every one of those. The
fix for v0.1.x is to move forward, not to wait for one.

Backporting is not a promise that everything reaches the release line. Some
fixes are for code added after it, so the defect is not there to fix; and a
check whose subject does not exist is left out rather than wired to fire on
nothing, because a table saying a gate ran is worse than a table without it.
The release line's own NEWS names each omission and why.

## Our own claims, tested

The properties above are asserted by the test suite rather than argued for, and
a report is most useful when it makes one of those tests fail. Relevant places:

- `internal/tmpl` — the template language and its fuzz target
- `internal/a11y`, `internal/codescan` — the scanners
- `internal/auth` — roles, scopes, throttling
- `cmd/quilzo/gate_test.go` — every write surface consults the type gate
- `internal/admin/roles_test.go` — every role can do its own job and no more
- `internal/agent` — the gate, narrowing, the breaker and receipts
- `cmd/quilzo/agent*_test.go` — runs, approvals, could-it and receipts end to end
- `internal/agentbox` — the box an agent's program runs in
- `internal/oauthas`, `cmd/quilzo/agentinterface_test.go` — connected apps
- `cmd/quilzo/mcpgateway_test.go` — the MCP gateway
- `internal/memory`, `internal/pii` — governed memory and the privacy guard
- `internal/shield/guardrails_test.go` — what a playbook may never do
