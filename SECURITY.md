# Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](../../security/advisories/new)**

That channel is private between you and the maintainers until an advisory is
published. It needs no email address from either side, which is deliberate —
this project is maintained pseudonymously and a disclosure process should not
depend on anybody publishing a personal address.

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
  API or the agent interface.
- **Tokens are scoped.** Any way a token performs an action outside its scope,
  or a principal's own grant.
- **The store is append-only and verifiable.** Any way to alter stored content
  such that `quilzo verify` still passes.
- **Nothing is executed from content.** Any way a template or an imported
  document causes code to run, or any way content decides what an extension is.

### What the extension boundary actually is, so nobody reports it as a bug

An extension is a subprocess. It gets an empty environment, a working directory
in the temporary area, a timeout, a bounded output, and a process group that is
killed as a unit. Those bound what it *inherits* and what it *costs*.

They do not bound what it can *read*. An extension runs with the uid of the
process that started it, so on a normal single-account deployment it can read
the token store, the policy and the key file — the same as any other program
that account runs. The mitigation today is operational: run extensions as an
account that owns nothing.

That is a real limitation and it is written here rather than implied away,
because "sandbox" is a word that promises more than a subprocess delivers.
Registering an extension is already an admin-only action for this reason.

**In scope**: an extension escaping the timeout, the output bound or the process
group; content choosing which extension runs or what it is given; an extension
reaching the store through the application rather than through the filesystem.

**Not currently in scope**: an extension reading files its uid can read. That is
the documented limit above, and closing it needs a capability-based sandbox
rather than a subprocess.

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

Until 1.0 the most recent release is the supported one. There are no backports
to earlier tags, and saying otherwise would be a promise this project cannot
currently keep.

## Our own claims, tested

The properties above are asserted by the test suite rather than argued for, and
a report is most useful when it makes one of those tests fail. Relevant places:

- `internal/tmpl` — the template language and its fuzz target
- `internal/a11y`, `internal/codescan` — the scanners
- `internal/auth` — roles, scopes, throttling
- `cmd/quilzo/gate_test.go` — every write surface consults the type gate
- `internal/admin/roles_test.go` — every role can do its own job and no more
