# Governance

## Where this project is, stated plainly

Quilzo was written by one person. It is being opened not to collect patches for
a project that stays under one person's control, but to find people who will
take it over. That is the actual goal, so this document exists before there is
anybody to govern.

Right now there is one maintainer. That is a risk to anybody depending on this,
and it is written at the top of this file rather than discovered later.

## Becoming a maintainer

The bar is deliberately low and deliberately concrete, because a governance
document that says "sustained contribution over time" is one where the existing
maintainer decides by feel and nobody else can tell when they qualify.

**Three merged pull requests of substance, and an interest in continuing.**

That is it. Ask, or wait to be asked — either works. "Of substance" excludes
typo fixes and formatting; it includes a bug fix with a test, a feature, a
refactor that removes something, documentation that explains a subsystem, or a
security finding with a fix.

A maintainer gets commit access, release rights, and a vote. Nobody is asked to
commit to hours, a rota, or a response time.

## How decisions get made

**Ordinary changes** — lazy consensus. Open a pull request. If no maintainer
objects within 72 hours, it can be merged. Two maintainers approving overrides
the wait.

**Changes to the structural claims** — the properties in the README and
[SECURITY.md](SECURITY.md), the zero-dependency rule, or the licence — need
explicit agreement from every maintainer, not silence. These are the reasons
somebody would choose Quilzo. Removing one is allowed; removing one quietly is
not.

**Disagreement** that a discussion does not resolve goes to a simple majority of
maintainers. If it is tied, the change does not happen. A tie means the project
was not convinced, and the default is the status quo.

## Succession, which is the point of this file

If the current maintainer disappears — and solo maintainers do — the project
must not disappear with them.

- Any maintainer may cut a release. There is no single release key: the workflow
  runs on a tag and uses GitHub's own token.
- Nothing in the release path depends on one person's machine, credentials or
  account. If it ever does, that is a bug and reporting it is welcome.
- After **six months** with no maintainer response to a direct request, the
  remaining maintainers may reorganise the project however they need to,
  including moving it and appointing themselves. No permission required, and
  this paragraph is the permission.
- If there are no maintainers left at all, anybody may fork and claim
  continuity. The Apache License's grant is perpetual and irrevocable, so the
  code stays available; this paragraph says you also have the project's
  blessing to carry the name forward, provided you say honestly that it
  changed hands.

## The licence

Quilzo is licensed under the [Apache License 2.0](LICENSE). Contributions are
taken under the same licence with a [DCO](https://developercertificate.org/)
sign-off. Copyright stays with each contributor; there is no contributor
licence agreement and no assignment.

A licence change needs every maintainer's explicit agreement, and it changes in
public, in this file, before it changes in the code.

## Money

**There is no open-core tier and there will not be one.** Every security
property — the audit log, the anchoring, the sandbox, the capability model, the
gates — is in the version you can clone. A system that put its access controls
behind a licence key would be arguing that its users deserve less protection
than its customers, and that is not an argument this project is willing to make.

Money, if it comes, comes from **hosting and support**: running Quilzo for
people who would rather not, and helping people who run it themselves.

## Moving to a foundation

The intention is to place Quilzo under a neutral non-profit. That is not
possible yet, and the reasons are worth writing down so nobody has to rediscover
them:

- **Software Freedom Conservancy** asks for "an existing, vibrant, diverse
  community that develops and documents the software", and generally does not
  take projects under development for less than a year. An OSI-approved licence
  is mandatory, which Apache-2.0 is. The gate is community, not code.
- **The Apache Software Foundation** releases everything under Apache-2.0,
  which Quilzo already uses, so no relicensing stands in the way. The Incubator
  adopts communities, so the gate is the same one.
  [docs/apache-incubator-proposal.md](docs/apache-incubator-proposal.md) is
  written and unsent.
- **NLnet / NGI Zero** funds individuals rather than adopting projects and its
  subject matter is exactly this one. It is funding rather than governance, and
  is the realistic near-term step.

So the order is: contributors first, foundation second. A foundation exists to
steward a community; there is no shortcut that skips having one.

## Code of conduct

The [Contributor Covenant](CODE_OF_CONDUCT.md) applies. Reports go privately to
the maintainers through this repository's "Report a vulnerability" form, titled
"Conduct report".

While there is one maintainer, a report about that maintainer has nowhere
independent to go. That is a real gap and it is named here rather than papered
over. Until there are at least three maintainers, anyone uncomfortable reporting
internally should raise it publicly in an issue; the project would rather handle
that awkwardly in the open than have it go unsaid.
