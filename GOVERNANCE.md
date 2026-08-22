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
somebody would choose this over an established CMS. Removing one is allowed;
removing one quietly is not.

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
  continuity. The AGPL guarantees the code stays available; this paragraph says
  you also have the project's blessing to carry the name forward, provided you
  say honestly that it changed hands.

## The licence, and the time it was changed and changed back

Quilzo is **AGPL-3.0-or-later**, and contributions are taken under a
[DCO](https://developercertificate.org/) rather than a CLA. Copyright stays with
each contributor.

This section used to claim that made the licence unchangeable. On 22 August 2026
it was changed to Apache-2.0 and changed back about eighty minutes later, which
settles the question better than the claim did.

The previous version of this file also said:

> If this ever changes, it changes in public, in this file, before it changes
> in the code.

That part was kept, and it is the only part of the original arrangement that
survived the episode intact. The rest is worth setting out plainly:

- **The protection was real for contributors and empty for the project.** A DCO
  does stop anyone relicensing code you wrote. It cannot stop a sole author
  relicensing code they wrote, and there was exactly one human author. The
  sentence overclaimed.
- **It is not empty from the second author onward.** A further licence change
  then needs every author's agreement. The guarantee begins with the next
  contributor rather than having existed before.
- **Neither direction retracts anything.** Every release made under AGPL stays
  available under AGPL. The commits published during the Apache-2.0 window stay
  available under Apache-2.0, permanently, to anyone who took a copy. [NOTICE](NOTICE)
  names the commits and the times.

Why it changed and changed back is in [NOTICE](NOTICE), stated as a decision
with a reason rather than as an inevitability. The short version: it was
relicensed for a scenario the project turned out not to be pursuing, and a
licence changed for a plan that changed should change back.

## What is still true about money

**Quilzo stays fully AGPL-3.0-or-later. There is no open-core tier and there
will not be one.** Every security property — the audit log, the anchoring, the
sandbox, the capability model, the gates — is in the version you can clone. A
CMS that put its access controls behind a licence key would be arguing that its
users deserve less protection than its customers, and that is not an argument
this project is willing to make.

Money, if it comes, comes from **hosting and support**: running Quilzo for
people who would rather not, and helping people who run it themselves. Both are
services on top of software that stays whole, so neither requires holding a
feature back.

Two models are ruled out, and it is worth saying which and why:

- **Open core** would mean the paid tier subtracts from the free one, whatever
  the marketing says. It also breaks the security argument above.
- **Dual licensing** — selling a proprietary escape from the copyleft — is
  possible for as long as one party holds the copyright, which is today and not
  for long. It is ruled out by choice rather than by arithmetic, and the
  previous version of this file claimed the arithmetic did it. It did not.

## Moving to a foundation

The intention is to place Quilzo under a neutral non-profit. That is not
possible yet, and the reasons are worth writing down so nobody has to rediscover
them:

- **Software Freedom Conservancy** requires "an existing, vibrant, diverse
  community" and does not take projects under a year old. AGPL is fine with
  them. This is the target, and the gate is community, not code.
- **The Apache Software Foundation** is unavailable while Quilzo is AGPL —
  GPLv3-family licences are Category X under ASF policy — so going there means
  relicensing, which is a decision to make on its merits rather than as a side
  effect. See [docs/apache-incubator-proposal.md](docs/apache-incubator-proposal.md),
  which is written and unsent, and honest about the real gate being a community
  rather than a licence.
- **NLnet / NGI Zero** funds individuals rather than adopting projects and its
  subject matter is exactly this one. It is funding rather than governance, and
  is the realistic near-term step.

So the order is: contributors first, foundation second. A foundation exists to
steward a community; there is no shortcut that skips having one.

## Code of conduct

The [Contributor Covenant](CODE_OF_CONDUCT.md) applies. Reports go through
GitHub's private reporting to the maintainers.

While there is one maintainer, a report about that maintainer has nowhere
independent to go. That is a real gap and it is named here rather than papered
over. Until there are at least three maintainers, anyone uncomfortable reporting
internally should raise it publicly in an issue; the project would rather handle
that awkwardly in the open than have it go unsaid.
