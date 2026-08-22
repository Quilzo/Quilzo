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
  continuity. Apache-2.0 lets you take the code and keep going; this paragraph
  says you also have the project's blessing to carry the name forward, provided
  you say honestly that it changed hands. Note the difference from what this
  said under AGPL: a permissive licence guarantees you *may* continue, not that
  whoever continues has to publish what they do next.

## The licence, and the time it was changed

Quilzo is **Apache-2.0**. Contributions are taken under a
[DCO](https://developercertificate.org/) rather than a CLA, and copyright stays
with each contributor.

Until August 2026 this section said something else. It said Quilzo was
AGPL-3.0-or-later and that the licence *could not be quietly changed*, because
copyright was distributed and no single party could relicense it. Then the
licence was changed, by the single party who at that point held all of it.

The previous version of this file also said:

> If this ever changes, it changes in public, in this file, before it changes
> in the code.

This paragraph is that commitment being kept, and it is the only part of the
original arrangement that survived intact. The rest is worth setting out
plainly:

- **The protection was real for contributors and empty for the project.** A DCO
  does stop anyone relicensing code you wrote. It cannot stop a sole author
  relicensing code they wrote, and until August 2026 there was exactly one
  human author. The sentence overclaimed.
- **It is not empty any more.** From the second author onward, another licence
  change needs every author's agreement. The guarantee begins now rather than
  having existed before.
- **Nothing was retracted.** Every release made under AGPL-3.0-or-later stays
  available under those terms permanently.

Why it changed is in [NOTICE](NOTICE), stated as a decision with a reason rather
than as an inevitability.

## What is still true about money

**There is no open-core tier and there will not be one.** Every security
property — the audit log, the anchoring, the sandbox, the capability model, the
gates — is in the version you can clone. A CMS that put its access controls
behind a licence key would be arguing that its users deserve less protection
than its customers, and that is not an argument this project is willing to make.
The licence changed; that has not.

Money, if it comes, comes from **hosting and support**: running Quilzo for
people who would rather not, and helping people who run it themselves. Both are
services on top of software that stays whole, so neither requires holding a
feature back.

One model that used to be ruled out no longer is, and pretending otherwise would
be the same overclaim in a new place. **Dual licensing** was ruled out on the
grounds that it needs one party to hold the copyright and the DCO ensured nobody
did. Under Apache-2.0 there is no copyleft to sell an escape from, so the
question is moot rather than resolved — nobody needs to buy a permissive licence
that is already granted. **Open core** stays ruled out on its own merits, which
were never about the licence.

## Moving to a foundation

The intention is to place Quilzo under a neutral non-profit. That is not
possible yet, and the reasons are worth writing down so nobody has to rediscover
them:

- **The Apache Software Foundation** was permanently unavailable while Quilzo
  was AGPL — GPLv3-family licences are Category X under ASF policy. The licence
  change removes that bar. What it does not remove is the Incubator's actual
  gate, which is a community rather than a codebase, and one maintainer is not
  one. See [docs/apache-incubator-proposal.md](docs/apache-incubator-proposal.md),
  which is kept for the record with a note on where it stands.
- **Software Freedom Conservancy** requires "an existing, vibrant, diverse
  community" and does not take projects under a year old. Apache-2.0 is fine
  with them. The gate is community, not code.
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
