# Contributor Licence Agreement

Until this document existed, this project took contributions under a Developer
Certificate of Origin and no contributor licence agreement, and
[CONTRIBUTING.md](CONTRIBUTING.md) said so in strong terms. That changed when the
project added a commercial licence alongside the AGPL. This page says what
replaced it and what it costs you, because a CLA introduced quietly is worse than
one introduced at all.

## Why a DCO was not enough

A DCO is a statement about the past: *I wrote this, or I have the right to submit
it, under the project's licence.* It grants the maintainer nothing beyond that.

A dual-licensed project needs something the DCO does not provide — the right to
offer your contribution under the commercial licence as well. Without it, the
first contribution from anybody else would make part of the program
non-relicensable, and either that part gets excluded from commercial builds
(which means two codebases, which [LICENSING.md](LICENSING.md) commits against)
or the commercial licence quietly ships code it has no right to. Both are worse
than asking.

## What we use

The [Harmony](https://www.harmonyagreements.org/) contributor agreements,
version 1.0, published by Project Harmony under CC-BY-3.0. Harmony is a set of
templates with explicit options rather than a single document, so the honest way
to state which agreement applies is to state the selections:

| Choice | Selection |
|---|---|
| Base agreement | **HA-CLA-I** — Contributor **Licence** Agreement, individual |
| Outbound licence (§2.1(d)) | **Option 5** — any licence, with the promise back that the contribution is also licensed under the project's original licences |
| Media (§2.1(e)) | Included — documentation, diagrams and site content |
| Third-party content (§3(d)) | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Governing law (§5.1) | **not yet set** — see below |
| Mechanism | Sign-off in the pull request, recorded against the PR |

Entity contributors — anybody contributing on an employer's behalf — need
**HA-CCLA-E** with the same selections.

### The two selections that matter, in plain terms

**It is the licence variant, not the assignment variant.** Harmony publishes both.
The assignment version (CAA) transfers copyright to the project; this one does
not. **Your copyright stays yours.** That was the part of the old promise worth
keeping and it is kept.

**Outbound option 5 is the only one that permits a commercial licence.** Harmony's
five options run from "the original licences only" up to "any licence". Options 1
through 4 restrict outbound licensing to open source licences and would make dual
licensing impossible, so option 5 is not a preference here, it is the requirement.

## What this actually costs you

Stated as a trade rather than as reassurance, because option 5 is the broadest of
the five and it would be dishonest to present it as a formality.

- **The maintainer may license code you wrote under commercial terms**, including
  to an organisation that will never publish its changes. If you contribute, some
  of your work may end up in a closed product that somebody paid for.
- **The promise back is what bounds that.** Option 5 requires that your
  contribution is *also* licensed under the project's original licences. So there
  is no version of this where your code exists only inside a closed product.
  Whatever you write stays available under AGPL-3.0-or-later, to everyone,
  permanently.
- **Copyright stays yours.** You keep every right you had. You can relicense your
  own contribution to anyone else, use it in your own proprietary work, or publish
  it separately. Nothing here is exclusive.
- **You cannot revoke it later.** That is true of every licence grant and is
  stated because "I'll withdraw it if the project changes hands" is a thing people
  assume and it is not available.

If that trade is not one you want to make, that is a reasonable position and the
project would rather you said so than signed. Bug reports, reproductions, design
review, documentation corrections that do not rise to authorship, and adversarial
testing are all contributions that need no agreement at all.

## What has not changed

- **Sign-off is still required.** The DCO has not been replaced by the CLA; the
  CLA is in addition. Every commit still carries `Signed-off-by`.
- **Copyright is still not assigned.** There is no CAA and none is planned.
- **Nothing already contributed is affected.** This applies to contributions made
  after it was published. A CLA cannot reach backwards any more than a licence
  change can, which is the position [NOTICE](NOTICE) takes about the Apache-2.0
  window and has to be the position here too.

## Before this is used on anybody

Two things are deliberately unfinished, and a contributor asked to sign an
unfinished agreement should be able to see that from here.

- **Governing law (§5.1) is not set.** Harmony asks for the jurisdiction the
  project's holder is in, and that is a fact about the maintainer rather than
  something to be guessed at. Until it is filled in, the agreement is incomplete.
- **This has not been reviewed by counsel.** Harmony's own adoption guidance says
  to obtain advice from counsel familiar with these issues before finalising the
  selections. That has not happened yet.

Until both are resolved, this document records an intended position. It is not
being enforced against anyone, and no contribution is being held up for a
signature that cannot yet be given properly.
