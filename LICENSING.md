# Licensing

Quilzo is available under **two licences, and you choose**. They are alternatives,
not conditions to satisfy together. The SPDX expression for that is `OR`, and it
is the expression carried in every source file:

```
SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial
```

Meeker's standing complaint about dual-licensed projects is that readers cannot
tell `OR` from `AND` and end up guessing from the website. This page exists so
nobody has to guess, and the test in [`docs_claims_test.go`](docs_claims_test.go)
exists so this page cannot quietly stop being true.

## Which one applies to you

**AGPL-3.0-or-later, unless you have signed the other one.** That is the default
and it is not a trial. You need no permission, no key and no conversation. Read
[LICENSE](LICENSE) for the terms; the short version is that if you run a modified
Quilzo as a service for other people, those people can have the source of what is
actually running.

You need the commercial licence in exactly one situation: **you cannot comply with
the AGPL, or you are not permitted to.** In practice that is two populations.

- Organisations whose policy prohibits AGPL code outright. Google
  [publishes theirs](https://opensource.google/documentation/reference/using/agpl-policy)
  — AGPL `MUST NOT` be used — and because it is one of the few public ones, others
  copy it. Defence, classified and regulated buyers are heavily represented here.
  A blanket ban is not a price objection; there is no price at which those buyers
  can take the AGPL.
- Vendors embedding Quilzo in a product they do not intend to release under the
  AGPL.

If you are hosting Quilzo, modifying it, charging for it, or building a business
on it, **and you are willing to offer your users the source of what you run**, the
AGPL already permits all of that and you need nothing further. That was true
before this page existed and this page does not narrow it.

## What the commercial licence is not

It is not a better version of the program. This is the commitment, stated so it
can be held against the repository later:

> **There is one Quilzo.** No feature is withheld for paying licensees, there is
> no separate enterprise build, and no code path anywhere in this repository
> branches on which licence the operator holds. The commercial licence changes
> the terms you hold the software under. It does not change the software.

That is a choice and not an inevitability — the usual thing to do here is open
core, where the free edition is deliberately the worse one. Open core makes the
project's own documentation adversarial, because every page has to be read
twice: once for what the software does, and once for whether the reader is
allowed to have it. A CMS whose argument is that you can verify what was
published cannot afford a second, unverifiable version of itself.

The commercial licence is also not a public licence. It is a negotiated,
signed agreement with one named party. Nobody acquires it by downloading
anything. See [LICENSES/LicenseRef-Quilzo-Commercial.txt](LICENSES/LicenseRef-Quilzo-Commercial.txt).

## Why AGPL is the base, and why it stays

The reasoning is in [NOTICE](NOTICE) and has not changed: nobody distributes a
CMS, they host it, so a licence triggered by distribution would never trigger.

What is worth adding here is that the industry tested the alternative and came
back. Elastic left Apache-2.0 for SSPL and ELv2 in 2021 and
[added AGPL back](https://www.elastic.co/blog/elasticsearch-is-open-source-again)
on 29 August 2024 — as a third option, in their words "simply adding another
option, and not removing anything". Redis left BSD-3 for SSPL and RSALv2 in
March 2024 and
[returned to AGPLv3](https://redis.io/blog/agplv3/) in May 2025, by which point
the Valkey fork had taken ground it has not given back. Both trips ended at
AGPL. Quilzo is already there.

So this is an addition and not a relicensing. **No permission anyone holds today
is withdrawn by it.** Every copy already taken stays under the terms it was taken
under, which is the same thing [NOTICE](NOTICE) says about the Apache-2.0 window
running in the other direction — a licence change decides what happens next and
cannot reach back, and that has to hold when the change is one you like.

## Contributions

Dual licensing needs inbound rights that a Developer Certificate of Origin does
not grant. A DCO says you had the right to submit your work under the project's
licence; it says nothing about the maintainer's right to offer it under a
commercial one.

Until this change the project took contributions under a DCO alone and said so
in strong terms. That is no longer sufficient and [CLA.md](CLA.md) explains what
replaced it, what it costs a contributor, and which parts of the old promise
survive. [CONTRIBUTING.md](CONTRIBUTING.md) records what the section used to say.

## The Apache-2.0 window

For approximately eighty minutes on 22 August 2026 this project was public under
Apache-2.0. That grant is permanent for anyone who took a copy, covering commits
`656bc88` through `67a85b8`, and it permits exactly the closed use a commercial
licence is otherwise needed for.

It is stated here, on the licensing page, rather than only in NOTICE, because a
prospective licensee's counsel will find it either way and there is no version of
this where they should find it from someone other than us.
