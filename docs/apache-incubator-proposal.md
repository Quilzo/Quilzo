# Quilzo — Apache Incubator Proposal

*Draft for discussion on `general@incubator.apache.org`. Not yet submitted:
this proposal has no Champion and no Mentors, and it should not be sent until
it has both.*

## Licensing, first, because it decides everything else

Quilzo is currently AGPL-3.0-or-later. The ASF classifies AGPL as
[Category X](https://www.apache.org/legal/resolved.html): it cannot be
included in an ASF product in source or binary form, and every ASF project is
released under Apache-2.0. So this is not a licence the Incubator could make
an exception for, and this proposal does not ask it to.

**The project will relicense to Apache-2.0 on acceptance.** That is offered
without reservation and it is clean to do:

- **Every commit in the repository was authored either by the proposer or by
  Dependabot bumping a version string in a workflow file.** There is one human
  contributor and he is the sole copyright holder. That is a property of the
  history rather than a count that goes stale: `git log --format='%ae' | sort -u`
  returns two addresses, one of which is a bot.
- Contribution is under a **DCO, not a CLA**. No third party's copyright has
  been aggregated, so nobody else's permission is needed and no
  contributor-agreement archaeology is required.
- There are **no dependencies at all** — `go.mod` has no `require` block — so
  there is no third-party licence to review, reclassify, or replace. The
  usual hardest part of an IP clearance is empty here.

An SGA can be filed as soon as a Champion asks for one.

### Why it was AGPL, and why that reasoning does not survive contact with ASF

The reasoning is worth stating rather than skipping, because it explains a
design choice that outlives the licence.

Nobody distributes a CMS; they host it. A licence whose obligations trigger on
distribution would never trigger at all for this category of software, so
GPL-3.0 would have been decorative. AGPL was chosen for one specific reason:
if somebody runs a modified Quilzo as a service, the people using that service
can have the source of what is actually running. For a system whose entire
argument is *"you can verify what was published"*, source availability at the
point of use was the licence that matched the architecture.

That reasoning is coherent and it is also **not the ASF's model**, and the
ASF's model has an argument this one does not: permissive licensing is what
allows a governance foundation to be a neutral home rather than a party to a
compliance relationship. Given a choice between AGPL and an ASF community, the
community is worth more to this project than the reciprocity clause. The
verifiability the AGPL was protecting is a property of the *design* — content
addressed by hash, publishing as a pointer move, an append-only audit chain —
and none of it depends on the licence.

One honest cost, stated because the Incubator will work it out anyway:
relicensing removes the obligation on a hosted fork to publish its changes. If
a vendor runs a modified Quilzo as a proprietary service, Apache-2.0 permits
it. That is a real loss and it is accepted.

---

## Abstract

Quilzo is a content management system with no query language over content, no
executable template language, and no plugin runtime — three capabilities
removed so that the vulnerability classes that depend on them cannot exist.
Content is immutable and addressed by the hash of its own bytes; publishing
moves a pointer.

## Proposal

Quilzo manages structured content and publishes a website from it, with the
capabilities a CMS is expected to have: content types, media, taxonomies,
menus, declared queries over structured data, forms, workflow, multiple
languages, staged environments, scheduled publication, and an audit trail.

It does them on a storage model borrowed from version control rather than from
a relational database, and that choice is the product rather than an
implementation detail. It is written in Go against the standard library only.

We propose to enter the Apache Incubator to build a governance structure and a
contributor community around it, and to relicense to Apache-2.0.

## Background

Content management systems are exploited in two recurring ways: a query an
attacker can influence, and a place where writing data means writing something
that later executes. WordPress's 2026 pre-auth RCE chained exactly those two;
Drupal's CVE-2026-9082 was the first on its own. The industry response is
patching, and patching is a response to instances rather than to classes.

Quilzo started in August 2026 from the position that those links can be
removed rather than hardened, and that they can only be removed at the level of
the storage model and the template language — which is why it is a new system
rather than a hardening guide for an existing one.

## Rationale

**Why this is worth a foundation's time, rather than a repository.**

Three reasons, in descending order of how unusual they are.

**1. It has no dependencies, which is the ASF's own hard problem, absent.**

`go.mod` has no `require` block. Not vendored, not pinned — none, with CI
failing the build if one appears. That cost a content-addressed merkle store, a
template language with a real parser, a CIDv1 encoder, an OIDC client with
PKCE, and Windows file locking via `LockFileEx`. Roughly 65,600 lines of
program with 34,500 lines of test across 1,229 test functions.

For the ASF specifically this is not an aesthetic claim. Third-party licence
review — Category A, B and X classification, LICENSE and NOTICE assembly,
re-review on every dependency bump — is a standing cost on every podling and a
recurring source of release-blocking issues. Here that work is empty and stays
empty by policy. The single supply-chain input is the Go toolchain itself, and
`go.mod` carries a comment explaining why it is pinned to a floor rather than
left open.

**2. Governance is the product, and the ASF is a governance foundation.**

Quilzo's differentiator is not that it manages content. It is that it can prove
what it published, refuse what it should not publish, and constrain what an
automated agent may do — and that these are enforced rather than documented.
That is an unusually close fit with an organisation whose core competence is
governance, and an unusually poor fit with a venture-funded company, where the
incentive is eventually to make the guarantees a paid tier.

**3. It is infrastructure that regulated users need and cannot currently get.**

Discussed under *Who this helps* below.

## Initial Goals

1. Relicense to Apache-2.0, file the SGA, and complete IP clearance.
2. Move to ASF infrastructure and Apache-style governance; grow the committer
   base beyond one person, which is the project's principal risk.
3. Cut a first Apache release. There is no 1.0 today; the release path is
   already automated, reproducible, and produces an attested container image.
4. Publish a measured prompt-injection benchmark result (see *AI*, below), so
   the project's central safety claim is evidence rather than architecture.

---

## What it is, and what other systems lack

### Immutable, content-addressed storage

Every object is named by the SHA-256 of its own bytes. Nothing is overwritten:
a change writes a new object, and the old one is still there. A commit names a
tree; an environment is a pointer at a commit.

Publishing therefore **moves a pointer**. Nothing is copied, re-serialised or
rebuilt on the way to production, so *"the bytes production serves are the
bytes staging served"* is an exact statement rather than a property of a
deterministic build. Rollback is another pointer move. History is free.

*What others lack:* Git-based CMSs share the version-control model but not the
content addressing, so their publish is a build and their rollback is a
rebuild. Database-backed CMSs have neither.

### A template language that cannot execute

Four constructs — a value, an `if`, a `for`, and an explicit `raw` — with no
function calls, no arithmetic, no comparisons, no field access on host values,
and no way to add a fifth. Values may pass through a **closed list of sixteen
filters** whose arguments are literals and can never name another value; that
line is what keeps a filter set from becoming an expression language.

*What others lack:* Go's own `text/template` calls methods, which is precisely
the capability a template language must not have. Twig, Liquid and Smarty each
have sandbox escapes in their CVE histories, because a sandbox around an
evaluator is a smaller claim than having no evaluator.

### No query language over content

Views are **declared queries** with typed parameters, a field allowlist and a
cost budget, resolved before rendering. A page names the listings it embeds and
the template receives data, never a callable. There is no string an attacker
can influence that becomes a query.

### Publishing that refuses rather than warns

A warning nobody reads is a feature nobody has. Publication stops on an
inaccessible page (checked by rendering it, not by inspecting the content), an
unmarked AI-generated page, a menu pointing at nothing, content violating its
own type, a claim the business cannot substantiate, or an image whose licence
has lapsed. Overriding is possible, explicit, and lands in the commit metadata
with a name attached.

*What others lack:* every CMS has a linter somebody turned off.

### One set of rules across three interfaces

A browser interface, a command line, and an agent interface over MCP. Every
capability exists in all three or carries a written reason why not — **and a
test walks the source and fails on the gap.** This project shipped a rule the
terminal honoured and the browser did not, more than once; the test exists
because the intention did not work.

### Approvals that are signatures over content

An approval names a content hash. Change one character and the hash changes and
the approval no longer applies to anything — not because a rule detects the
edit, but because it is an approval of different bytes.

*What others lack:* nearly every review system attaches approval to a *request*
rather than to *what was in it*, so an edit after approval carries the approval
forward. It is a hole most people never notice they have.

### Concurrent editing without locks

A write declares the commit it was based on; a write whose base has moved is
refused. In a content-addressed store that is exact rather than a heuristic
about timestamps. A three-way merge then resolves the collisions that are not
real ones — two people on different pages, or on different fields of one page —
and **never resolves a genuine disagreement by picking a side.** Locks exist,
are advisory, expire on their own, and have no break-lock button.

---

## How Quilzo uses AI, and why it is different

Most CMSs shipping AI mean one of two things: a text box that calls a model and
pastes the answer into a field, or an agent handed the operator's credentials
and asked to behave. The second is the interesting case and the dangerous one.

The problem is not that models are careless. A model reads content, and content
is written by people — commenters, contributors, whoever filled in a form.
Anything a model reads may have been written by an attacker. Prompt injection
is not a defect to be trained away; it is what happens when instructions and
data share a channel.

**So the model never holds the authority.** An agent's *manifest* is the whole
of what it may do: which capabilities, over which content, on what budget, at
what autonomy level — enforced at one chokepoint every operation passes
through. A completely hijacked agent can still only do what it declared before
anyone talked to it. The model chooses from that list; it cannot invent an
entry. This follows CaMeL ([arXiv:2503.18813](https://arxiv.org/abs/2503.18813)),
where the research settled: enforce policy outside the model with a
deterministic gate.

Two consequences that fall out rather than being bolted on:

- **Reading stored content taints the run**, as a fact that follows the data.
  Anything an agent produced after reading input somebody else could have
  written needs a person before it goes live, and the system knows which runs
  those are.
- **A model cannot approve its own work.** Approvals must come from principals
  and self-approval is forbidden; a model is not a principal. The rule that
  stops an editor rubber-stamping herself is the rule that stops a model
  shipping unreviewed.

There is also a governance layer for agent protocols. *Governance Gaps in Agent
Protocols* ([arXiv:2606.31498](https://arxiv.org/abs/2606.31498)) identifies six
things MCP, A2A and ACP cannot express: permissions, delegation with
accountability, budgets, provenance, revocation, and who answers for what an
agent did. Quilzo's agent card fills all six, published as an A2A governance
extension, so another system can read what this one will allow before it asks.

**What is honestly missing:** this has never been run against AgentDojo. That
benchmark is what would turn *"designed to resist injection"* into a measured
number, and until it is run the claim is architectural. It is tracked as issue
#33 and it is an explicit initial goal above. No CMS has published such a
figure; doing so is a contribution to the field and not only to this project.

---

## Who this helps

### Government and regulated organisations

FedRAMP 20x ended the era of the compliance PDF: since CR26 was finalised in
June 2026, packages carry machine-readable evidence, at least 70% of it
automated, with OSCAL required from 30 September 2026. That suits a system that
knows its own configuration better than one that must be described.

- `posture scan` reads the actual deployment, and every rule names the NIST SP
  800-53 controls it bears on and its OWASP category. **35 controls have an
  automated check.**
- **OSCAL 1.2.3 assessment results** are generated from that scan — the output
  of an assessment, which is what the format is for.
- A **CycloneDX 1.6 SBOM** derived from the build, and a crypto inventory with
  post-quantum positions.
- **Audit export** as OCSF, CEF or JSON Lines with an integrity envelope, so a
  receiving system can tell whether events were removed. Identifiers are
  pseudonymised unless explicitly requested, and requesting them is recorded.
- **GDPR Article 20** by export tested through a round trip; **Article 17** by
  keeping form submissions deliberately outside the append-only store, because
  an append-only store cannot erase.
- **EU AI Act Article 50** by refusing to publish unmarked AI-generated
  content.

For air-gapped or classified deployment: one static binary with no dependency
graph to review, a distroless container with no shell or package manager, no
telemetry, no outbound request an operator did not configure, and the entire
state in one directory.

*This is not an authorisation.* There is no ATO and no third-party assessment.
These are the artefacts an assessment needs, produced continuously.

### Companies

The commercial case is the same property seen from a different angle: a CMS
sits at the highest-value point in a web infrastructure, and every transitive
dependency in it is somebody else's release process inside yours. A zero-
dependency, single-binary system with no plugin runtime is a much shorter
conversation with a security team than a Node application with a dependency
tree in the hundreds.

Beyond that: exports that are tested by round trip in three formats plus an
RO-Crate research deposit, so leaving is a file copy rather than a project;
machine-readable crawl terms that grant search, AI training and AI
summarisation **separately**; and a `/catalogue.json` with schema.org Product
and Offer emitted from the same row the page rendered, for agentic discovery —
with a deliberate refusal to ever hold a payment credential.

---

## Current Status

Working, tested, and used to build its own demonstration site. Not yet 1.0, and
no backports to earlier tags. 65 packages; 1,229 test functions; CI runs tests,
`govulncheck`, gofmt and CodeQL on every pull request, with CodeQL a required
check on `main`.

### Meritocracy

The bar for commit access is written down in `GOVERNANCE.md` — three merged
pull requests of substance — specifically so nobody has to guess when they
qualify. Adopting Apache-style meritocracy is a formalisation of an intent
already documented, not a change of direction.

### Community

Effectively none yet, and this is the proposal's weakest point. It is stated
plainly rather than dressed up. There are three issues scoped and labelled for
a first contribution, each naming the file and the trap to avoid.

### Core Developers

One: the sole copyright holder and proposer. See *Homogenous Developers*
under Known Risks.

### Alignment

The ASF has been in this space before, and the honest answer is more
interesting than "no overlap".

**Apache Jackrabbit** (TLP) is a JCR content repository, and **Apache Sling**
(TLP) builds content-centric applications on top of one. Both are adjacent to
Quilzo and both made the opposite decision on the point that defines it: JCR
specifies a query language over content — XPath, and SQL-2 — and that
capability is precisely the one Quilzo removes. Quilzo is not a JCR
implementation and should not become one; its store is a content-addressed
merkle graph with declared queries resolved before rendering. There is no
dependency in either direction and adding one would breach the
zero-dependency rule.

So the relationship is coexistence rather than competition or duplication:
Jackrabbit and Sling serve applications that need a queryable repository, and
Quilzo serves ones that need to prove what they published. A user choosing
between them is choosing between those two properties, and both are
legitimate.

**Apache Lenya** was a Java/XML CMS and is retired to the Attic. That
precedent deserves to be raised by the proposer rather than by the Incubator.
Lenya's retirement is a reasonable prior that ASF CMS projects do not sustain
a community, and this proposal cannot refute it with evidence — it has a
smaller community than Lenya ever did. What it can offer is a different shape:
Lenya was a large Java application with a substantial dependency surface and a
plugin ecosystem, and Quilzo is a single binary with no dependencies and
deliberately no plugin ecosystem, which makes it materially cheaper to
maintain per contributor. Whether that is enough is a fair question for the
Incubator to press on.

There is also affinity with the ASF's own tooling preferences — no
dependencies, reproducible builds, an integrity-verifiable audit log — and the
project already emits CycloneDX and OSCAL, formats other ASF projects consume.

---

## Known Risks

### Homogenous developers, and reliance on a single developer

**The principal risk, and the reason this proposal may not be accepted as it
stands.** One contributor, in one place. The Incubator normally expects three
or more initial committers, ideally across organisations, and this proposal
cannot show that today.

It is stated first rather than buried, because a proposal that hides it wastes
a Champion's time. Three honest options, and the proposer's preference is the
first:

1. **Recruit two to three committers before submitting.** The proposal is
   stronger and the Incubator's core objection disappears. This is the intended
   path, and it means this document is not sent for some months.
2. Enter with one committer and treat community-building as *the* incubation
   goal. Podlings have done this; many have also retired.
3. Withdraw and seek a different home — the Commons Conservancy, or the
   Software Freedom Conservancy — where a single-maintainer project is less
   anomalous.

### Orphaned products

The proposer intends to continue development regardless of the outcome, and has
already put the release path outside any single machine or account. The
mitigation for orphaning is the same as for the risk above: more committers.
There is no external funding and therefore no funding to withdraw.

### Inexperience with open source

Real. The proposer has not previously run an open-source project at scale, has
not shepherded a foundation release, and would rely heavily on Mentors for the
release process, IP clearance and the ASF voting conventions. The project has,
however, been developed in public with a DCO, published security policy,
written governance, and disclosure-first handling of its own defects.

### Reliance on salaried developers

There are none. Quilzo is written in personal time, no employer funds or
directs it, and there is no corporate sponsor to withdraw. That removes the
"sponsor leaves, project dies" risk entirely and concentrates the bus-factor
risk, which is item one.

### Relationships with other Apache products

No dependency in either direction, and none is planned: taking a dependency on
an ASF project would breach Quilzo's own zero-dependency rule, which is a
tension worth naming now rather than discovering during incubation. It means
Quilzo cannot participate in the usual pattern of ASF projects building on one
another, and a Mentor may reasonably regard that as isolating.

The overlap that does exist is with Jackrabbit and Sling, discussed under
Alignment. It is a difference of design rather than a duplication of function,
but the Incubator should test that judgement rather than take it.

### An excessive fascination with the Apache brand

The attraction is specifically **governance**, and the reason is a design
constraint rather than marketing. A system whose value is that its guarantees
are enforced rather than promised needs a home where the guarantees cannot be
quietly made a paid tier. That is a structural argument for a foundation, and
the ASF is the foundation whose competence is exactly this.

If the Incubator's judgement is that the project is not ready — and the
single-committer objection is a fair reason to reach that judgement — the
proposer would rather hear it than receive a probationary yes.

---

## Documentation

- Source: <https://github.com/Quilzo/Quilzo>
- Manual: <https://quilzo.github.io>
- `SECURITY.md`, `GOVERNANCE.md`, `CONTRIBUTING.md` in-repo
- Live demonstration site, built with the tool: <https://quilzo.github.io/demo/>

## Initial Source

`https://github.com/Quilzo/Quilzo` — active since 14 August 2026. Single
copyright holder; DCO sign-off throughout.

## Source and Intellectual Property Submission Plan

The sole copyright holder will file a Software Grant Agreement and relicense to
Apache-2.0. No CLA has ever been used and no third-party copyright has been
aggregated, so there is no contributor to trace. No third-party code is
vendored or bundled.

## External Dependencies

**None.** `go.mod` contains no `require` block, and CI fails the build if one
appears. The only input is the Go toolchain (Go 1.27, BSD-3-Clause, Category
A). Build and test dependencies are likewise the toolchain alone.

## Cryptography

Quilzo uses cryptography and would require an ASF export-control notification.
All of it is from the Go standard library; none is implemented in-project.

| Primitive | Used for |
|---|---|
| SHA-256 | content addressing, the audit chain, the merkle log |
| SHA-384 / SHA-512 | OIDC ID-token signature verification |
| HMAC-SHA256 | audit-log pseudonymisation, webhook signatures |
| AES-256-GCM | encrypting objects at rest, wrapping data keys |
| ECDSA / RSA | verifying OIDC signatures; provenance signing |
| `crypto/rand` | token and identifier generation |
| `crypto/subtle` | constant-time comparison |

`quilzo compliance crypto` prints this inventory with post-quantum positions.

## Required Resources

- **Mailing lists:** `dev@`, `private@`, `commits@`, `users@`
- **Git:** `https://gitbox.apache.org/repos/asf/quilzo.git`
- **Issue tracking:** GitHub Issues (already in use)
- **Other:** a website, and CI on GitHub Actions as today

## Initial Committers

- Rashik Adhikari (`rsh1k`) — sole author and copyright holder

*Additional committers to be recruited before submission. See Known Risks.*

## Affiliations

- Rashik Adhikari — no affiliation relevant to this project. Quilzo is
  personal work: no employer funds it, no employer directs it, and no employer
  has any claim on it.

## Sponsors

### Champion

**Not yet identified.** This proposal should not be submitted until a Champion
has read it and agreed to shepherd it.

### Nominated Mentors

**None yet.**

### Sponsoring Entity

The Apache Incubator.
