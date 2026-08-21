# Submitting Quilzo to the Apache Incubator

Everything below is ready to send. Two emails, in this order, from the address
you want subscribed.

---

## Step 1 — subscribe (required before you can post)

The list rejects mail from unsubscribed addresses, so this has to happen first.

**To:** `general-subscribe@incubator.apache.org`
**Subject:** *(anything — it is ignored)*
**Body:** *(empty)*

You will get a challenge email back. **Reply to it** without editing the
subject. That is the confirmation step; nothing is subscribed until you do it.

Give it a few minutes, then check you appear in the archive at
<https://lists.apache.org/list.html?general@incubator.apache.org>.

---

## Step 2 — the DISCUSS post

Send once subscription is confirmed. Plain text only — ASF lists strip HTML,
and a proposal that arrives as an unreadable blob starts badly.

**To:** `general@incubator.apache.org`
**Subject:** `[DISCUSS] Quilzo — a CMS with no query language, no template execution, and no dependencies`

Paste the body below, then paste the whole of
`docs/apache-incubator-proposal.txt` underneath it.

```
Hello,

I would like to propose Quilzo for the Incubator, and I am looking for a
Champion and Mentors. The full draft is below.

Quilzo is a content management system written in Go. Its defining property
is what it does not have: no query language over content, no executable
template language, and no plugin runtime. Those three are where CMS
vulnerabilities actually come from, and removing a capability removes the
whole class rather than the currently-known instances of it.

Three things I think make it worth the Incubator's time, and one that may
make it not:

1. It has no dependencies at all. go.mod has no require block -- not
   vendored, not pinned, none -- and CI fails the build if one appears.
   For the ASF specifically that means the Category A/B/X review, the
   LICENSE and NOTICE assembly, and the re-review on every dependency
   bump are all empty and stay empty by policy. The single supply-chain
   input is the Go toolchain.

2. Governance is the product rather than a feature of it. Quilzo's value
   is that it can prove what it published, refuse what it should not
   publish, and constrain what an automated agent may do -- enforced at a
   chokepoint rather than documented. A foundation is a better custodian
   of that than a company, where the incentive is eventually to make the
   guarantees a paid tier.

3. It produces the artefacts regulated users now need continuously rather
   than annually: OSCAL assessment results from a real posture scan
   against 35 NIST SP 800-53 controls, a CycloneDX SBOM from the build,
   and an audit export with an integrity envelope.

And the thing that may sink it: there is one committer. Me. I know the
Incubator normally expects three or more, ideally across employers, and I
would rather say so in the first message than have it drawn out of me. I
am willing to spend time recruiting before any vote, and I would value
frank advice on whether to do that first or to enter with community
building as the incubation goal.

On licensing. Quilzo is AGPL-3.0-or-later today. I understand AGPL is
Category X and that this is not something the Incubator could make an
exception for, so I am not asking it to: I will relicense to Apache-2.0,
without reservation, and file an SGA whenever a Champion asks for one.
The relicensing is clean -- one human contributor, a DCO rather than a
CLA, and no third-party code to reclassify. The draft explains why AGPL
was chosen and what dropping it costs.

One more thing I would rather say than have found. Quilzo has been
developed with substantial LLM assistance, and the git history says so --
71 of 174 commits carry a Co-Authored-By trailer naming the model. I have
read the ASF's generative tooling guidance. No third-party material is
included (the zero-dependency rule is enforced by CI, so there is nothing
vendored to have come from anywhere), the work is mine to represent as my
own, and I reviewed and tested every line before merging it. I used
Co-Authored-By where the ASF asks for Generated-by, and I will switch to
the ASF's token. The draft sets this out in the IP section.

It does not change the risk that matters. A project written quickly by one
person with a model is still a project with one person on it.

I have tried to write the risks section as an honest assessment rather
than a pitch, including the fact that Apache Lenya was an ASF CMS that
retired to the Attic, and that Jackrabbit and Sling are adjacent projects
which made the opposite decision on the point that defines this one.

Source:   https://github.com/Quilzo/Quilzo
Manual:   https://quilzo.github.io
Demo:     https://quilzo.github.io/demo/

Grateful for any feedback, and particularly for anyone willing to
Champion it.

Rashik Adhikari
```

---

## What happens next

Expect a lively thread and expect to rework the proposal — the guide says so
outright, and proposals that arrive perfect are usually proposals nobody
engaged with. Reply in plain text, quote inline rather than top-posting, and
concede the fair points quickly.

The single-committer question will come up. It is answered honestly in the
draft; do not argue it, ask for advice on it.

Once a Champion and Mentors are on board and the thread has settled, the final
version goes back to the same list as a `[VOTE]` thread.

---

## What is not done yet

- **No Champion.** Step 2 is partly a request for one.
- **No Mentors.**
- **One committer.** The strongest single thing you can do before the vote is
  bring in two or three more.
