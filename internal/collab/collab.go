// Package collab handles more than one person working on the same thing.
//
// # Three problems that turn out to be one
//
// Concurrent editing, the four-eyes principle and keeping a human in the loop
// on AI changes look like three features. They are one mechanism seen from
// three angles: every write says what it was based on, and every release says
// who agreed to exactly what.
//
// # Why locks are the smaller half
//
// The received wisdom is a checkout lock: a person opens a page, the system
// locks it, nobody else can edit until they release it. It scales badly and it
// leaves stale locks, because people close laptops. Every CMS that does this
// grows a "break lock" button, and the button is used constantly, and then the
// lock guarantees nothing.
//
// Optimistic control is the right shape for content editing, where conflicts
// are rare but must be detected. And in a content-addressed store it costs
// nothing: a write declares the commit it was based on, and a write whose base
// is no longer the current draft is a conflict. That is compare-and-swap, and
// it is exact — not a heuristic about timestamps.
//
// So there are locks here, and they are advisory. They stop two people wasting
// an afternoon on the same page. They are not the safety property, they expire
// on their own, and the code says so in the one place somebody would otherwise
// assume otherwise.
//
// # Why an approval is a signature over content, not a flag on a ticket
//
// Everywhere else, approval is a state: a row moves to "approved", and someone
// with edit rights changes the content afterwards. The approval survives,
// because it was attached to the request rather than to what was in it. Every
// review system has this hole and most people never notice.
//
// Here an approval names a content hash. Change one character and the hash
// changes and the approval no longer applies to anything — not because a rule
// says so, but because it is an approval of different bytes. Nothing has to
// detect the edit.
//
// # Human in the loop is the same mechanism
//
// A change written by a model is a change whose author cannot approve it,
// because a model is not one of the people the policy names. That is not a
// special case bolted on for AI; it falls out of requiring approvers to be
// principals and forbidding self-approval. The rule that stops Dana rubber
// stamping her own work is the rule that stops a model shipping unreviewed.
package collab

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Conflict describes a write that was based on something no longer current.
type Conflict struct {
	// Expected is the commit the writer thought they were changing.
	Expected string
	// Actual is what the draft is now.
	Actual string
	// By and At name whoever moved it, so the message can say who to talk to
	// rather than only that something happened.
	By string
	At time.Time
	// Pages are the page names that differ between the two, so a writer editing
	// an unrelated page can be told their change does not actually collide.
	Pages []string
}

func (c Conflict) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "the draft moved while you were working")
	if c.By != "" {
		fmt.Fprintf(&b, "; %s changed it", c.By)
		if !c.At.IsZero() {
			fmt.Fprintf(&b, " at %s", c.At.UTC().Format("15:04 on 2 Jan"))
		}
	}
	fmt.Fprintf(&b, "\n  you were editing %s, the draft is now %s",
		short(c.Expected), short(c.Actual))
	if len(c.Pages) > 0 {
		fmt.Fprintf(&b, "\n  the pages that differ: %s", strings.Join(c.Pages, ", "))
	} else {
		fmt.Fprintf(&b, "\n  no page you touched was changed, so this is safe "+
			"to retry against the current draft")
	}
	return b.String()
}

// Overlaps reports whether the conflicting change touched anything this writer
// also changed.
//
// A conflict that touches nothing in common is a conflict only in the sense
// that the ref moved. Treating it the same as a real collision is what teaches
// people to retry blindly, which is how the real ones get retried blindly too.
func (c Conflict) Overlaps(changed []string) []string {
	mine := map[string]bool{}
	for _, p := range changed {
		mine[p] = true
	}
	var both []string
	for _, p := range c.Pages {
		if mine[p] {
			both = append(both, p)
		}
	}
	sort.Strings(both)
	return both
}

// -- advisory locks ----------------------------------------------------------

// MaxLock is how long an advisory lock lasts.
//
// Thirty minutes, and it cannot be extended indefinitely. A lock that outlives
// the person holding it is the failure mode of every checkout system: they
// close a laptop, the lock stays, somebody adds a break-lock button, and the
// button gets used until the lock means nothing.
const MaxLock = 30 * time.Minute

// Lock is a claim that somebody is working on a page.
//
// Advisory. It never prevents a write — compare-and-swap does that, exactly and
// without expiry. This exists so two people do not each spend an afternoon on
// the same page and discover it at the end.
type Lock struct {
	Page   string `json:"page"`
	Holder string `json:"holder"`
	Since  int64  `json:"since"`
	Until  int64  `json:"until"`
	// Note is what they said they were doing, which is more useful than a name
	// on its own when deciding whether to interrupt them.
	Note string `json:"note,omitempty"`
}

func (l Lock) Held(now time.Time) bool { return now.Unix() < l.Until }

// Locks is the set of current claims.
type Locks struct {
	Locks []Lock `json:"locks"`
}

// Claim records that somebody is working on a page.
//
// Taking a lock somebody else holds is permitted and returns their claim, so
// the caller can say who and decide. Refusing would make this a real lock, and
// a real lock needs a break-glass button, and the button is the problem.
func (ls *Locks) Claim(page, holder, note string, now time.Time) (Lock, *Lock) {
	var existing *Lock
	kept := ls.Locks[:0]
	for _, l := range ls.Locks {
		if !l.Held(now) {
			continue // expired, drop it
		}
		if l.Page == page {
			if l.Holder != holder {
				e := l
				existing = &e
			}
			continue // replaced below
		}
		kept = append(kept, l)
	}
	mine := Lock{
		Page: page, Holder: holder, Note: note,
		Since: now.Unix(), Until: now.Add(MaxLock).Unix(),
	}
	ls.Locks = append(kept, mine)
	sort.Slice(ls.Locks, func(i, j int) bool { return ls.Locks[i].Page < ls.Locks[j].Page })
	return mine, existing
}

// Release drops a claim. Only the holder may.
func (ls *Locks) Release(page, holder string, now time.Time) bool {
	kept := ls.Locks[:0]
	found := false
	for _, l := range ls.Locks {
		if l.Page == page && l.Holder == holder {
			found = true
			continue
		}
		if l.Held(now) {
			kept = append(kept, l)
		}
	}
	ls.Locks = kept
	return found
}

// Active returns the locks currently held, dropping expired ones.
func (ls *Locks) Active(now time.Time) []Lock {
	var out []Lock
	for _, l := range ls.Locks {
		if l.Held(now) {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Page < out[j].Page })
	return out
}

// Holder returns who holds a page, if anyone.
func (ls *Locks) Holder(page string, now time.Time) (Lock, bool) {
	for _, l := range ls.Locks {
		if l.Page == page && l.Held(now) {
			return l, true
		}
	}
	return Lock{}, false
}

// -- dual authorization ------------------------------------------------------

// Approval is one person agreeing to one exact set of bytes.
type Approval struct {
	// Content is the hash of what was approved. This is what makes the approval
	// unfalsifiable by later editing: change anything and the hash changes and
	// this approval is about content that is no longer proposed.
	Content string `json:"content"`
	By      string `json:"by"`
	At      int64  `json:"at"`
	// Note is why they agreed, which is the part an auditor reads.
	Note string `json:"note,omitempty"`
}

// Proposal is a change waiting for the people who have to agree to it.
type Proposal struct {
	// Content is the hash of the commit being proposed.
	Content string `json:"content"`
	// Author is who wrote it. They may never approve it.
	Author string `json:"author"`
	// AuthorKind is human, service or ai. An AI-authored proposal always needs
	// a human, whatever the numeric threshold says.
	AuthorKind string     `json:"author_kind"`
	CreatedAt  int64      `json:"created_at"`
	Message    string     `json:"message,omitempty"`
	Approvals  []Approval `json:"approvals,omitempty"`
}

// Policy is how many people must agree, and who counts.
type Policy struct {
	// Required is how many distinct approvers are needed. Zero disables dual
	// authorization entirely, which is a legitimate choice for one person
	// running their own site and a terrible one for anybody else.
	Required int `json:"required"`
	// Approvers, if set, is the list of principals whose approval counts.
	// Empty means anybody the access policy allows to publish.
	Approvers []string `json:"approvers,omitempty"`
	// RequireHumanForAI makes an AI-authored change need at least one approval
	// from a human, independently of Required.
	//
	// On by default in NewPolicy, because the alternative is a model's work
	// reaching the public with a service account's approval — two machines
	// agreeing with each other, which is not what anyone means by review.
	RequireHumanForAI bool `json:"require_human_for_ai"`
	// RequiredHumans is how many of the approvals must come from people,
	// whatever wrote the change.
	//
	// Two-person integrity, as an environment that uses the phrase means it.
	// Required counts distinct approvers and does not ask what they are, so a
	// policy of two is satisfied by two service accounts — which is the same
	// hole RequireHumanForAI closes for model-authored work, left open for
	// everything else. A nightly import approved by the importer and the
	// deploy account meets "two approvals" and has been seen by nobody.
	//
	// Zero leaves the behaviour unchanged. Set to two, no publication happens
	// without two people, and the machines can hold as many credentials as
	// they like.
	RequiredHumans int `json:"required_humans,omitempty"`
}

// NewPolicy returns the default: two people, and a human on anything a model
// wrote.
func NewPolicy() Policy {
	return Policy{Required: 2, RequireHumanForAI: true}
}

// TwoPersonIntegrity is the policy an environment that uses the phrase means:
// two approvals, both from people, on everything.
//
// Offered as a named constructor rather than left to be assembled, because
// the assembly is where it goes wrong — Required: 2 alone reads like
// two-person integrity and is satisfied by two machines.
func TwoPersonIntegrity() Policy {
	return Policy{Required: 2, RequiredHumans: 2, RequireHumanForAI: true}
}

// Decision is the answer to "may this be published".
type Decision struct {
	Allowed bool `json:"allowed"`
	// Reason is written for whoever is blocked, not for a log.
	Reason string `json:"reason"`
	// Have and Need make the gap countable, so an interface can show progress
	// rather than only a refusal.
	//
	// Tagged separately. Declared as `Have, Need int` on one line they shared a
	// single json tag, so Need serialised as "have" and one of the two was
	// lost — an approval count that reads "2 of 2" when it is 1 of 2. go vet
	// catches this; nothing else would have.
	Have    int      `json:"have"`
	Need    int      `json:"need"`
	Missing []string `json:"missing,omitempty"`
}

// KindOf is how a caller reports what an approver is.
type KindOf func(principal string) string

// Evaluate decides whether a proposal has the agreement it needs.
//
// Approvals that name a different content hash are ignored rather than
// reported as invalid, because they are not invalid — they are approvals of
// something else. That distinction is the whole point: nothing has to detect
// that the content changed, because an approval of the old bytes was never an
// approval of the new ones.
func (p Policy) Evaluate(prop Proposal, kindOf KindOf, now time.Time) Decision {
	if p.Required <= 0 && !p.RequireHumanForAI {
		return Decision{Allowed: true, Reason: "dual authorization is not configured"}
	}

	allowed := map[string]bool{}
	for _, a := range p.Approvers {
		allowed[a] = true
	}

	seen := map[string]bool{}
	var valid []Approval
	var humans int
	for _, a := range prop.Approvals {
		if a.Content != prop.Content {
			continue // an approval of different bytes
		}
		if a.By == prop.Author {
			continue // self-approval, handled explicitly below
		}
		if len(allowed) > 0 && !allowed[a.By] {
			continue
		}
		if seen[a.By] {
			continue // one person, one approval, however many times they click
		}
		seen[a.By] = true
		valid = append(valid, a)
		if kindOf != nil && kindOf(a.By) == "human" {
			humans++
		}
	}

	// Self-approval is reported specifically, because "you need two approvals"
	// when somebody has already clicked approve reads as the system being
	// broken rather than as the rule doing its job.
	for _, a := range prop.Approvals {
		if a.By == prop.Author && a.Content == prop.Content {
			return Decision{
				Have: len(valid), Need: p.Required,
				Reason: fmt.Sprintf(
					"%s wrote this change and cannot also approve it. That is the "+
						"whole point of requiring a second pair of eyes — an "+
						"author who can approve their own work is one pair.",
					prop.Author),
			}
		}
	}

	if p.RequireHumanForAI && prop.AuthorKind == "ai" && humans == 0 {
		return Decision{
			Have: len(valid), Need: p.Required,
			Reason: "this change was written by a model, so it needs approval " +
				"from a person. Two machines agreeing with each other is not " +
				"review.",
		}
	}

	// Two-person integrity, checked before the count.
	//
	// Before the count because the message matters: "one of two approvals"
	// when two approvals exist and both are machines is a refusal nobody can
	// act on, and the action needed is a person, not another approval.
	if p.RequiredHumans > 0 && humans < p.RequiredHumans {
		return Decision{
			Have: len(valid), Need: p.Required,
			Reason: fmt.Sprintf(
				"this needs %d approval(s) from people and has %d. There "+
					"are %d approval(s) in total; the rest are service or "+
					"model accounts, and a change nobody has read is not "+
					"reviewed however many credentials agreed to it.",
				p.RequiredHumans, humans, len(valid)),
		}
	}

	if len(valid) < p.Required {
		d := Decision{
			Have: len(valid), Need: p.Required,
			Reason: fmt.Sprintf("%d of %d approvals; %d more needed",
				len(valid), p.Required, p.Required-len(valid)),
		}
		if len(allowed) > 0 {
			for who := range allowed {
				if !seen[who] && who != prop.Author {
					d.Missing = append(d.Missing, who)
				}
			}
			sort.Strings(d.Missing)
		}
		return d
	}

	who := make([]string, 0, len(valid))
	for _, a := range valid {
		who = append(who, a.By)
	}
	sort.Strings(who)
	return Decision{
		Allowed: true, Have: len(valid), Need: p.Required,
		Reason: "approved by " + strings.Join(who, " and "),
	}
}

// Approve records an agreement, refusing the cases that would make it
// meaningless.
func (prop *Proposal) Approve(by, note string, now time.Time) error {
	if strings.TrimSpace(by) == "" {
		return fmt.Errorf("an approval needs a name")
	}
	if by == prop.Author {
		return fmt.Errorf("%s wrote this change and cannot approve it", by)
	}
	for _, a := range prop.Approvals {
		if a.By == by && a.Content == prop.Content {
			return fmt.Errorf("%s has already approved this", by)
		}
	}
	prop.Approvals = append(prop.Approvals, Approval{
		Content: prop.Content, By: by, At: now.Unix(), Note: note,
	})
	return nil
}

// Stale reports approvals that no longer apply because the content changed.
//
// Reported rather than deleted. An auditor asking "who approved this before it
// was edited" has a real question, and silently dropping the record answers it
// with nothing.
func (prop Proposal) Stale() []Approval {
	var out []Approval
	for _, a := range prop.Approvals {
		if a.Content != prop.Content {
			out = append(out, a)
		}
	}
	return out
}

// Rebase moves a proposal to new content, keeping the old approvals as history.
//
// The approvals do not carry over, and no rule is needed to make that happen:
// they name the previous hash, so Evaluate no longer counts them.
func (prop *Proposal) Rebase(content, author string, now time.Time) {
	prop.Content = content
	prop.Author = author
	prop.CreatedAt = now.Unix()
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
