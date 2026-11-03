// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package accessreview is the review of the access Quilzo itself grants,
// and nothing wider.
//
// # What it reviews
//
// Three kinds of grant only this program holds: the bindings somebody made
// by hand, what each identity provider group means here (one item for each
// mapping, however many people are in the group), and the long-lived
// tokens. That is the population AC-2 asks an organisation to review, as
// far as this system is concerned, and nothing else can review it: another
// system's access review reads that system's exports, and an export of
// policy.json is a copy of last week's answer.
//
// What it leaves out, and why. Sessions end within a day by themselves.
// An agent's identity ends and is renewed, and the renewal is its
// recertification (the posture rule agent.identity-ending). A binding
// provisioning made is the identity provider's to review, because the next
// sync would put back whatever was taken away here. And the site's members
// are the public, holding nothing in the admin.
//
// # Why it was missing
//
// Nothing here recorded a review. A binding had no field saying anybody had
// looked at it since it was made, `quilzo token stale` printed a list and
// changed nothing, and the controls table left "reviews the people and
// tokens screens" to the customer, which is a sentence and not a record.
//
// # The four rules that make a review one
//
// The reviewer is named, and is a person: whether somebody still needs
// access is a question about what they do all day, which a model cannot
// see and a service account was never asked. Nobody reviews their own
// access, under any spelling of their name, because a self-certification
// with extra steps is the commonest way a review is worthless. And keeping
// privileged access needs a reason, because that is the decision nobody
// writes down and the one an auditor samples.
//
// A snapshot is taken when a review starts, so a binding granted half way
// through is reported at the close as not reviewed rather than slipping in
// as though it had been.
package accessreview

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/scim"
)

// Dormant is how long without any activity makes an item dormant.
//
// Ninety days, the same as the posture scan's token.stale rule, so the
// review and the scan never disagree about which credential nobody uses.
const Dormant = 90 * 24 * time.Hour

// DefaultEvery is how often a review is due when access.review.every is
// not set.
const DefaultEvery = 90 * 24 * time.Hour

// ControlID is the built-in periodic control a closed review evidences.
const ControlID = "quilzo/AC-2 account review"

// provisioned is who provisioning records as having granted a binding
// (cmd/quilzo's scimBy). Those bindings are the identity provider's to
// review: taking one away here is undone by its next sync.
const provisioned = "scim"

// Kind is what an item is.
type Kind string

const (
	// Binding is a grant somebody made by hand, or an app role assigned as
	// one.
	Binding Kind = "binding"
	// Mapping is what an identity provider group means here.
	Mapping Kind = "mapping"
	// Credential is a long-lived token. Named for what it is rather than
	// "token", which the audit log refuses as a detail key and would drop
	// the record of revoking it with.
	Credential Kind = "credential"
)

// Verdict is what a reviewer decided.
type Verdict string

const (
	// Keep is this access is still right.
	Keep Verdict = "keep"
	// Revoke is it goes, at once.
	Revoke Verdict = "revoke"
)

// Item is one grant, as it stood when the review started.
type Item struct {
	// ID is the item's number in its review, which is what a reviewer
	// types; numbered after sorting, so item 1 is the most urgent.
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	// Principal is who holds a binding or a credential.
	Principal string `json:"principal,omitempty"`
	// Group is a mapping's identity provider group, and Members the people
	// in it when the review started, for telling whether a reviewer is
	// reviewing a group they are in.
	Group   string   `json:"group,omitempty"`
	Members []string `json:"members,omitempty"`
	// Credential is a token's id, and Name what it was called.
	Credential string `json:"credential,omitempty"`
	Name       string `json:"name,omitempty"`
	// Role is the role, permission or job granted, or the app role for one
	// assigned as such (AppRole), and Resource where.
	Role     string `json:"role"`
	Resource string `json:"resource,omitempty"`
	AppRole  bool   `json:"app_role,omitempty"`
	// Via is how it was granted, in words.
	Via       string    `json:"via"`
	GrantedBy string    `json:"granted_by,omitempty"`
	GrantedAt time.Time `json:"granted_at,omitzero"`
	Expires   time.Time `json:"expires,omitzero"`
	// Privileged is administration, the security, compliance or log
	// areas, or a permission only an administrator holds otherwise.
	Privileged bool `json:"privileged,omitempty"`
	// LastActive is the latest sign of anybody using it: a token's last
	// use, or the principal's last record in the audit log, which is the
	// only lasting record once sessions are pruned a day after they end.
	LastActive time.Time `json:"last_active,omitzero"`
	Dormant    bool      `json:"dormant,omitempty"`
	// Proposed is the verdict the review suggests: revoke for a dormant
	// item. A suggestion; the reviewer decides.
	Proposed Verdict `json:"proposed,omitempty"`
}

// Key is what the item grants, for telling whether two snapshots hold the
// same grant.
func (i Item) Key() string {
	switch i.Kind {
	case Mapping:
		return "mapping\x00" + i.Group + "\x00" + i.Role
	case Credential:
		return "credential\x00" + i.Credential
	}
	return fmt.Sprintf("binding\x00%s\x00%s\x00%s\x00%t", i.Principal, i.Role, i.Resource, i.AppRole)
}

// Describe is the item in a line.
func (i Item) Describe() string {
	switch i.Kind {
	case Mapping:
		return fmt.Sprintf("the identity provider's group %q is %s here", i.Group, i.Role)
	case Credential:
		return fmt.Sprintf("%s's token %s (%s), %s on %s", i.Principal, i.Credential, i.Name, i.Role, i.Resource)
	}
	if i.AppRole {
		return fmt.Sprintf("%s is %s, a role in an app", i.Principal, i.Role)
	}
	return fmt.Sprintf("%s is %s on %s", i.Principal, i.Role, i.Resource)
}

// Holder is whether a person holds this item: as the principal, or as a
// member of the group a mapping is about.
func (i Item) Holder(name string) bool {
	if SamePerson(name, i.Principal) {
		return true
	}
	for _, m := range i.Members {
		if SamePerson(name, m) {
			return true
		}
	}
	return false
}

// NotHeldBy refuses name deciding an item they hold (Holder), because
// nobody reviews their own access. The host asks it again of a mapping
// with the group's members as they are now, since the identity provider
// may have put the reviewer in the group after the review started.
func (i Item) NotHeldBy(name string) error {
	if i.Holder(name) {
		return fmt.Errorf("item %s is %s's own access. Nobody reviews their own: another "+
			"administrator decides it", i.ID, name)
	}
	return nil
}

// Covers reports whether a binding is one this item put in front of the
// reviewer, which is what revoking the item may take away and all it may.
//
// The same principal and the same grant, made by hand, as Snapshot took it
// in: never a deny, and never a binding provisioning made. Revoking by
// principal, role and resource alone (auth's RevokeNamed) took a deny with
// the same three as well, and provisioning suspends somebody with a deny of
// reader on "/", the same three as the reader grant most people hold by
// hand. A suspended person's items are dormant and proposed for revoke, so
// the review's own suggestion lifted the suspension and their other grants
// worked again.
func (i Item) Covers(b auth.Binding) bool {
	if i.Kind != Binding || b.Deny || b.GrantedBy == provisioned || b.Principal != i.Principal {
		return false
	}
	if i.AppRole {
		role, ok := b.AppRoleOf()
		return ok && role == i.Role
	}
	return b.Via == "" && b.What() == i.Role && b.Resource == i.Resource
}

// SamePerson reports whether two names are one person's.
//
// Policy decisions compare names exactly and people do not: "Dana" and
// "dana " are two principals to Evaluate and one person to anybody asked.
// A reviewer refused their own binding as "dana" must not approve it as
// "Dana", so the comparison here is the loose one, which can only refuse
// more.
func SamePerson(a, b string) bool {
	a = personKey(a)
	return a != "" && strings.EqualFold(a, personKey(b))
}

// personKey is a name as SamePerson compares it: without the spaces around
// it, its case or a mailto: in front.
func personKey(s string) string {
	s, _ = strings.CutPrefix(strings.ToLower(strings.TrimSpace(s)), "mailto:")
	return s
}

// Inputs is what a snapshot is taken from.
type Inputs struct {
	Policy *auth.Policy
	Tokens *auth.TokenStore
	// SCIM is provisioning's state: the groups, who is in them and what
	// each means here. Nil when provisioning is not set up.
	SCIM *scim.State
	// MappedAt is when each group was mapped, as the audit log recorded
	// it; a group missing from it has an unknown date.
	MappedAt map[string]time.Time
	// Seen is a principal's latest record in the audit log, zero for none.
	Seen func(principal string) time.Time
	Now  time.Time
}

// Privileged reports whether a grant of a role or permission on a
// resource is privileged: the admin role anywhere, anything on the
// security, compliance or log areas, or a permission whose rung is
// administrator (approving, managing agents, installing).
//
// The permissions are a step past the list the review was specified with
// (the admin role and the three areas), and the safer one: each lets its
// holder change what code or agents do, and counting it as privileged only
// asks the reviewer for a reason to keep it.
func Privileged(role, resource string) bool {
	if auth.Role(role) == auth.RoleAdmin {
		return true
	}
	if need, ok := auth.Needs(auth.Action(role)); ok && auth.IsPermission(auth.Action(role)) && need == auth.RoleAdmin {
		return true
	}
	for _, area := range []string{auth.AreaSecurity, auth.AreaCompliance, auth.AreaLog} {
		if resource == area || strings.HasPrefix(resource, area+"/") {
			return true
		}
	}
	return false
}

// mappingPrivileged is Privileged for what a group means: a role over the
// whole site, a permission, or a job's own bindings.
func mappingPrivileged(to string) bool {
	if job, ok := auth.JobNamed(to); ok {
		for _, b := range job.Bindings {
			if Privileged(b.What(), b.Resource) {
				return true
			}
		}
		return false
	}
	return Privileged(to, "/")
}

// longLived reports whether a token is a credential somebody holds, rather
// than something that ends by itself within the day: a session, an app's
// access token, a federated job's, or an agent's.
func longLived(t auth.Token, now time.Time) bool {
	if t.Revoked || t.Expired(now) || t.IsSession() || t.Grant != "" || t.Audience != "" || t.Client != "" {
		return false
	}
	if strings.HasPrefix(t.Principal, "agent:") {
		return false
	}
	return t.ExpiresAt-t.CreatedAt > int64(auth.MaxSessionTTL/time.Second)
}

// Snapshot is the population a review starts with, most urgent first:
// dormant items, then privileged ones, then the rest. Numbered in that
// order.
func Snapshot(in Inputs) []Item {
	now := in.Now
	seen := func(string) time.Time { return time.Time{} }
	if in.Seen != nil {
		seen = in.Seen
	}
	var tokens []auth.Token
	stale := map[string]bool{}
	if in.Tokens != nil {
		tokens = in.Tokens.Snapshot()
		// Dormant credentials are the ones TokenStore.Stale already finds
		// at the posture scan's threshold, not a second detector that could
		// come to a different answer.
		for _, t := range in.Tokens.Stale(now, Dormant) {
			stale[t.ID] = true
		}
	}
	var bindings []auth.Binding
	if in.Policy != nil {
		bindings = in.Policy.Snapshot()
	}

	// The latest sign of a person, under every spelling this store has of
	// them: a token's last use, and their last record in the audit log.
	spellings := map[string][]string{}
	note := func(who string) {
		k := strings.ToLower(strings.TrimSpace(who))
		for _, s := range spellings[k] {
			if s == who {
				return
			}
		}
		spellings[k] = append(spellings[k], who)
	}
	for _, b := range bindings {
		note(b.Principal)
	}
	for _, t := range tokens {
		note(t.Principal)
	}
	// Each person's latest token use, found once rather than by asking
	// every token about every holder: twenty thousand people in a group
	// and ten thousand tokens took most of a minute that way, in the
	// request that started a review and in every hourly posture scan.
	used := map[string]time.Time{}
	for _, t := range tokens {
		if k := personKey(t.Principal); k != "" && t.LastUsed > 0 {
			if at := time.Unix(t.LastUsed, 0).UTC(); at.After(used[k]) {
				used[k] = at
			}
		}
	}
	active := func(who string) time.Time {
		var last time.Time
		later := func(t time.Time) {
			if t.After(last) {
				last = t
			}
		}
		names := spellings[strings.ToLower(strings.TrimSpace(who))]
		if len(names) == 0 {
			names = []string{who}
		}
		for _, n := range names {
			later(seen(n))
		}
		if k := personKey(who); k != "" {
			later(used[k])
		}
		return last
	}
	dormant := func(last, since time.Time) bool {
		if since.After(last) {
			last = since
		}
		return last.IsZero() || now.Sub(last) > Dormant
	}

	var out []Item
	apps := map[string]int{}
	for _, b := range bindings {
		if b.Deny || !b.Live(now) || b.GrantedBy == provisioned || strings.HasPrefix(b.Principal, "agent:") {
			continue
		}
		if role, ok := b.AppRoleOf(); ok {
			key := b.Principal + "\x00" + role
			if i, found := apps[key]; found {
				out[i].Privileged = out[i].Privileged || Privileged(b.What(), b.Resource)
				continue
			}
			apps[key] = len(out)
			out = append(out, bindingItem(b, role, true))
			continue
		}
		out = append(out, bindingItem(b, b.What(), false))
	}
	for i := range out {
		out[i].LastActive = active(out[i].Principal)
		out[i].Dormant = dormant(out[i].LastActive, out[i].GrantedAt)
	}

	if in.SCIM != nil {
		users := make(map[string]*scim.User, len(in.SCIM.Users))
		for i := range in.SCIM.Users {
			users[in.SCIM.Users[i].ID] = &in.SCIM.Users[i]
		}
		groups := make([]string, 0, len(in.SCIM.Mapping))
		for g, to := range in.SCIM.Mapping {
			if to != "" {
				groups = append(groups, g)
			}
		}
		sort.Strings(groups)
		for _, g := range groups {
			it := Item{Kind: Mapping, Group: g, Role: in.SCIM.Mapping[g], Via: "through an identity provider group",
				Privileged: mappingPrivileged(in.SCIM.Mapping[g]), GrantedAt: in.MappedAt[g]}
			for _, grp := range in.SCIM.Groups {
				if grp.DisplayName != g {
					continue
				}
				for _, id := range grp.Members {
					if u, ok := users[id]; ok && u.Active {
						it.Members = append(it.Members, u.UserName)
					}
				}
			}
			sort.Strings(it.Members)
			for _, m := range it.Members {
				if t := active(m); t.After(it.LastActive) {
					it.LastActive = t
				}
			}
			it.Dormant = dormant(it.LastActive, it.GrantedAt)
			out = append(out, it)
		}
	}

	for _, t := range tokens {
		if !longLived(t, now) {
			continue
		}
		it := Item{Kind: Credential, Principal: t.Principal, Credential: t.ID, Name: t.Name,
			Role: string(t.Role), Resource: t.Resource, Via: "as a token",
			GrantedAt: time.Unix(t.CreatedAt, 0).UTC(), Expires: time.Unix(t.ExpiresAt, 0).UTC(),
			Privileged: Privileged(string(t.Role), t.Resource), Dormant: stale[t.ID]}
		if t.LastUsed > 0 {
			it.LastActive = time.Unix(t.LastUsed, 0).UTC()
		}
		out = append(out, it)
	}

	order := map[Kind]int{Binding: 0, Mapping: 1, Credential: 2}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Dormant != b.Dormant {
			return a.Dormant
		}
		if a.Privileged != b.Privileged {
			return a.Privileged
		}
		if order[a.Kind] != order[b.Kind] {
			return order[a.Kind] < order[b.Kind]
		}
		return a.Key() < b.Key()
	})
	for i := range out {
		out[i].ID = fmt.Sprint(i + 1)
		if out[i].Dormant {
			out[i].Proposed = Revoke
		}
	}
	return out
}

func bindingItem(b auth.Binding, role string, app bool) Item {
	it := Item{Kind: Binding, Principal: b.Principal, Role: role, Resource: b.Resource, AppRole: app,
		Via: "by hand", GrantedBy: b.GrantedBy, Privileged: Privileged(b.What(), b.Resource)}
	if app {
		it.Via, it.Resource = "as a role in an app", ""
	}
	if b.GrantedAt > 0 {
		it.GrantedAt = time.Unix(b.GrantedAt, 0).UTC()
	}
	if b.Expires > 0 {
		it.Expires = time.Unix(b.Expires, 0).UTC()
	}
	return it
}

// Decider is who is deciding: a person, proved.
type Decider struct {
	Name     string
	Kind     audit.Kind
	Verified bool
	// Model is what an AI decider runs, for the record that refuses it.
	Model string
}

// check refuses a decider who cannot review: nobody named, or not a
// person.
func (d Decider) check() error {
	if strings.TrimSpace(d.Name) == "" || !d.Verified {
		return fmt.Errorf("a review needs a named reviewer, proved by their own credential: " +
			"a decision nobody signed is a list somebody exported")
	}
	switch d.Kind {
	case audit.KindAI:
		return fmt.Errorf("%s is a model. Whether somebody still needs access is a question about what "+
			"they do all day, which a model cannot see; it may read the list, and a person decides", d.Name)
	case audit.KindService, audit.KindUnknown:
		return fmt.Errorf("%s is a program's credential, not a person: a service token reviews nothing. "+
			"Decide with your own sign-in", d.Name)
	}
	return nil
}

// Decision is a reviewer's answer about one item.
type Decision struct {
	Item    string     `json:"item"`
	Verdict Verdict    `json:"verdict"`
	By      string     `json:"by"`
	Kind    audit.Kind `json:"kind"`
	At      time.Time  `json:"at"`
	// Why is the reviewer's reason, kept here and nowhere else: the audit
	// record says only whether one was given, so nobody's name typed into
	// a reason is copied into a log streamed elsewhere.
	Why string `json:"why,omitempty"`
}

// Review is one review, from its snapshot to its close. Kept as
// access/reviews/ID.json.
type Review struct {
	ID        string     `json:"id"`
	Started   time.Time  `json:"started"`
	StartedBy string     `json:"started_by"`
	Kind      audit.Kind `json:"kind"`
	Items     []Item     `json:"items"`
	Decisions []Decision `json:"decisions,omitempty"`

	Closed   time.Time  `json:"closed,omitzero"`
	ClosedBy string     `json:"closed_by,omitempty"`
	Summary  *Summary   `json:"summary,omitempty"`
	Closer   audit.Kind `json:"closer_kind,omitempty"`
}

// Open reports whether the review is still being decided.
func (r *Review) Open() bool { return r.Closed.IsZero() }

// Item finds an item by its number.
func (r *Review) Item(id string) (Item, bool) {
	id = strings.TrimSpace(id)
	for _, it := range r.Items {
		if it.ID == id {
			return it, true
		}
	}
	return Item{}, false
}

// Decided is the decision about an item, if there is one.
func (r *Review) Decided(id string) (Decision, bool) {
	for i := len(r.Decisions) - 1; i >= 0; i-- {
		if r.Decisions[i].Item == id {
			return r.Decisions[i], true
		}
	}
	return Decision{}, false
}

// Undecided counts the items nobody has decided yet.
func (r *Review) Undecided() int {
	n := 0
	for _, it := range r.Items {
		if _, ok := r.Decided(it.ID); !ok {
			n++
		}
	}
	return n
}

// New starts a review over a snapshot.
func New(id string, items []Item, by Decider, now time.Time) (*Review, error) {
	if err := by.check(); err != nil {
		return nil, err
	}
	return &Review{ID: id, Started: now.UTC(), StartedBy: by.Name, Kind: by.Kind, Items: items}, nil
}

// Check is whether a decider may give a verdict about an item, and the
// item, refused with the reason when they may not. Nothing is recorded:
// a revoke is applied by the host between Check and Record, and a revoke
// that could not be applied is not a decision.
func (r *Review) Check(id string, v Verdict, d Decider, why string) (Item, error) {
	if !r.Open() {
		return Item{}, fmt.Errorf("review %s closed on %s", r.ID, r.Closed.Format("2 January 2006"))
	}
	switch v {
	case Keep, Revoke:
	case "reduce":
		return Item{}, fmt.Errorf("there is no reduce: revoke it, then grant the lower role, so the " +
			"record shows both what was taken and what was given")
	default:
		return Item{}, fmt.Errorf("%q is not a verdict; keep or revoke", v)
	}
	it, ok := r.Item(id)
	if !ok {
		return Item{}, fmt.Errorf("review %s has no item %q; quilzo access review items lists them", r.ID, id)
	}
	if prev, done := r.Decided(it.ID); done && prev.Verdict == Revoke {
		return Item{}, fmt.Errorf("item %s was revoked by %s; if that was wrong, grant it again", it.ID, prev.By)
	}
	if err := d.check(); err != nil {
		return Item{}, err
	}
	if err := it.NotHeldBy(d.Name); err != nil {
		return Item{}, err
	}
	if v == Keep && it.Privileged && strings.TrimSpace(why) == "" {
		return Item{}, fmt.Errorf("item %s is privileged, and keeping it needs a reason (--why). It is the "+
			"decision nobody writes down and the one an auditor asks about", it.ID)
	}
	return it, nil
}

// Record keeps a decision Check allowed, replacing an earlier keep.
func (r *Review) Record(id string, v Verdict, d Decider, why string, now time.Time) Decision {
	dec := Decision{Item: id, Verdict: v, By: d.Name, Kind: d.Kind, At: now.UTC(), Why: strings.TrimSpace(why)}
	kept := r.Decisions[:0]
	for _, x := range r.Decisions {
		if x.Item != id {
			kept = append(kept, x)
		}
	}
	r.Decisions = append(kept, dec)
	return dec
}

// Summary is what a closed review comes to.
type Summary struct {
	Items      int `json:"items"`
	Kept       int `json:"kept"`
	Revoked    int `json:"revoked"`
	Dormant    int `json:"dormant"`
	Privileged int `json:"privileged"`
	// Gone are items whose grant was taken away some other way before
	// anybody decided them.
	Gone int `json:"gone,omitempty"`
	// Own are the only administrator's own items, which nobody else could
	// decide and which a review done alone closes undecided, saying so.
	Own int `json:"own,omitempty"`
	// NotReviewed are grants made since the review started: outside its
	// snapshot, and so not reviewed by it.
	NotReviewed []Item `json:"not_reviewed,omitempty"`
	// Alone says the store had one administrator, who did the review.
	Alone bool `json:"alone,omitempty"`
}

// Close ends a review. Refused while any item is undecided, except an item
// whose grant has already gone and, when the closer is the only
// administrator, their own: nobody else exists to decide it, so the review
// is closed as done alone and says how many of theirs went unreviewed.
// current is a snapshot taken now, against which both are judged and from
// which grants made since the start are reported as not reviewed.
func (r *Review) Close(d Decider, current []Item, alone bool, now time.Time) (Summary, error) {
	if !r.Open() {
		return Summary{}, fmt.Errorf("review %s closed on %s", r.ID, r.Closed.Format("2 January 2006"))
	}
	if err := d.check(); err != nil {
		return Summary{}, err
	}
	still := map[string]bool{}
	for _, it := range current {
		still[it.Key()] = true
	}
	sum := Summary{Items: len(r.Items), Alone: alone}
	var waiting []string
	for _, it := range r.Items {
		if it.Dormant {
			sum.Dormant++
		}
		if it.Privileged {
			sum.Privileged++
		}
		dec, ok := r.Decided(it.ID)
		switch {
		case ok && dec.Verdict == Revoke:
			sum.Revoked++
		case ok:
			sum.Kept++
		case !still[it.Key()]:
			sum.Gone++
		case alone && it.Holder(d.Name):
			sum.Own++
		default:
			waiting = append(waiting, it.ID)
		}
	}
	if len(waiting) > 0 {
		return Summary{}, fmt.Errorf("%d item(s) are undecided (%s). A review closed with items nobody "+
			"looked at evidences a list, not a review", len(waiting), strings.Join(waiting, ", "))
	}
	before := map[string]bool{}
	for _, it := range r.Items {
		before[it.Key()] = true
	}
	for _, it := range current {
		if !before[it.Key()] {
			it.ID = ""
			sum.NotReviewed = append(sum.NotReviewed, it)
		}
	}
	r.Closed, r.ClosedBy, r.Closer, r.Summary = now.UTC(), d.Name, d.Kind, &sum
	return sum, nil
}

// Resource is where a review's records are filed in the audit log.
func (r *Review) Resource() string { return "/access/review/" + r.ID }

// StartedDetail is the review.started record's detail: how much there is
// to decide.
func (r *Review) StartedDetail() map[string]string {
	dormant, privileged := 0, 0
	for _, it := range r.Items {
		if it.Dormant {
			dormant++
		}
		if it.Privileged {
			privileged++
		}
	}
	return map[string]string{"review": r.ID, "items": fmt.Sprint(len(r.Items)),
		"dormant": fmt.Sprint(dormant), "privileged": fmt.Sprint(privileged)}
}

// DecisionDetail is a review.keep or review.revoke record's detail.
//
// The principal goes under "principal", which the log pseudonymises, and a
// token's id under "credential": a key containing "token" makes the log
// refuse the whole record, and the revocation of a credential would go
// unrecorded. The reason is "given" or "none", never its text.
func (r *Review) DecisionDetail(it Item, dec Decision) map[string]string {
	d := map[string]string{"review": r.ID, "item": it.ID, "kind": string(it.Kind), "role": it.Role,
		"resource": it.Resource, "dormant": fmt.Sprint(it.Dormant), "privileged": fmt.Sprint(it.Privileged),
		"reason": "none"}
	if dec.Why != "" {
		d["reason"] = "given"
	}
	switch it.Kind {
	case Mapping:
		d["group"] = it.Group
	case Credential:
		d["principal"], d["credential"] = it.Principal, it.Credential
	default:
		d["principal"] = it.Principal
	}
	if it.AppRole {
		d["resource"] = "its app"
	}
	return d
}

// ClosedDetail is the review.closed record's detail: the counts, and
// "alone" when one administrator did it all, which approval.alone counts.
func (r *Review) ClosedDetail(s Summary) map[string]string {
	d := map[string]string{"review": r.ID, "items": fmt.Sprint(s.Items), "kept": fmt.Sprint(s.Kept),
		"revoked": fmt.Sprint(s.Revoked), "dormant": fmt.Sprint(s.Dormant),
		"privileged": fmt.Sprint(s.Privileged), "not_reviewed": fmt.Sprint(len(s.NotReviewed))}
	if s.Gone > 0 {
		d["gone"] = fmt.Sprint(s.Gone)
	}
	if s.Alone {
		d["alone"] = "true"
		d["own_unreviewed"] = fmt.Sprint(s.Own)
	}
	return d
}

// Control is the built-in periodic control a closed review evidences:
// quarterly, as auditors read AC-2's review of accounts, so the usual
// two-occurrence rule (internal/assurance) applies to it like any other.
func Control() assurance.Control {
	return assurance.Control{ID: ControlID, Name: "Review of the access Quilzo grants (Quilzo)",
		Cadence: assurance.Quarterly, Owner: "the administrators",
		Maps: []string{"NIST SP 800-53 AC-2", "NIST SP 800-53 AC-2(3)"}}
}

// Evidence is what a closed review shows: that the control operated for
// the quarter up to its close.
func (r *Review) Evidence() assurance.Evidence {
	s := Summary{}
	if r.Summary != nil {
		s = *r.Summary
	}
	what := fmt.Sprintf("access review %s closed: %d item(s), %d kept, %d revoked, %d granted since and not reviewed",
		r.ID, s.Items, s.Kept, s.Revoked, len(s.NotReviewed))
	if s.Alone {
		what += fmt.Sprintf("; done by the only administrator, %d of their own left unreviewed", s.Own)
	}
	return assurance.Evidence{Control: ControlID, From: r.Closed.Add(-assurance.Quarterly.Every()), To: r.Closed,
		Outcome: assurance.Operated, What: what, Source: "quilzo access review",
		Ref: "access/reviews/" + r.ID + ".json, and its review.closed record", At: r.Closed,
		By: r.ClosedBy, Kind: r.Closer}
}
