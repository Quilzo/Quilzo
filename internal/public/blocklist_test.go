// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"testing"
	"time"
)

// One instance cannot take the whole inbox's allowance.
//
// The limit was keyed on the connecting address alone, and this file assumes
// elsewhere that a TLS-terminating proxy sits in front — where the address is
// the proxy's for every remote server on the fediverse. So one chatty instance
// filled the single bucket and the rest were refused. A shared limit is not a
// limit on anybody in particular.
//
// The sending host is unproved at this point and cannot be proved — proving it
// is the outbound fetch the address bucket exists to bound — so it only ever
// makes the answer stricter. Varying it buys a fresh host bucket and nothing
// else, because the address bucket is still counting.
func TestOneInstanceCannotFillEverybodysBucket(t *testing.T) {
	var g inboxGuard
	now := time.Now()

	// One instance, arriving through a proxy, spends its share.
	spent := 0
	for i := 0; i < InboxRate*2; i++ {
		if g.allow("10.0.0.1", "chatty.example", now) {
			spent++
		}
	}
	if spent != InboxRate {
		t.Fatalf("one host sent %d before being refused, and the limit is %d",
			spent, InboxRate)
	}

	// Somebody else, whose address the deployment can actually tell apart, is
	// not refused because of them. That is what site.trusted_proxy is for:
	// behind a proxy with it off, the address is the proxy's for everybody
	// and the bucket above is the whole fediverse's.
	if !g.allow("10.0.0.2", "quiet.example", now) {
		t.Error("a second instance was refused because a first one was busy")
	}
}

// And the host bucket refuses one instance that arrives from many addresses.
//
// Which is the half the address bucket cannot do: a sender with a routed /64
// has a fresh address bucket per request, and the name it signs with is the
// only thing that stays the same.
func TestOneInstanceFromManyAddressesIsStillBounded(t *testing.T) {
	var g inboxGuard
	now := time.Now()

	allowed := 0
	for i := 0; i < InboxRate*3; i++ {
		if g.allow("2001:db8::"+string(rune('a'+i%26)), "chatty.example", now) {
			allowed++
		}
	}
	if allowed > InboxRate {
		t.Errorf("%d requests got through from one instance by changing "+
			"address, and the limit is %d", allowed, InboxRate)
	}
}

// And the address still bounds what an unverified caller can make this server
// do, which is why that bucket exists: verifying costs an outbound fetch to a
// host the caller names.
func TestVaryingTheClaimedHostDoesNotBuyMoreRequests(t *testing.T) {
	var g inboxGuard
	now := time.Now()

	allowed := 0
	for i := 0; i < InboxRate*3; i++ {
		// A different claimed host every time, which is free to do: the name
		// is not proved at this point.
		if g.allow("203.0.113.9", string(rune('a'+i%26))+".example", now) {
			allowed++
		}
	}
	if allowed > InboxRate {
		t.Errorf("%d requests got through from one address by varying the "+
			"host they claimed, and the limit is %d. That is the reflection "+
			"this bucket exists to bound", allowed, InboxRate)
	}
}

// A blocked instance is turned away, silently, after its signature is checked.
//
// There was no blocklist at all: handleFollow accepted any actor whose
// signature checked out, up to a hundred thousand followers, and the only
// remedy was stopping the server and editing followers.json by hand — after
// which the same instance could follow again immediately. An operator being
// harassed from one place had no answer.
func TestABlockedActorIsTurnedAwaySilently(t *testing.T) {
	var blocked []string
	f := &Federation{
		Blocked:   func(actor string) bool { return actor == "https://spam.example/@a" },
		OnBlocked: func(actor, kind string) { blocked = append(blocked, actor+" "+kind) },
	}

	if !f.Blocked("https://spam.example/@a") {
		t.Fatal("the premise is wrong")
	}
	if f.Blocked("https://friendly.example/@b") {
		t.Error("a block on one instance refused another")
	}
	// The hook exists so an operator can see whether a block is still earning
	// its place. Silence towards the sender is the point; silence towards the
	// operator is not.
	f.OnBlocked("https://spam.example/@a", "Follow")
	if len(blocked) != 1 {
		t.Error("turning somebody away is not reported anywhere")
	}
}
