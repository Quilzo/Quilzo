// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"time"
)

// The admin's words for time, in one place.
//
// There were five helpers, and they had drifted apart. The Today screen
// said "Last published 3 hours ago" above a waiting item "3 h ago", and for
// the second day one said "47 h" where the other said "1 day". A playbook's
// one-minute step was "for 1 minutes". Now an age is agoText and a span is
// plainDuration, in full words with one threshold for each unit; agoAt,
// plainAge and roughDuration are the same words for their callers.
//
// travel's "since" and the settings' shortDuration are not these: one is a
// sentence about a journey, the other Go's notation for a value to type.

// plainAge says how long, roughly, the way a person would: "just now",
// "1 minute", "3 hours", "2 days". Each unit is whole and counted down, so
// 47 hours is "1 day" and not "47 hours".
func plainAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return counted(int(d/time.Minute), "minute", "minutes")
	case d < 24*time.Hour:
		return counted(int(d/time.Hour), "hour", "hours")
	}
	return counted(int(d/(24*time.Hour)), "day", "days")
}

// agoText says how long ago, without "just now ago": "5 minutes ago",
// "3 hours ago". Every age on a screen is this.
func agoText(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	return plainAge(d) + " ago"
}

// plainDuration writes a span of time the way somebody would say it: "1
// minute", "90 minutes", "an hour", "24 hours".
//
// Go prints 24h0m0s, which is exact and is not English. The screens put a
// span in a sentence — "what agents have done in the last ...", "slow the
// source for ..." — and a sentence with a duration literal in it reads as a
// value that leaked out of the program rather than as something written for
// a reader.
//
// Only whole hours and whole minutes are said in words. Anything else keeps
// Go's rendering, because a wrong-but-tidy number is worse than an ugly
// exact one: the Shield screen's copy cut 90 seconds to "1 minutes".
func plainDuration(d time.Duration) string {
	switch {
	case d == time.Hour:
		return "an hour"
	case d >= time.Hour && d%time.Hour == 0:
		return counted(int(d/time.Hour), "hour", "hours")
	case d >= time.Minute && d%time.Minute == 0:
		return counted(int(d/time.Minute), "minute", "minutes")
	}
	return d.String()
}
