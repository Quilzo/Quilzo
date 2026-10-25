// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"time"
)

// plainAge says how long, the way a person would.
func plainAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// agoText says how long ago, without "just now ago".
func agoText(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	return plainAge(d) + " ago"
}
