package public

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Where somebody sends a vulnerability, published where they will look.
//
// # Why a file
//
// A finder with a working exploit and no way to report it does one of three
// things: gives up, posts it, or sells it. Two of those are worse for the site
// than being told. RFC 9116 fixes the address so nobody has to guess, and
// /.well-known/security.txt is the first thing a researcher checks and the
// first thing an automated scanner checks.
//
// # Why now
//
// The Cyber Resilience Act's reporting duty starts on 11 September 2026: a
// manufacturer of a product with digital elements has 24 hours to report an
// actively exploited vulnerability to ENISA. Twenty-four hours is not a long
// time to discover that somebody has been trying to reach you through a
// contact form since Friday. The duty is on the manufacturer rather than on a
// site published with this program -- but a site is where a finder looks, and
// a CMS that cannot publish a contact for its operator has made its operator's
// problem harder for no reason.
//
// # What it does not do
//
// It does not promise a bounty, a response time, or immunity. Those are
// commitments an operator makes, and inventing them on their behalf would be
// this program speaking for somebody about their legal exposure.

// SecurityTxtPath is where RFC 9116 says this lives.
const SecurityTxtPath = "/.well-known/security.txt"

// SecurityContact is what an operator publishes for people reporting problems.
type SecurityContact struct {
	// Contact is a mailto:, https: or tel: URI. At least one is required by
	// the RFC, and a file without one is the thing it exists to prevent.
	Contact []string
	// Expires is when this stops being trustworthy. Required, because a
	// security contact nobody has confirmed in three years is an address that
	// may reach nobody, and a finder deserves to know which they are looking
	// at.
	Expires time.Time
	// Policy, Acknowledgments and Encryption are optional and are the
	// operator's own URLs.
	Policy          string
	Acknowledgments string
	Encryption      string
	// PreferredLanguages, as RFC 5646 tags.
	PreferredLanguages []string
}

// Valid reports whether there is enough here to publish.
func (c *SecurityContact) Valid() bool {
	return c != nil && len(c.Contact) > 0 && !c.Expires.IsZero()
}

// defaultExpiry is how long a contact is good for when nobody said.
//
// A year. The RFC asks for less than a year and gives no default; the point of
// the field is that somebody looks at it again, and a date far enough away to
// be forgotten defeats it.
const defaultExpiry = 365 * 24 * time.Hour

// securityTxt serves the file.
func (st *Site) securityTxt(w http.ResponseWriter, r *http.Request) {
	c := st.Security
	if !c.Valid() {
		// Not found rather than an empty file. A security.txt with no contact
		// in it is worse than none: it answers 200 to the scanner that went
		// looking and tells the person nothing.
		http.NotFound(w, r)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	// Short, because the interesting change to this file is somebody's contact
	// address changing and a day-old copy is a day of reports going nowhere.
	h.Set("Cache-Control", "public, max-age=3600")

	var b strings.Builder
	b.WriteString("# Reporting a security problem with this site.\n" +
		"# https://www.rfc-editor.org/rfc/rfc9116\n\n")
	for _, contact := range c.Contact {
		fmt.Fprintf(&b, "Contact: %s\n", contact)
	}
	fmt.Fprintf(&b, "Expires: %s\n", c.Expires.UTC().Format(time.RFC3339))
	if c.Policy != "" {
		fmt.Fprintf(&b, "Policy: %s\n", c.Policy)
	}
	if c.Acknowledgments != "" {
		fmt.Fprintf(&b, "Acknowledgments: %s\n", c.Acknowledgments)
	}
	if c.Encryption != "" {
		fmt.Fprintf(&b, "Encryption: %s\n", c.Encryption)
	}
	if len(c.PreferredLanguages) > 0 {
		fmt.Fprintf(&b, "Preferred-Languages: %s\n",
			strings.Join(c.PreferredLanguages, ", "))
	}
	if st.BaseURL != "" {
		// The canonical location, so a copy found somewhere else can be
		// checked against where it is supposed to live.
		fmt.Fprintf(&b, "Canonical: %s%s\n",
			strings.TrimRight(st.BaseURL, "/"), SecurityTxtPath)
	}
	_, _ = w.Write([]byte(b.String()))
}
