// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/media"
)

// The optimiser's settings, read in one place.
//
// They were read in four: the browser's upload, `media add`, the Telegram
// bot, and nowhere at all in `media get`. Four copies of the same five lines
// is how the fifth caller comes to be written without them, and that is
// exactly what happened — a fetched image was stored unresized with its EXIF
// intact, on the one path that ingests a file from somebody else's server.
//
// internal/media puts it plainly: stripping metadata is "a property of the
// pipeline rather than a filter somebody has to remember". A property of the
// pipeline has to be in the pipeline, and a list of keys repeated at every
// entrance is not.
func mediaOptions(c *config.Config) media.Options {
	if c == nil {
		return media.Options{}
	}
	return media.Options{
		MaxWidth:    c.Int("media.max_width"),
		MaxHeight:   c.Int("media.max_height"),
		JPEGQuality: c.Int("media.jpeg_quality"),
		WebP:        c.Bool("media.webp"),
		// Declared with a Weaker clause and two NIST controls, and read by
		// nothing until now. A setting that appears in the posture report and
		// changes no behaviour is a claim the product does not keep.
		KeepMetadata: !c.Bool("media.strip_metadata"),
	}
}

// mediaOptionsAt reads them for a site root.
func mediaOptionsAt(root string) media.Options {
	c, err := loadConfig(root)
	if err != nil {
		// The defaults, not nothing. An unreadable config must not silently
		// turn the pipeline off — that would store a six-thousand-pixel
		// photograph with its GPS tag because a file had a syntax error.
		return mediaOptions(config.New())
	}
	return mediaOptions(c)
}
