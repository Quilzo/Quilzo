package admin

// The manual, assembled.
//
// The order here is the order somebody reads it in: what this is and how to
// stand it up, then how to make things, then how to ship them, then the three
// surfaces, then access and administration, then security and privacy, then
// this interface itself.
//
// One list rather than a registry each chapter appends to, so the whole
// structure is visible in one screen and adding a chapter is a line rather
// than a side effect.
var manual = []chapter{
	chapterStart,
	chapterContent,
	chapterRelease,
	chapterInterfaces,
	chapterAdmin,
	chapterTrust,
	chapterYou,
}
