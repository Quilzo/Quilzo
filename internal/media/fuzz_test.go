package media

import (
	"testing"
	"time"
)

// Every accepted format is decoded rather than sniffed, which means image
// decoders, container parsers and a PDF scanner all see attacker bytes.
func FuzzAccept(f *testing.F) {
	f.Add("photo.png", png(4, 4, true))
	f.Add("doc.pdf", pdf(""))
	f.Add("a.mp4", append([]byte{0, 0, 0, 0x18}, []byte("ftypisom")...))
	f.Add("x.wav", []byte("RIFF\x00\x00\x00\x00WAVE"))
	f.Add("x.txt", []byte("hello"))
	f.Add("x.csv", []byte("a,b\n1,2\n"))
	f.Add("", []byte{})

	now := time.Unix(1786000000, 0)
	f.Fuzz(func(t *testing.T, name string, body []byte) {
		fl, err := Accept(name, body, now)
		if err != nil {
			return
		}
		// Anything accepted must have a usable identity and a bounded name.
		if len(fl.ID) != 64 {
			t.Errorf("accepted %q with id %q", name, fl.ID)
		}
		if fl.Name == "" {
			t.Errorf("accepted %q with an empty display name", name)
		}
		d := fl.DownloadName()
		for _, bad := range []string{"/", "\\", "..", "\x00", "\n", "\r", `"`} {
			if contains(d, bad) {
				t.Errorf("download name %q contains %q", d, bad)
			}
		}
	})
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
