// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/marking"
)

// Switching marking on must not take the connection away from the handlers.
//
// The banner wrapper buffers every response so the banner can be inserted,
// and a wrapper with no Unwrap hides the connection from
// http.ResponseController. The media route sets a write deadline sized to the
// file it is sending; without this, a deployment with a classification banner
// would have had that quietly do nothing, and the only way to find out would
// be a stalled reader holding a connection nobody could account for.
func TestTheBannerDoesNotHideTheConnection(t *testing.T) {
	st, _ := setup(t)
	st.Marking = &marking.Policy{
		Levels: []string{"UNCLASSIFIED", "SECRET"},
		Banner: "SECRET//NOFORN",
	}

	var asked bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := http.NewResponseController(w).SetWriteDeadline(
			time.Now().Add(time.Minute))
		if err != nil {
			t.Errorf("a handler behind the banner cannot set a deadline: %v", err)
			return
		}
		asked = true
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	})

	dw := &deadlineWriter{ResponseWriter: httptest.NewRecorder()}
	st.marked(inner).ServeHTTP(dw, httptest.NewRequest("GET", "/", nil))

	if !asked {
		t.Fatal("the deadline was never set")
	}
	if len(dw.asked) == 0 {
		t.Error("the deadline did not reach the writer underneath")
	}
}
