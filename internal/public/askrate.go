// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
)

// Whether an answer helped: two buttons under it, posted to
// /ask/NAME/rate.
//
// Counted with nothing about the visitor (gaps.Ledger.Rate). A "no" also
// keeps the question, masked, where the owner keeps what a chatbot could
// not answer, when they keep that: an answer that did not help is a page
// that says something badly. The form carries a token this server signed
// for that question and chatbot, good for an hour and once, so the route
// is not a way to put words of anybody's choosing in front of the owner,
// or to count the same answer a thousand times.

// RateFor is how long an answer can be rated.
const RateFor = time.Hour

// maxRated bounds the tokens remembered as used.
const maxRated = 20_000

// rateMAC is the signature on a rating token: this process's key, over
// the chatbot, the question and when it was answered.
func (as *Assistants) rateMAC(name, question string, issued int64) []byte {
	o := as.own()
	o.mu.Lock()
	if o.rateKey == nil {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			o.mu.Unlock()
			return nil
		}
		o.rateKey = k
	}
	key := o.rateKey
	o.mu.Unlock()
	m := hmac.New(sha256.New, key)
	m.Write([]byte(name + "\x00" + question + "\x00" + strconv.FormatInt(issued, 10)))
	return m.Sum(nil)
}

// rateToken is the token an answer's rating form carries.
func (as *Assistants) rateToken(name, question string, now time.Time) string {
	issued := now.Unix()
	mac := as.rateMAC(name, question, issued)
	if mac == nil {
		return ""
	}
	return strconv.FormatInt(issued, 10) + "." + base64.RawURLEncoding.EncodeToString(mac)
}

// spendRateToken reports whether a token is this server's, for this
// question, recent and not used before; and uses it.
func (as *Assistants) spendRateToken(name, question, token string, now time.Time) bool {
	ts, sig, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	issued, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	at := time.Unix(issued, 0)
	if now.Before(at.Add(-time.Minute)) || now.After(at.Add(RateFor)) {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, as.rateMAC(name, question, issued)) {
		return false
	}
	o := as.own()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.rated == nil {
		o.rated = map[string]time.Time{}
	}
	if _, used := o.rated[sig]; used {
		return false
	}
	if len(o.rated) >= maxRated {
		for k, t := range o.rated {
			if now.After(t.Add(RateFor)) {
				delete(o.rated, k)
			}
		}
		if len(o.rated) >= maxRated {
			return false
		}
	}
	o.rated[sig] = at
	return true
}

// rate takes a visitor's rating of an answer.
func (st *Site) rate(w http.ResponseWriter, r *http.Request, a assistant.Assistant) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	if st.Assistants.Rated == nil {
		st.notFound(w, r)
		return
	}
	if ok, wait := st.questionAllowed(r); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		http.Error(w, "You have asked a lot in a short time. You can try again "+inAbout(wait)+".", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, questionForm)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "that could not be read", http.StatusBadRequest)
		return
	}
	q := r.PostFormValue("q")
	helpful := r.PostFormValue("helpful")
	if helpful != "yes" && helpful != "no" {
		http.Error(w, "say yes or no", http.StatusBadRequest)
		return
	}
	back := url.Values{}
	if !st.Assistants.spendRateToken(a.Name, q, r.PostFormValue("t"), time.Now()) {
		back.Set("rated", "late")
	} else {
		st.Assistants.Rated(a.Name, q, helpful == "yes")
		back.Set("rated", helpful)
	}
	if e := r.PostFormValue("embed"); e == "1" || e == "panel" {
		back.Set("embed", e)
	}
	if v := visitorToken(r.PostFormValue("v")); v != "" {
		back.Set("v", v)
	}
	http.Redirect(w, r, "/ask/"+a.Name+"?"+back.Encode(), http.StatusSeeOther)
}

// ratedNote is what the page says after a rating.
func ratedNote(v string) string {
	switch v {
	case "yes":
		return "Thank you: that is noted."
	case "no":
		return "Thank you: that is noted, so the site can say it better."
	case "late":
		return "That answer can no longer be rated: ask again to rate the new one."
	}
	return ""
}
