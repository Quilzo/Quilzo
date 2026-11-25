// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/dpop"
	"github.com/quilzo/quilzo/internal/egress"
	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/plaintext"
)

// `quilzo evidence push`: a pipeline's job sends a file of evidence to a
// Quilzo server, holding no secret.
//
// It runs in the job, where no store is (storeless). It asks the job's
// platform for the identity token it signs for this run (GitHub Actions
// hands it out at ACTIONS_ID_TOKEN_REQUEST_URL to a job given id-token:
// write; GitLab CI puts it in a variable the job's id_tokens names), makes
// a key that lives only in this process, exchanges the identity token at
// the server's /token/exchange with a proof made by that key, and posts the
// file to /api/v1/evidence/import with a fresh proof. The token it is given
// lasts minutes, works only with that key, and is gone with the process;
// nothing is written to the job's disk. What the platform signed about the
// job (its repository, its workflow) is held to the pipeline's source on
// the server, and the file is graded "ci".

func init() {
	storeless["evidence push"] = true
}

// pushOptions is what a push is told.
type pushOptions struct {
	file, format, to, source, audience string
	// tokenEnv is the variable GitLab's id_tokens puts the job's identity
	// token in; idToken, when set, is the token itself (for a test).
	tokenEnv string
	idToken  string
	json     bool
}

// pushClient is how a push reaches the platform and the server: through
// egress, so it obeys offline mode and is in the report of what this
// program talks to.
var pushClient = func() *http.Client { return egress.Client("push", 2*time.Minute) }

func evidencePushCmd(args []string) error {
	fs := flag.NewFlagSet("evidence push", flag.ContinueOnError)
	var o pushOptions
	fs.StringVar(&o.format, "format", "", "how the file is read: sarif, cyclonedx, spdx, ocsf, csaf, openvex, dsse or osquery")
	fs.StringVar(&o.to, "to", "", "the Quilzo server's address, https://admin.example")
	fs.StringVar(&o.source, "source", "", "the pipeline's source on the server, when its repository and workflow do not find it")
	fs.StringVar(&o.audience, "audience", "", "the audience the server's trust expects in the identity token (its address by default)")
	fs.StringVar(&o.tokenEnv, "token-env", "QUILZO_ID_TOKEN", "on GitLab CI, the variable id_tokens puts the job's identity token in")
	fs.BoolVar(&o.json, "json", false, "print what the server answered as JSON")
	var pos []string
	if err := parseFlags(fs, args, &pos, 1); err != nil {
		return err
	}
	if len(pos) != 1 || o.format == "" || o.to == "" {
		return errMisused{errors.New("usage: quilzo evidence push FILE --format FORMAT --to https://SERVER [--source NAME] " +
			"[--audience AUD], run in a GitHub Actions job with id-token: write, or a GitLab CI job whose id_tokens " +
			"sets QUILZO_ID_TOKEN")}
	}
	o.file = pos[0]
	res, err := pushEvidence(context.Background(), pushClient(), o, time.Now)
	if err != nil {
		return err
	}
	if o.json {
		return json.NewEncoder(os.Stdout).Encode(res)
	}
	fmt.Printf("Pushed %s to %s: %v fact(s) read, %v written, graded %v, under the source %v.\n", o.file,
		o.to, res["facts"], res["written"], res["grade"], res["source"])
	return nil
}

// pushEvidence does the push and says what the server answered.
func pushEvidence(ctx context.Context, c *http.Client, o pushOptions, now func() time.Time) (map[string]any, error) {
	if _, ok := evidence.FormatNamed(o.format); !ok {
		return nil, errMisused{fmt.Errorf("%q is not a format the server reads", plaintext.Clip(o.format, 40, "…"))}
	}
	server, err := pushServer(o.to)
	if err != nil {
		return nil, errMisused{err}
	}
	body, err := os.ReadFile(o.file)
	if err != nil {
		return nil, err
	}
	if len(body) > evidence.MaxFile {
		return nil, fmt.Errorf("%s is larger than the %d bytes a server reads", o.file, evidence.MaxFile)
	}
	audience := o.audience
	if audience == "" {
		audience = server.String()
	}
	idToken := o.idToken
	if idToken == "" {
		if idToken, err = jobIdentity(ctx, c, audience, o.tokenEnv); err != nil {
			return nil, err
		}
	}
	// The key lives in this process and nowhere else.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	exchangeAt := server.JoinPath("token", "exchange").String()
	proof, err := dpop.Prove(key, http.MethodPost, exchangeAt, "", now())
	if err != nil {
		return nil, err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {idToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, exchangeAt, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	var exchanged struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	status, err := pushDo(c, req, &exchanged)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || exchanged.AccessToken == "" {
		return nil, fmt.Errorf("the server did not exchange the job's identity token (%d %s): %s", status,
			oauthWord(exchanged.Error), plaintext.Clip(exchanged.Description, 400, "…"))
	}
	if !strings.EqualFold(exchanged.TokenType, "DPoP") {
		return nil, errors.New("the server gave a token not bound to this job's key, and a push is made with one that is")
	}
	importAt := server.JoinPath("api", "v1", "evidence", "import")
	q := url.Values{"format": {o.format}}
	if o.source != "" {
		q.Set("source", o.source)
	}
	importAt.RawQuery = q.Encode()
	proof, err = dpop.Prove(key, http.MethodPost, server.JoinPath("api", "v1", "evidence", "import").String(),
		exchanged.AccessToken, now())
	if err != nil {
		return nil, err
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, importAt.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "DPoP "+exchanged.AccessToken)
	req.Header.Set("DPoP", proof)
	answer := map[string]any{}
	status, err = pushDo(c, req, &answer)
	if err != nil {
		return nil, err
	}
	if status != http.StatusCreated {
		why, _ := answer["error"].(string)
		detail, _ := answer["detail"].(string)
		err := fmt.Errorf("the server refused the push (%d): %s %s", status, plaintext.Clip(why, 400, "…"),
			plaintext.Clip(detail, 400, "…"))
		if status == http.StatusForbidden || status == http.StatusUnauthorized {
			return nil, errBlocked{err}
		}
		return nil, err
	}
	return answer, nil
}

// pushServer is the server's address: https, or http to this machine for
// a test, with no path, query or credentials in it.
func pushServer(to string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(to), "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("--to is the server's address, such as https://admin.example, with nothing after it")
	}
	host := u.Hostname()
	loopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		loopback = true
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return nil, fmt.Errorf("--to is an https address: the job's identity token goes to it")
	}
	u.Path = ""
	return u, nil
}

// jobIdentity is the identity token the job's platform signs for this run.
func jobIdentity(ctx context.Context, c *http.Client, audience, tokenEnv string) (string, error) {
	if at, bearer := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"); at != "" && bearer != "" {
		u, err := url.Parse(at)
		if err != nil || u.Scheme != "https" {
			return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL is not an https address")
		}
		q := u.Query()
		q.Set("audience", audience)
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "bearer "+bearer)
		var got struct {
			Value string `json:"value"`
		}
		status, err := pushDo(c, req, &got)
		if err != nil {
			return "", err
		}
		if status != http.StatusOK || got.Value == "" {
			return "", fmt.Errorf("GitHub Actions gave no identity token (%d); the job needs permissions: id-token: write", status)
		}
		return got.Value, nil
	}
	if v := strings.TrimSpace(os.Getenv(tokenEnv)); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no identity token: in GitHub Actions give the job permissions: id-token: write; in GitLab CI "+
		"declare id_tokens: %s: aud: the server's address", tokenEnv)
}

// pushDo sends a request and reads a JSON answer of at most 1 MiB.
func pushDo(c *http.Client, req *http.Request, into any) (int, error) {
	res, err := c.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", req.URL.Host, err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return res.StatusCode, err
	}
	_ = json.Unmarshal(b, into)
	return res.StatusCode, nil
}

// oauthWord is an OAuth error code as a server wrote it, if it is one.
func oauthWord(s string) string {
	for _, r := range s {
		if !(r == '_' || r >= 'a' && r <= 'z') {
			return ""
		}
	}
	return plaintext.Clip(s, 40, "…")
}
