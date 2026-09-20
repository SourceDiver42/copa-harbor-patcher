// webhook-server is a narrow HTTP receiver for Harbor webhook events. It
// authenticates the request against a shared secret, extracts only the
// repository+tag identifying the artifact that changed, and execs
// patch-one.sh with those two values as argv — it never interpolates
// webhook-supplied data into a shell string, and it never trusts or parses
// Harbor's own vulnerability-report data (patch-one.sh re-scans itself).
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const maxBodyBytes = 1 << 20 // 1 MiB is generous for a Harbor webhook payload

// refPattern allows a bare Docker/OCI reference: registry host (with
// optional port), one or more path segments, and a tag. Deliberately
// conservative — this is the only thing standing between an authenticated
// caller's JSON body and an exec.Command argv.
var refPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?(:[0-9]+)?(/[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?)+:[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$`)

// harborPayload captures only the fields we need from Harbor's webhook
// payload (v2 "resources"-style event body used for PUSH_ARTIFACT and
// SCANNING_COMPLETED events). Every other field Harbor sends, including any
// vulnerability summary, is deliberately ignored.
type harborPayload struct {
	Type      string `json:"type"`
	EventData struct {
		Resources []struct {
			ResourceURL string `json:"resource_url"`
			Tag         string `json:"tag"`
		} `json:"resources"`
		Repository struct {
			RepoFullName string `json:"repo_full_name"`
		} `json:"repository"`
	} `json:"event_data"`
}

type server struct {
	sharedSecret []byte
	patchScript  string
	patchTimeout time.Duration
	registryHost string // used to build a full ref if a resource lacks resource_url
}

func main() {
	secret := os.Getenv("WEBHOOK_SHARED_SECRET")
	if secret == "" {
		log.Fatal("WEBHOOK_SHARED_SECRET must be set")
	}
	addr := os.Getenv("WEBHOOK_ADDR")
	if addr == "" {
		addr = ":8443"
	}
	patchScript := os.Getenv("PATCH_SCRIPT")
	if patchScript == "" {
		patchScript = "/usr/local/bin/patch-one.sh"
	}
	timeout := 15 * time.Minute
	if v := os.Getenv("PATCH_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			timeout = d
		} else {
			log.Printf("invalid PATCH_TIMEOUT %q, using default %s", v, timeout)
		}
	}

	s := &server{
		sharedSecret: []byte(secret),
		patchScript:  patchScript,
		patchTimeout: timeout,
		registryHost: os.Getenv("HARBOR_REGISTRY_HOST"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/webhook", s.handleWebhook)

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("webhook-server listening on %s", addr)
	log.Fatal(httpServer.ListenAndServe())
}

// unauthorized responds identically regardless of whether auth or payload
// validation failed, so the endpoint can't be used as an oracle to test
// guesses at the shared secret. Detail is only ever logged server-side.
func unauthorized(w http.ResponseWriter, detail string) {
	log.Printf("rejecting request: %s", detail)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (s *server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkAuth(r.Header.Get("Authorization"), s.sharedSecret) {
		unauthorized(w, "bad or missing bearer token")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		unauthorized(w, fmt.Sprintf("failed to read body: %v", err))
		return
	}

	var payload harborPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		unauthorized(w, fmt.Sprintf("invalid JSON body: %v", err))
		return
	}

	repo, tag, err := extractRef(payload, s.registryHost)
	if err != nil {
		unauthorized(w, fmt.Sprintf("could not extract ref: %v", err))
		return
	}
	if !validRef(repo, tag) {
		unauthorized(w, fmt.Sprintf("ref failed validation: %s:%s", repo, tag))
		return
	}

	w.WriteHeader(http.StatusAccepted)

	go s.runPatch(repo, tag)
}

// checkAuth compares the request's bearer token to the configured secret in
// constant time.
func checkAuth(authHeader string, secret []byte) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}
	token := []byte(strings.TrimPrefix(authHeader, prefix))
	// subtle.ConstantTimeCompare requires equal-length inputs to be
	// meaningful; a length mismatch is not itself a useful timing signal
	// here since token length leaks nothing about the secret's content.
	if len(token) != len(secret) {
		return false
	}
	return subtle.ConstantTimeCompare(token, secret) == 1
}

// extractRef pulls a full "repo:tag" reference out of a Harbor webhook
// payload. It prefers the first resource's resource_url (Harbor typically
// sends this as the full registry/project/repo:tag reference already);
// falling back to repository.repo_full_name + a resource's tag field,
// prefixed with registryHost, only if resource_url is absent.
func extractRef(p harborPayload, registryHost string) (repo, tag string, err error) {
	if len(p.EventData.Resources) == 0 {
		return "", "", errors.New("no resources in event_data")
	}
	res := p.EventData.Resources[0]

	if res.ResourceURL != "" {
		return splitRef(res.ResourceURL)
	}

	if p.EventData.Repository.RepoFullName == "" || res.Tag == "" {
		return "", "", errors.New("resource_url absent and repo_full_name/tag incomplete")
	}
	if registryHost == "" {
		return "", "", errors.New("resource_url absent and HARBOR_REGISTRY_HOST not configured")
	}
	return fmt.Sprintf("%s/%s", registryHost, p.EventData.Repository.RepoFullName), res.Tag, nil
}

// splitRef splits "host[:port]/path...:tag" into repo and tag, correctly
// treating a colon that appears before the last "/" as part of a host:port
// rather than the tag separator.
func splitRef(ref string) (repo, tag string, err error) {
	lastSlash := strings.LastIndex(ref, "/")
	tagSep := strings.LastIndex(ref, ":")
	if tagSep <= lastSlash {
		return "", "", fmt.Errorf("reference %q has no tag", ref)
	}
	return ref[:tagSep], ref[tagSep+1:], nil
}

// validRef applies an allowlist check before repo/tag ever reach exec.Command.
func validRef(repo, tag string) bool {
	if len(repo) == 0 || len(repo) > 255 || len(tag) == 0 || len(tag) > 128 {
		return false
	}
	return refPattern.MatchString(repo + ":" + tag)
}

func (s *server) runPatch(repo, tag string) {
	ctx, cancel := context.WithTimeout(context.Background(), s.patchTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.patchScript, repo, tag)
	cmd.Stdout = logWriter{prefix: fmt.Sprintf("[%s:%s] ", repo, tag)}
	cmd.Stderr = cmd.Stdout

	log.Printf("starting patch for %s:%s", repo, tag)
	if err := cmd.Run(); err != nil {
		log.Printf("patch failed for %s:%s: %v", repo, tag, err)
		return
	}
	log.Printf("patch succeeded for %s:%s", repo, tag)
}

// logWriter adapts the standard logger to io.Writer for streaming a
// subprocess's combined output line-by-line-ish (best effort; not
// line-buffered, just prefixed per Write call).
type logWriter struct{ prefix string }

func (w logWriter) Write(p []byte) (int, error) {
	log.Print(w.prefix, string(p))
	return len(p), nil
}
