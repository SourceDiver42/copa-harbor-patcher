package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckAuth(t *testing.T) {
	secret := []byte("s3cr3t")
	cases := []struct {
		name   string
		header string
		want   bool
	}{
		{"correct", "Bearer s3cr3t", true},
		{"wrong token", "Bearer nope", false},
		{"missing prefix", "s3cr3t", false},
		{"empty", "", false},
		{"different length", "Bearer s3cr3t-but-longer", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkAuth(tc.header, secret); got != tc.want {
				t.Errorf("checkAuth(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}

func TestSplitRef(t *testing.T) {
	cases := []struct {
		ref, repo, tag string
		wantErr        bool
	}{
		{"harbor.local:30003/library/python:3.7-alpine-patched", "harbor.local:30003/library/python", "3.7-alpine-patched", false},
		{"harbor.local/library/nginx:1.25", "harbor.local/library/nginx", "1.25", false},
		{"harbor.local/library/notag", "", "", true},
	}
	for _, tc := range cases {
		repo, tag, err := splitRef(tc.ref)
		if tc.wantErr {
			if err == nil {
				t.Errorf("splitRef(%q): expected error, got none", tc.ref)
			}
			continue
		}
		if err != nil || repo != tc.repo || tag != tc.tag {
			t.Errorf("splitRef(%q) = (%q, %q, %v), want (%q, %q, nil)", tc.ref, repo, tag, err, tc.repo, tc.tag)
		}
	}
}

func TestValidRef(t *testing.T) {
	cases := []struct {
		repo, tag string
		want      bool
	}{
		{"harbor.local:30003/library/python", "3.7-alpine-patched", true},
		{"harbor.local/library/python", "1.0", true},
		{"harbor.local/library/python", "; rm -rf /", false},
		{"harbor.local/library/python$(whoami)", "1.0", false},
		{"", "1.0", false},
		{"harbor.local/library/python", "", false},
	}
	for _, tc := range cases {
		if got := validRef(tc.repo, tc.tag); got != tc.want {
			t.Errorf("validRef(%q, %q) = %v, want %v", tc.repo, tc.tag, got, tc.want)
		}
	}
}

func TestExtractRef(t *testing.T) {
	p := harborPayload{}
	p.EventData.Resources = []struct {
		ResourceURL string `json:"resource_url"`
		Tag         string `json:"tag"`
	}{{ResourceURL: "harbor.local/library/python:3.7-alpine-patched"}}

	repo, tag, err := extractRef(p, "")
	if err != nil || repo != "harbor.local/library/python" || tag != "3.7-alpine-patched" {
		t.Fatalf("extractRef = (%q, %q, %v)", repo, tag, err)
	}

	empty := harborPayload{}
	if _, _, err := extractRef(empty, ""); err == nil {
		t.Fatal("expected error for payload with no resources")
	}
}

func TestHandleWebhook_RejectsBadAuth(t *testing.T) {
	s := &server{sharedSecret: []byte("s3cr3t"), patchScript: "/bin/true", patchTimeout: time.Second}
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()

	s.handleWebhook(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleWebhook_RejectsBadPayloadSameStatusAsAuth(t *testing.T) {
	s := &server{sharedSecret: []byte("s3cr3t"), patchScript: "/bin/true", patchTimeout: time.Second}
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(`{"event_data":{"resources":[]}}`))
	req.Header.Set("Authorization", "Bearer s3cr3t")
	rec := httptest.NewRecorder()

	s.handleWebhook(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (same as bad-auth response)", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleWebhook_AcceptsValidRequest(t *testing.T) {
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("no /bin/true-equivalent on PATH")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	script := filepath.Join(dir, "patch-one.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch \""+marker+"\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	s := &server{sharedSecret: []byte("s3cr3t"), patchScript: script, patchTimeout: 5 * time.Second}
	body := `{"event_data":{"resources":[{"resource_url":"harbor.local/library/python:3.7-alpine-patched"}]}}`
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer s3cr3t")
	rec := httptest.NewRecorder()

	s.handleWebhook(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("patch script did not run in time")
}
