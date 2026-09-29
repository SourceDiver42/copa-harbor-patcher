package main

import (
	"archive/tar"
	"bytes"
	"testing"
)

// TestFindOSReleaseSkipsSymlink reproduces the Alpine layout where
// /etc/os-release is a symlink to /usr/lib/os-release: the symlink entry has
// no content, so the scanner must skip it and read the real file instead of
// returning an empty OS type.
func TestFindOSReleaseSkipsSymlink(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	// Symlink first (as it typically appears in the tar), with no body.
	if err := tw.WriteHeader(&tar.Header{
		Name:     "etc/os-release",
		Typeflag: tar.TypeSymlink,
		Linkname: "../usr/lib/os-release",
	}); err != nil {
		t.Fatal(err)
	}
	// The real file, which carries the actual data.
	body := []byte("NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.24.1\n")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "usr/lib/os-release",
		Typeflag: tar.TypeReg,
		Size:     int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	osType, osVersion, found, err := findOSRelease(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("findOSRelease error: %v", err)
	}
	if !found || osType != "alpine" || osVersion != "3.24.1" {
		t.Fatalf("findOSRelease = (%q, %q, found=%v), want (\"alpine\", \"3.24.1\", true)", osType, osVersion, found)
	}
}

// mimeKeyedBody is the shape Harbor actually returns from
// /additions/vulnerabilities: a JSON object keyed by report MIME type. The
// previous flat-struct decode silently produced zero vulnerabilities here.
const mimeKeyedBody = `{
  "application/vnd.security.vulnerability.report; version=1.1": {
    "generated_at": "2026-01-01T00:00:00Z",
    "severity": "Critical",
    "vulnerabilities": [
      {"id": "CVE-2024-0001", "package": "openssl", "version": "3.0.0", "fix_version": "3.0.1", "severity": "High"},
      {"id": "CVE-2024-0002", "package": "zlib", "version": "1.2.0", "fix_version": "", "severity": "Low"}
    ]
  }
}`

const flatBody = `{
  "generated_at": "2026-01-01T00:00:00Z",
  "vulnerabilities": [
    {"id": "CVE-2024-0003", "package": "musl", "version": "1.2.3", "fix_version": "1.2.4", "severity": "Medium"}
  ]
}`

func TestParseHarborReport(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		wantCount    int
		wantFirstPkg string
	}{
		{"mime-keyed", mimeKeyedBody, 2, "openssl"},
		{"flat", flatBody, 1, "musl"},
		{"empty-mime-keyed", `{"application/vnd.security.vulnerability.report; version=1.1": {"vulnerabilities": []}}`, 0, ""},
		{"empty-flat", `{"vulnerabilities": []}`, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := parseHarborReport([]byte(tc.body))
			if err != nil {
				t.Fatalf("parseHarborReport() error: %v", err)
			}
			if len(report.Vulnerabilities) != tc.wantCount {
				t.Fatalf("got %d vulnerabilities, want %d", len(report.Vulnerabilities), tc.wantCount)
			}
			if tc.wantFirstPkg != "" && report.Vulnerabilities[0].Package != tc.wantFirstPkg {
				t.Errorf("first package = %q, want %q", report.Vulnerabilities[0].Package, tc.wantFirstPkg)
			}
		})
	}
}

func TestParseOSRelease(t *testing.T) {
	cases := []struct {
		name        string
		data        string
		wantType    string
		wantVersion string
	}{
		{
			name:        "alpine",
			data:        "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.18.4\nPRETTY_NAME=\"Alpine Linux v3.18\"\n",
			wantType:    "alpine",
			wantVersion: "3.18.4",
		},
		{
			name:        "debian quoted",
			data:        "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n",
			wantType:    "debian",
			wantVersion: "12",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotVersion := parseOSRelease([]byte(tc.data))
			if gotType != tc.wantType || gotVersion != tc.wantVersion {
				t.Errorf("parseOSRelease() = (%q, %q), want (%q, %q)", gotType, gotVersion, tc.wantType, tc.wantVersion)
			}
		})
	}
}
