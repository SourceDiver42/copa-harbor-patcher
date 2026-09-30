package main

import (
	"archive/tar"
	"bytes"
	"testing"
)

// writeTar builds a layer tarball from a list of entries. A nil body with a
// non-empty linkname makes a symlink; otherwise a regular file.
type tarEntry struct {
	name    string
	body    string
	symlink string
}

func writeTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if e.symlink != "" {
			if err := tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeSymlink, Linkname: e.symlink}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Size: int64(len(e.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestScanLayerSkipsSymlink reproduces the Alpine layout where /etc/os-release
// is a symlink to /usr/lib/os-release: the symlink entry has no content, so
// the scanner must skip it and read the real file, and must also pick up the
// apk package DB in the same layer.
func TestScanLayerSkipsSymlink(t *testing.T) {
	layer := writeTar(t, []tarEntry{
		{name: "etc/os-release", symlink: "../usr/lib/os-release"},
		{name: "usr/lib/os-release", body: "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.24.1\n"},
		{name: "lib/apk/db/installed", body: "P:musl\nV:1.2.5-r0\n\nP:busybox\nV:1.36.1-r0\no:busybox\n"},
	})
	osType, osVersion, osPkgs, err := scanLayer(bytes.NewReader(layer))
	if err != nil {
		t.Fatalf("scanLayer error: %v", err)
	}
	if osType != "alpine" || osVersion != "3.24.1" {
		t.Fatalf("scanLayer OS = (%q, %q), want (alpine, 3.24.1)", osType, osVersion)
	}
	if !osPkgs["musl"] || !osPkgs["busybox"] {
		t.Fatalf("scanLayer osPkgs = %v, want musl+busybox present", osPkgs)
	}
}

func TestParseAPKInstalled(t *testing.T) {
	pkgs := parseAPKInstalled([]byte("P:musl\nV:1.2.5-r0\nA:x86_64\n\nP:libssl3\no:openssl\nV:3.3.0-r0\n"))
	for _, want := range []string{"musl", "libssl3", "openssl"} {
		if !pkgs[want] {
			t.Errorf("parseAPKInstalled missing %q; got %v", want, pkgs)
		}
	}
	if pkgs["x86_64"] {
		t.Errorf("parseAPKInstalled should not treat arch (A:) as a package")
	}
}

func TestParseDpkgStatus(t *testing.T) {
	status := "Package: libc6\nStatus: install ok installed\nVersion: 2.36-9\n\n" +
		"Package: libssl3\nSource: openssl\nStatus: install ok installed\n\n" +
		"Package: perl-base\nSource: perl (5.36.0-7)\n"
	pkgs := parseDpkgStatus([]byte(status))
	for _, want := range []string{"libc6", "libssl3", "openssl", "perl-base", "perl"} {
		if !pkgs[want] {
			t.Errorf("parseDpkgStatus missing %q; got %v", want, pkgs)
		}
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
