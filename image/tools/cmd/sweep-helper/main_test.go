package main

import "testing"

func TestLastPathSegment(t *testing.T) {
	cases := map[string]string{
		"myharbor/mirror/cyberchef":      "cyberchef",
		"cyberchef":                      "cyberchef",
		"harbor.test:30003/lib/a/b/c":    "c",
		"harbor.test:30003/library/xxx":  "xxx",
	}
	for in, want := range cases {
		if got := lastPathSegment(in); got != want {
			t.Errorf("lastPathSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParsePlatform(t *testing.T) {
	cases := []struct{ in, os, arch, variant string }{
		{"linux/amd64", "linux", "amd64", ""},
		{"linux/arm64", "linux", "arm64", ""},
		{"linux/arm/v7", "linux", "arm", "v7"},
	}
	for _, c := range cases {
		o, a, v := parsePlatform(c.in)
		if o != c.os || a != c.arch || v != c.variant {
			t.Errorf("parsePlatform(%q) = (%q,%q,%q), want (%q,%q,%q)", c.in, o, a, v, c.os, c.arch, c.variant)
		}
	}
}

func TestSplitNonEmpty(t *testing.T) {
	if got := splitNonEmpty(""); len(got) != 0 {
		t.Errorf("splitNonEmpty(\"\") = %v, want empty", got)
	}
	if got := splitNonEmpty("linux/amd64"); len(got) != 1 || got[0] != "linux/amd64" {
		t.Errorf("splitNonEmpty single = %v", got)
	}
	if got := splitNonEmpty("linux/amd64, linux/arm64 "); len(got) != 2 {
		t.Errorf("splitNonEmpty two = %v", got)
	}
}

func TestRenderTagTemplate(t *testing.T) {
	got, err := renderTagTemplate(defaultTagTemplate, "11.3")
	if err != nil {
		t.Fatal(err)
	}
	if got != "11.3-patched" {
		t.Errorf("renderTagTemplate default = %q, want 11.3-patched", got)
	}
	got, err = renderTagTemplate("patched-{{ .SourceTag }}", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if got != "patched-1.0" {
		t.Errorf("renderTagTemplate custom = %q, want patched-1.0", got)
	}
}
