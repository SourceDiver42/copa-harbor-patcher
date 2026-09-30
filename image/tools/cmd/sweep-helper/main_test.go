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
