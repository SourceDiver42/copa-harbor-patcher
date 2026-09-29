package main

import "testing"

func TestPickLatestPatchedTag(t *testing.T) {
	cases := []struct {
		name    string
		baseTag string
		tags    []string
		want    string
	}{
		{
			name:    "no patched tags yet",
			baseTag: "1.0-patched",
			tags:    []string{"1.0", "2.0", "1.0-patched-386-notreal"},
			want:    "",
		},
		{
			name:    "only base",
			baseTag: "1.0-patched",
			tags:    []string{"1.0", "1.0-patched"},
			want:    "1.0-patched",
		},
		{
			name:    "numeric re-patch versions win",
			baseTag: "1.0-patched",
			tags:    []string{"1.0-patched", "1.0-patched-1", "1.0-patched-2"},
			want:    "1.0-patched-2",
		},
		{
			// Regression: copa excludes the "-386" arch tag from its patched-tag
			// versioning, so we must too — otherwise we key the report under
			// "1.0-patched-386" while copa looks it up under "1.0-patched",
			// missing every time and re-patching forever.
			name:    "arch-specific -386 tag must be ignored",
			baseTag: "1.0-patched",
			tags:    []string{"1.0-patched", "1.0-patched-386"},
			want:    "1.0-patched",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pickLatestPatchedTag(tc.baseTag, tc.tags)
			if got != tc.want {
				t.Errorf("pickLatestPatchedTag(%q, %v) = %q, want %q", tc.baseTag, tc.tags, got, tc.want)
			}
		})
	}
}
