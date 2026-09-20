package main

import "testing"

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
