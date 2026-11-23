package main

import "testing"

func TestIsNewerVersion(t *testing.T) {
	cases := []struct {
		current string
		latest  string
		want    bool
	}{
		{"1.4.0-preview", "1.4.0", true},
		{"1.4.0-preview", "1.4.1", true},
		{"1.4.0", "1.4.1", true},
		{"1.4.0", "1.5.0", true},
		{"1.4.0", "2.0.0", true},
		{"1.4.0", "1.4.0", false},
		{"1.4.1", "1.4.0", false},
		{"1.4.0", "1.4.0-preview", false},
	}
	for _, tc := range cases {
		if got := isNewerVersion(tc.current, tc.latest); got != tc.want {
			t.Errorf("isNewerVersion(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}
