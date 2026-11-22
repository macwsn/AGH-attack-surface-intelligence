package web

import (
	"testing"
	"time"
)

// REQ-SCAN-021: AC3 of T-803xb7cwjk
func TestFormatRange(t *testing.T) {
	for _, tc := range []struct {
		low, high time.Duration
		want      string
	}{
		{0, 0, "-"},
		{10 * time.Second, 40 * time.Second, "about 1 min or less"},
		{164 * time.Second, 655 * time.Second, "about 2-11 min"},
		{30 * time.Second, 90 * time.Second, "about 1-2 min"},
		{2 * time.Minute, 2 * time.Minute, "about 2 min"},
		{100 * time.Minute, 200 * time.Minute, "about 1-4 h"},
	} {
		if got := formatRange(tc.low, tc.high); got != tc.want {
			t.Errorf("formatRange(%s, %s) = %q, want %q", tc.low, tc.high, got, tc.want)
		}
	}
}
