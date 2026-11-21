package scan

import (
	"testing"
	"time"
)

// REQ-SCAN-001
func TestSizerAdaptsToMovingAverage(t *testing.T) {
	type obs struct {
		n    int
		d    time.Duration
		want int
	}
	for _, tc := range []struct {
		name string
		obs  []obs
	}{
		{"fast groups grow to the maximum", []obs{
			{64, time.Second, MaxGroupSize},
			{1024, 2 * time.Second, MaxGroupSize},
		}},
		{"slow groups shrink to the minimum", []obs{
			{64, 10 * time.Minute, MinGroupSize},
			{16, 10 * time.Minute, MinGroupSize},
		}},
		{"a group inside 30-60 s keeps the size", []obs{
			{64, 40 * time.Second, 64},
			{64, 55 * time.Second, 64},
		}},
		{"size aims at 45 s from the average", []obs{
			{64, 90 * time.Second, 32},
			{32, 90 * time.Second, 21},
		}},
		{"one outlier is averaged with the window", []obs{
			{100, 45 * time.Second, 100},
			{100, 45 * time.Second, 100},
			{100, 45 * time.Second, 100},
			{100, 450 * time.Second, 30},
		}},
		{"only the last SizeWindow groups count", []obs{
			{64, 640 * time.Second, MinGroupSize},
			{16, 8 * time.Second, MinGroupSize},
			{16, 8 * time.Second, MinGroupSize},
			{16, 8 * time.Second, MinGroupSize},
			{16, 8 * time.Second, 90},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z := &sizer{size: InitialGroupSize}
			if z.current() != 64 {
				t.Fatalf("initial size = %d, want 64", z.current())
			}
			for i, o := range tc.obs {
				z.observe(o.n, o.d)
				if got := z.current(); got != o.want {
					t.Fatalf("after observation %d (%d addresses in %s) size = %d, want %d", i, o.n, o.d, got, o.want)
				}
				if got := z.current(); got < 16 || got > 1024 {
					t.Fatalf("size %d outside 16-1024", got)
				}
			}
		})
	}
}

// REQ-SCAN-001
func TestSizerFixedAndZeroDuration(t *testing.T) {
	z := &sizer{size: 12, fixed: true}
	z.observe(12, time.Hour)
	if z.current() != 12 {
		t.Fatalf("fixed size changed to %d", z.current())
	}
	z = &sizer{size: InitialGroupSize}
	z.observe(64, 0)
	if z.current() != MaxGroupSize {
		t.Fatalf("instant group: size = %d, want %d", z.current(), MaxGroupSize)
	}
	z.observe(0, time.Hour)
	if z.current() != MaxGroupSize {
		t.Fatalf("empty group changed the size to %d", z.current())
	}
}
