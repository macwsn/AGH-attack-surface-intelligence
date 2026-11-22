package inventory

import "testing"

// REQ-INVENTORY-018
func TestMedian(t *testing.T) {
	cases := []struct {
		in   []int64
		want int64
	}{
		{nil, 0},
		{[]int64{7}, 7},
		{[]int64{900, 100, 120}, 120},
		{[]int64{100, 200, 300, 400}, 250},
		{[]int64{2000, 100, 100, 110, 90, 100, 105, 95, 100, 100}, 100},
	}
	for _, c := range cases {
		if got := Median(c.in); got != c.want {
			t.Errorf("Median(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

// REQ-INVENTORY-018
func TestSlowerThanUsual(t *testing.T) {
	cases := []struct {
		latest, median int64
		want           bool
	}{
		{1600, 500, true},
		{1500, 500, false},
		{600, 150, true},
		{500, 100, false},
		{501, 100, true},
		{450, 10, false},
		{9000, 9000, false},
	}
	for _, c := range cases {
		if got := SlowerThanUsual(c.latest, c.median); got != c.want {
			t.Errorf("SlowerThanUsual(%d, %d) = %v, want %v", c.latest, c.median, got, c.want)
		}
	}
}
