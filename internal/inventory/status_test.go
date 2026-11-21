package inventory

import (
	"math"
	"testing"
)

func TestDeriveStatus(t *testing.T) {
	const T, F = true, false
	cases := []struct {
		seen      []bool
		n         int
		status    Status
		missed    int
		stability float64
	}{
		{[]bool{T}, 3, StatusActive, 0, 1.0},
		{[]bool{T, F}, 3, StatusUnstable, 1, 0.5},
		{[]bool{T, F, F}, 3, StatusUnstable, 2, 1.0 / 3},
		{[]bool{T, F, F, F}, 3, StatusInactive, 3, 0.25},
		{[]bool{T, F}, 1, StatusInactive, 1, 0.5},
		{[]bool{T, F, F, T}, 3, StatusActive, 0, 0.5},
		{[]bool{T, T, F, T, T, T, T, T, T, T, T, F}, 3, StatusUnstable, 1, 0.8},
		{[]bool{T, F, F, F}, 0, StatusInactive, 3, 0.25},
		{[]bool{T, F, F}, -1, StatusUnstable, 2, 1.0 / 3},
		{[]bool{T, F, F, F, F}, 5, StatusUnstable, 4, 0.2},
	}
	for _, c := range cases {
		status, missed, stability := DeriveStatus(c.seen, c.n)
		if status != c.status || missed != c.missed || math.Abs(stability-c.stability) > 1e-9 {
			t.Errorf("DeriveStatus(%v, %d) = %s, %d, %v; want %s, %d, %v",
				c.seen, c.n, status, missed, stability, c.status, c.missed, c.stability)
		}
	}
}
