package inventory

func DeriveStatus(seen []bool, n int) (Status, int, float64) {
	if n <= 0 {
		n = DefaultInactiveAfter
	}
	missed := 0
	for i := len(seen) - 1; i >= 0 && !seen[i]; i-- {
		missed++
	}
	window := seen
	if len(window) > StabilityWindow {
		window = window[len(window)-StabilityWindow:]
	}
	stability := 0.0
	if len(window) > 0 {
		hits := 0
		for _, s := range window {
			if s {
				hits++
			}
		}
		stability = float64(hits) / float64(len(window))
	}
	switch {
	case missed == 0:
		return StatusActive, 0, stability
	case missed >= n:
		return StatusInactive, missed, stability
	default:
		return StatusUnstable, missed, stability
	}
}
