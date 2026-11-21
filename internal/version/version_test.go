package version

import "testing"

func TestString(t *testing.T) {
	if got := String(); got != "asi "+Version {
		t.Fatalf("String() = %q", got)
	}
}
