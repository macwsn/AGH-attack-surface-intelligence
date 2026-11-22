package schedule

import (
	"strings"
	"testing"

	"asi/internal/inventory"
)

func TestDefinitionValidateRefusesAddressesTimesPortsAboveCeiling(t *testing.T) {
	ports := make([]int, 1001)
	for i := range ports {
		ports[i] = i + 1
	}
	d := Definition{
		Name:          "wide",
		InactiveAfter: 3,
		Settings:      inventory.RunSettings{Targets: []string{"10.0.0.0/14"}, Ports: ports, MaxRate: 100, Workers: 1},
		Schedule:      Schedule{Frequency: Frequency{Kind: FrequencyDaily}},
	}
	err := d.Validate()
	if err == nil {
		t.Fatal("saving a scan definition of 262144 addresses x 1001 ports succeeded, want a refusal above the work ceiling")
	}
	if !strings.Contains(err.Error(), "26214") || !strings.Contains(err.Error(), "1001") {
		t.Fatalf("Validate = %q, want it to name 262144 addresses and 1001 ports", err)
	}
}
