package schedule

import (
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
)

func TestValidateRejectsMaxRateBelowTwo(t *testing.T) {
	for _, rate := range []int{0, 1} {
		d := Definition{
			Name:          "max rate",
			InactiveAfter: 3,
			Settings: inventory.RunSettings{
				Targets: []string{"10.0.0.0/28"},
				Ports:   []int{80, 443},
				MaxRate: rate,
				Workers: 1,
			},
			Schedule: Schedule{
				Timezone:  "Europe/Warsaw",
				Windows:   []Window{{Days: []time.Weekday{1, 2, 3, 4, 5}, Start: "22:00", End: "02:00"}},
				Frequency: Frequency{Kind: FrequencyDaily},
			},
		}
		err := d.Validate()
		if err == nil || !strings.Contains(err.Error(), "max rate: enter at least 2") {
			t.Errorf("Validate with max rate %d: err = %v, want a \"max rate: enter at least 2\" error", rate, err)
		}
	}
	ok := Definition{
		Name:          "max rate",
		InactiveAfter: 3,
		Settings:      inventory.RunSettings{Targets: []string{"10.0.0.0/28"}, Ports: []int{80}, MaxRate: 2, Workers: 1},
		Schedule:      Schedule{Timezone: "Europe/Warsaw", Frequency: Frequency{Kind: FrequencyDaily}},
	}
	if err := ok.Validate(); err != nil {
		t.Errorf("Validate with max rate 2: %v", err)
	}
}
