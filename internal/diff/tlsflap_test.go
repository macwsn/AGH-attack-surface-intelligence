package diff

import (
	"testing"

	"asi/internal/inventory"
	"asi/internal/probe"
)

func TestTransientTLSFailureDoesNotFlapServiceName(t *testing.T) {
	const addr = "172.30.0.18"
	good := webSvc(443, active)
	good.Service = "https"
	failed := svc(443, active)
	failed.HTTP = &probe.HTTP{Scheme: "https", URL: "https://172.30.0.18/", Headers: map[string]string{}, Cookies: []probe.Cookie{}, RedirectChain: []string{}, Error: probe.ErrorTLSHandshake}
	runs := []inventory.ExportService{good, failed, good}
	for i := 1; i < len(runs); i++ {
		d := Compute(export("r1", host(addr, active, runs[i-1])), export("r2", host(addr, active, runs[i])), Options{})
		for _, c := range d.Changes {
			if c.Type == ServiceChanged {
				t.Errorf("run %d->%d: transient TLS failure produced service_changed %+v", i, i+1, c.Fields)
			}
		}
	}
}
