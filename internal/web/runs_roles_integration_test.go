//go:build integration

package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"asi/internal/auth"
	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/schedule"
)

// REQ-SCHEDULE-008
func TestRunPageReadableByEveryRoleActionsNeedScanRun(t *testing.T) {
	ctx := context.Background()
	site := newInventorySite(t, func(context.Context, *inventory.Inventory) {})
	deps := site.deps
	deps.Scans = &schedule.Scheduler{Store: schedule.NewStore(site.deps.Store, site.deps.Keyring), Scanner: &scan.Scanner{Store: site.inv}}
	h, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		role    string
		scanRun bool
	}{
		{auth.RoleViewer, false},
		{auth.RoleOperator, false},
		{auth.RoleEditor, true},
		{auth.RoleAdmin, true},
	} {
		t.Run(c.role, func(t *testing.T) {
			run, err := site.inv.CreateRun(ctx, inventory.RunSpec{Name: "run-" + c.role, Settings: inventory.RunSettings{Workers: 1}})
			if err != nil {
				t.Fatal(err)
			}
			if err := site.inv.SetRunTotal(ctx, run.ID, 10); err != nil {
				t.Fatal(err)
			}
			page := fmt.Sprintf("/runs/%d", run.ID)
			rec := do(h, http.MethodGet, page, nil, site.cookies[c.role])
			body := rec.Body.String()
			if rec.Code != http.StatusOK {
				t.Fatalf("%s GET %s = %d, want 200", c.role, page, rec.Code)
			}
			if !strings.Contains(body, `<span class="label">Addresses scanned</span>`) {
				t.Errorf("%s run page lacks the progress figures", c.role)
			}
			pauseForm := strings.Contains(body, `action="`+page+`/pause"`)
			resumeForm := strings.Contains(body, `action="`+page+`/resume"`)
			if pauseForm != c.scanRun {
				t.Errorf("%s run page shows the pause form = %v, want %v", c.role, pauseForm, c.scanRun)
			}
			if !c.scanRun && resumeForm {
				t.Errorf("%s run page shows the resume form", c.role)
			}
			for _, action := range []string{"pause", "resume"} {
				rec := postForm(h, page+"/"+action, url.Values{}, site.cookies[c.role], site.csrf[c.role])
				if c.scanRun {
					if rec.Code == http.StatusForbidden {
						t.Errorf("%s POST %s/%s = 403, want allowed", c.role, page, action)
					}
				} else if rec.Code != http.StatusForbidden {
					t.Errorf("%s POST %s/%s = %d, want 403", c.role, page, action, rec.Code)
				}
			}
		})
	}
}
