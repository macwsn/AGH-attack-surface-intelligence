package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"

	"asi/internal/auth"
	"asi/internal/diff"
	"asi/internal/inventory"
)

const (
	cellPitch    = 10
	highInterest = 70
)

type stripCell struct {
	Class string
	X     float64
	Title string
}

type timelineRun struct {
	Name    string
	At      string
	Class   string
	Label   string
	Changes []changeRow
}

type timelineData struct {
	Address    string
	Status     inventory.Status
	StatusText string
	Usual      string
	Score      int
	High       bool
	Reasons    []inventory.Reason
	Cells      []stripCell
	StripWidth int
	Seen       int
	Covering   int
	Runs       []timelineRun
}

var statusLabels = map[inventory.Status]string{inventory.StatusActive: "Active", inventory.StatusUnstable: "Unstable", inventory.StatusInactive: "Inactive"}

var presenceLabels = map[string]string{"seen": "Seen", "missed": "Missed", "uncovered": "Not covered"}

func RegisterTimeline(r *Router, d Deps) {
	inv := d.Inventory
	if inv == nil && d.Store != nil {
		inv = inventory.New(d.Store, d.Keyring)
	}
	r.Handle(http.MethodGet, "/hosts/{address}/timeline", Require(auth.PermInventoryRead), func(w http.ResponseWriter, req *http.Request) {
		r.timelinePage(w, req, inv)
	})
}

func (r *Router) timelinePage(w http.ResponseWriter, req *http.Request, inv Inventory) {
	if inv == nil {
		r.ServerError(w, req, errors.New("timeline: no inventory configured"))
		return
	}
	raw := req.PathValue("address")
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		r.Error(w, req, http.StatusBadRequest, fmt.Sprintf("%q is not an address. Use an IPv4 or IPv6 address such as 192.0.2.10.", raw))
		return
	}
	addr := ip.Unmap().String()
	tl, err := inv.HostTimeline(req.Context(), addr)
	if errors.Is(err, inventory.ErrUnknownHost) {
		r.Error(w, req, http.StatusNotFound, fmt.Sprintf("No host with address %s has been seen. Check the address or pick a host from the changes page.", addr))
		return
	}
	if err != nil {
		r.ServerError(w, req, err)
		return
	}
	r.Render(w, req, http.StatusOK, "timeline.html", View{Title: addr + " timeline", Data: newTimelineData(tl)})
}

func newTimelineData(tl inventory.Timeline) timelineData {
	data := timelineData{Address: tl.Address, Status: tl.Host.Status, StatusText: statusLabels[tl.Host.Status], Score: tl.Score, High: tl.Score >= highInterest,
		Reasons: tl.Reasons, StripWidth: len(tl.Entries) * cellPitch}
	if tl.Usual && tl.Host.Status != inventory.StatusInactive {
		data.Usual = "Usually seen " + tl.Pattern.Label()
	}
	var prev, prevSeen *inventory.TimelineEntry
	for i, e := range tl.Entries {
		class := "uncovered"
		if e.Covered {
			data.Covering++
			class = "missed"
			if e.Seen {
				class = "seen"
				data.Seen++
			}
		}
		at := zonedTime(e.At, nil)
		data.Cells = append(data.Cells, stripCell{Class: class, X: float64(i*cellPitch) + 0.5,
			Title: fmt.Sprintf("%s, %s: %s", e.Run.Name, at, presenceLabels[class])})
		run := timelineRun{Name: e.Run.Name, At: at, Class: class, Label: presenceLabels[class]}
		if e.Covered && e.State != nil {
			for _, c := range entryChanges(tl, prev, &tl.Entries[i]) {
				if c.Port == nil {
					run.Changes = append(run.Changes, newChangeRow(c))
				}
			}
			if e.Seen {
				for _, c := range entryChanges(tl, prevSeen, &tl.Entries[i]) {
					if c.Port != nil {
						run.Changes = append(run.Changes, newChangeRow(c))
					}
				}
				prevSeen = &tl.Entries[i]
			}
			prev = &tl.Entries[i]
		}
		data.Runs = append(data.Runs, run)
	}
	slices.Reverse(data.Runs)
	return data
}

func entryChanges(tl inventory.Timeline, from, to *inventory.TimelineEntry) []diff.Change {
	if from == nil {
		return nil
	}
	return diff.Compute(inventory.Export{Run: from.Run.Name, Hosts: []inventory.ExportHost{*from.State}, VolatileHeaders: from.Run.Settings.VolatileHeaders},
		inventory.Export{Run: to.Run.Name, Hosts: []inventory.ExportHost{*to.State}, VolatileHeaders: to.Run.Settings.VolatileHeaders},
		diff.Options{VolatileHeaders: tl.VolatileHeaders}).Changes
}
