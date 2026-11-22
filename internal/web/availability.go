package web

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"strings"

	"asi/internal/auth"
	"asi/internal/inventory"
)

type availabilityCell struct {
	Class string
	Title string
}

type availabilityView struct {
	Address string
	Samples int
	Cells   []availabilityCell
	Words   string
}

func RegisterAvailability(r *Router, d Deps) {
	r.Handle(http.MethodGet, "/hosts/{address}/availability", Require(auth.PermInventoryRead), func(w http.ResponseWriter, req *http.Request) {
		if d.Store == nil {
			r.ServerError(w, req, errors.New("availability page: no database"))
			return
		}
		raw := req.PathValue("address")
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			r.Error(w, req, http.StatusNotFound, fmt.Sprintf("There is no host %q in the inventory.", raw))
			return
		}
		want := addr.Unmap().String()
		inv := inventory.New(d.Store, d.Keyring)
		if _, err := inv.GetHostUserFields(req.Context(), want); errors.Is(err, inventory.ErrUnknownHost) {
			r.Error(w, req, http.StatusNotFound, fmt.Sprintf("There is no host %q in the inventory.", want))
			return
		} else if err != nil {
			r.ServerError(w, req, err)
			return
		}
		exp, err := inv.Export(req.Context(), "")
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		profile := inventory.NewAvailability()
		for _, h := range exp.Hosts {
			if h.Address == want {
				profile = h.Availability.Profile()
				break
			}
		}
		v := availabilityOf(want, profile)
		r.Render(w, req, http.StatusOK, "availability.html", View{Title: "Availability of " + want, Data: v})
	})
}

func availabilityOf(address string, a inventory.Availability) availabilityView {
	v := availabilityView{Address: address, Samples: a.Samples}
	if a.Samples == 0 {
		v.Words = "No availability data yet"
		return v
	}
	for h, p := range a.Hours {
		c := availabilityCell{Title: fmt.Sprintf("%02d:00 up %d%%", h, int(math.Round(p*100)))}
		switch {
		case p >= inventory.UsuallyUp:
			c.Class = "seen"
		case p <= inventory.UsuallyDown:
			c.Class = "missed"
		}
		v.Cells = append(v.Cells, c)
	}
	v.Words = usualHoursText(a.UsualHours())
	return v
}

func usualHoursText(hours []int) string {
	var up [24]bool
	for _, h := range hours {
		if h >= 0 && h < 24 {
			up[h] = true
		}
	}
	var ranges []string
	for h := range 24 {
		if !up[h] || up[(h+23)%24] {
			continue
		}
		end := h
		for up[(end+1)%24] {
			end = (end + 1) % 24
		}
		ranges = append(ranges, fmt.Sprintf("%02d:00-%02d:00", h, (end+1)%24))
	}
	if len(ranges) == 0 {
		return "No regular hours yet"
	}
	return "Usually up " + strings.Join(ranges, ", ")
}
