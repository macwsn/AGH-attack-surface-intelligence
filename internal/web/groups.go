package web

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"asi/internal/auth"
	"asi/internal/inventory"
)

const groupMembersShown = 10

type groupMember struct {
	Label    string
	Timeline string
}

type serviceGroupRow struct {
	Technologies string
	Title        string
	Favicon      string
	Count        int
	Members      []groupMember
	More         int
}

type groupsData struct {
	Run    string
	Groups []serviceGroupRow
}

func RegisterGroups(r *Router, d Deps) {
	inv := d.Inventory
	if inv == nil && d.Store != nil {
		inv = inventory.New(d.Store, d.Keyring)
	}
	access := Require(auth.PermInventoryRead)
	r.NavIn(NavInventory, "Groups", "/groups", access)
	r.Handle(http.MethodGet, "/groups", access, func(w http.ResponseWriter, req *http.Request) {
		if inv == nil {
			r.ServerError(w, req, errors.New("groups: no inventory configured"))
			return
		}
		exp, err := inv.Export(req.Context(), "")
		if err != nil {
			r.ServerError(w, req, err)
			return
		}
		r.Render(w, req, http.StatusOK, "groups.html", View{Title: "Groups", Data: newGroupsData(exp)})
	})
}

func newGroupsData(exp inventory.Export) groupsData {
	hosts := make([]inventory.ExportHost, 0, len(exp.Hosts))
	for _, h := range exp.Hosts {
		h.Services = slices.DeleteFunc(slices.Clone(h.Services), func(s inventory.ExportService) bool { return s.Status == inventory.StatusInactive })
		hosts = append(hosts, h)
	}
	data := groupsData{Run: exp.Run}
	for _, g := range inventory.GroupServices(hosts) {
		row := serviceGroupRow{Technologies: strings.Join(g.Key.Technologies, ", "), Title: g.Key.Title, Favicon: g.Key.FaviconSHA256, Count: g.Count}
		for i, m := range g.Members {
			if i == groupMembersShown {
				row.More = len(g.Members) - i
				break
			}
			row.Members = append(row.Members, groupMember{Label: m.Address + ":" + strconv.Itoa(m.Port), Timeline: "/hosts/" + url.PathEscape(m.Address) + "/timeline"})
		}
		data.Groups = append(data.Groups, row)
	}
	return data
}
