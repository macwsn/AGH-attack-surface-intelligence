package nmap

import (
	"encoding/xml"
	"fmt"
	"io"
)

type xmlRun struct {
	Hosts []xmlHost `xml:"host"`
}

type xmlHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr string `xml:"addr,attr"`
		Type string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		ID       int    `xml:"portid,attr"`
		State    struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Service struct {
			Name      string `xml:"name,attr"`
			Product   string `xml:"product,attr"`
			Version   string `xml:"version,attr"`
			ExtraInfo string `xml:"extrainfo,attr"`
			Tunnel    string `xml:"tunnel,attr"`
		} `xml:"service"`
	} `xml:"ports>port"`
}

func Parse(r io.Reader) ([]Host, error) {
	var run xmlRun
	if err := xml.NewDecoder(r).Decode(&run); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}
	hosts := make([]Host, 0, len(run.Hosts))
	for _, xh := range run.Hosts {
		h := Host{Up: xh.Status.State == "up"}
		for _, a := range xh.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				h.Address = a.Addr
				break
			}
		}
		if h.Address == "" {
			return nil, fmt.Errorf("parse nmap xml: host without ip address")
		}
		for _, n := range xh.Hostnames {
			h.Hostnames = append(h.Hostnames, n.Name)
		}
		for _, xp := range xh.Ports {
			h.Ports = append(h.Ports, Port{
				Number:    xp.ID,
				Protocol:  xp.Protocol,
				State:     xp.State.State,
				Service:   xp.Service.Name,
				Product:   xp.Service.Product,
				Version:   xp.Service.Version,
				ExtraInfo: xp.Service.ExtraInfo,
				Tunnel:    xp.Service.Tunnel,
			})
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}
