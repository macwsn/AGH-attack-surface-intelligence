package nmap

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type xmlRun struct {
	Hosts []xmlHost `xml:"host"`
	Stats struct {
		Hosts struct {
			Total string `xml:"total,attr"`
		} `xml:"hosts"`
	} `xml:"runstats"`
}

type xmlHost struct {
	TimedOut string `xml:"timedout,attr"`
	Status   struct {
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
			Method    string `xml:"method,attr"`
			FP        string `xml:"servicefp,attr"`
		} `xml:"service"`
		Scripts []struct {
			ID     string `xml:"id,attr"`
			Output string `xml:"output,attr"`
			Elems  []struct {
				Key   string `xml:"key,attr"`
				Value string `xml:",chardata"`
			} `xml:"elem"`
		} `xml:"script"`
	} `xml:"ports>port"`
}

func Parse(r io.Reader) ([]Host, error) {
	hosts, _, err := parse(r)
	return hosts, err
}

func parse(r io.Reader) ([]Host, string, error) {
	var run xmlRun
	if err := xml.NewDecoder(r).Decode(&run); err != nil {
		return nil, "", fmt.Errorf("parse nmap xml: %w", err)
	}
	hosts := make([]Host, 0, len(run.Hosts))
	for _, xh := range run.Hosts {
		h := Host{Up: xh.Status.State == "up", TimedOut: xh.TimedOut == "true"}
		for _, a := range xh.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				h.Address = a.Addr
				break
			}
		}
		if h.Address == "" {
			return nil, "", fmt.Errorf("parse nmap xml: host without ip address")
		}
		for _, n := range xh.Hostnames {
			h.Hostnames = append(h.Hostnames, n.Name)
		}
		for _, xp := range xh.Ports {
			banner := nullResponse(xp.Service.FP)
			var scriptProduct, scriptVersion string
			for _, sc := range xp.Scripts {
				if sc.ID == "banner" && banner == "" {
					banner = sc.Output
				}
				for _, e := range sc.Elems {
					switch e.Key {
					case "product":
						scriptProduct = strings.TrimSpace(e.Value)
					case "version":
						scriptVersion = strings.TrimSpace(e.Value)
					}
				}
			}
			h.Ports = append(h.Ports, Port{
				Number:        xp.ID,
				Protocol:      xp.Protocol,
				State:         xp.State.State,
				Service:       xp.Service.Name,
				Product:       xp.Service.Product,
				Version:       xp.Service.Version,
				ExtraInfo:     xp.Service.ExtraInfo,
				Tunnel:        xp.Service.Tunnel,
				Guessed:       xp.State.State == "open" && xp.Service.Method == "table",
				Banner:        banner,
				ScriptProduct: scriptProduct,
				ScriptVersion: scriptVersion,
			})
		}
		hosts = append(hosts, h)
	}
	return hosts, run.Stats.Hosts.Total, nil
}

func nullResponse(fp string) string {
	fp = strings.ReplaceAll(fp, "\nSF:", "")
	_, rest, ok := strings.Cut(fp, "%r(NULL,")
	if !ok {
		return ""
	}
	_, rest, ok = strings.Cut(rest, ",\"")
	if !ok {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch {
		case c == '"':
			return b.String()
		case c != '\\' || i+1 == len(rest):
			b.WriteByte(c)
		default:
			i++
			switch rest[i] {
			case 'r':
				b.WriteByte('\r')
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case '0':
				b.WriteByte(0)
			case 'x':
				if n, err := strconv.ParseUint(rest[i+1:min(i+3, len(rest))], 16, 8); err == nil {
					b.WriteByte(byte(n))
					i += 2
				} else {
					b.WriteByte('x')
				}
			default:
				b.WriteByte(rest[i])
			}
		}
	}
	return ""
}
