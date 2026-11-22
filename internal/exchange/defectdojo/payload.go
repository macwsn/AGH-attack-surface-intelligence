package defectdojo

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"asi/internal/detect"
	"asi/internal/inventory"
)

var findingKinds = map[string]string{
	"admin-panel":        "Admin panel",
	"staging":            "Staging",
	"iot":                "IoT device",
	"interesting-header": "Notable header",
	"interesting-cookie": "Notable cookie",
	"custom":             "Custom finding",
	"outdated":           "Outdated version",
}

const serviceVulnID = "open-service"

type nmapRun struct {
	XMLName          xml.Name   `xml:"nmaprun"`
	Scanner          string     `xml:"scanner,attr"`
	Args             string     `xml:"args,attr"`
	Start            int64      `xml:"start,attr"`
	XMLOutputVersion string     `xml:"xmloutputversion,attr"`
	Hosts            []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapState      `xml:"status"`
	Address   nmapAddress    `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname"`
	Ports     []nmapPort     `xml:"ports>port"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	ID       int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr,omitempty"`
	Version string `xml:"version,attr,omitempty"`
	Tunnel  string `xml:"tunnel,attr,omitempty"`
}

func observed(h inventory.ExportHost) []inventory.ExportService {
	var out []inventory.ExportService
	for _, s := range h.Services {
		if s.Status == inventory.StatusActive && s.State == "open" {
			out = append(out, s)
		}
	}
	return out
}

func NmapXML(exp inventory.Export) ([]byte, int, error) {
	run := nmapRun{
		Scanner:          "nmap",
		Args:             "asi defectdojo export --run " + exp.Run,
		XMLOutputVersion: "1.05",
	}
	if !exp.GeneratedAt.IsZero() {
		run.Start = exp.GeneratedAt.Unix()
	}
	services := 0
	for _, h := range exp.Hosts {
		if h.Status != inventory.StatusActive {
			continue
		}
		addrType := "ipv4"
		if a, err := netip.ParseAddr(h.Address); err == nil && a.Is6() {
			addrType = "ipv6"
		}
		xh := nmapHost{Status: nmapState{State: "up"}, Address: nmapAddress{Addr: h.Address, Type: addrType}}
		for _, n := range h.Hostnames {
			xh.Hostnames = append(xh.Hostnames, nmapHostname{Name: n, Type: "user"})
		}
		for _, s := range observed(h) {
			p := nmapPort{Protocol: s.Protocol, ID: s.Port, State: nmapState{State: "open"},
				Service: nmapService{Name: s.Service, Product: s.Product, Version: s.Version}}
			if s.HTTP != nil && s.HTTP.Scheme == "https" {
				p.Service.Tunnel = "ssl"
			}
			xh.Ports = append(xh.Ports, p)
			services++
		}
		run.Hosts = append(run.Hosts, xh)
	}
	body, err := xml.MarshalIndent(run, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("encode nmap xml: %w", err)
	}
	return append([]byte(xml.Header), append(body, '\n')...), services, nil
}

type genericReport struct {
	Findings []genericFinding `json:"findings"`
}

type genericFinding struct {
	Title            string            `json:"title"`
	Severity         string            `json:"severity"`
	Description      string            `json:"description"`
	Impact           string            `json:"impact"`
	Date             string            `json:"date"`
	UniqueIDFromTool string            `json:"unique_id_from_tool"`
	VulnIDFromTool   string            `json:"vuln_id_from_tool"`
	StaticFinding    bool              `json:"static_finding"`
	DynamicFinding   bool              `json:"dynamic_finding"`
	Endpoints        []genericEndpoint `json:"endpoints"`
}

type genericEndpoint struct {
	Protocol string `json:"protocol,omitempty"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

func UniqueID(address, protocol string, port int, signatureID string) string {
	return "asi:" + address + ":" + protocol + "/" + strconv.Itoa(port) + ":" + signatureID
}

func GenericFindings(exp inventory.Export) ([]byte, int, error) {
	report := genericReport{Findings: []genericFinding{}}
	var services []genericFinding
	for _, h := range exp.Hosts {
		if h.Status != inventory.StatusActive {
			continue
		}
		for _, s := range observed(h) {
			for _, f := range uniqueFindings(s.Findings) {
				label, ok := findingKinds[f.Kind]
				if !ok {
					continue
				}
				report.Findings = append(report.Findings, finding(h, s, f, label))
			}
			services = append(services, serviceFinding(h, s))
		}
	}
	signatures := len(report.Findings)
	report.Findings = append(report.Findings, services...)
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("encode generic findings: %w", err)
	}
	return append(body, '\n'), signatures, nil
}

func uniqueFindings(in []inventory.Finding) []inventory.Finding {
	findings := make([]detect.Finding, 0, len(in))
	for _, f := range in {
		findings = append(findings, detect.Finding(f))
	}
	out := make([]inventory.Finding, 0, len(in))
	for _, f := range detect.MergeFindings(findings) {
		out = append(out, inventory.Finding(f))
	}
	return out
}

func location(h inventory.ExportHost, s inventory.ExportService) (hostPort, where string, ep genericEndpoint) {
	hostPort = h.Address + ":" + strconv.Itoa(s.Port)
	if strings.Contains(h.Address, ":") {
		hostPort = "[" + h.Address + "]:" + strconv.Itoa(s.Port)
	}
	ep = genericEndpoint{Host: h.Address, Port: s.Port}
	where = hostPort + "/" + s.Protocol
	if s.HTTP != nil && s.HTTP.Scheme != "" {
		ep.Protocol = s.HTTP.Scheme
		where = s.HTTP.Scheme + "://" + hostPort + "/"
	}
	return hostPort, where, ep
}

func serviceFinding(h inventory.ExportHost, s inventory.ExportService) genericFinding {
	hostPort, where, ep := location(h, s)
	what := strings.TrimSpace(s.Product + " " + s.Version)
	if what == "" {
		what = s.Service
	}
	title := "Open service: " + hostPort
	if what != "" {
		title += " " + what
	}
	desc := fmt.Sprintf("Open port %d/%s found by ASI on %s.", s.Port, s.Protocol, where)
	if len(h.Hostnames) > 0 {
		desc += "\n\nHostnames: " + strings.Join(h.Hostnames, ", ") + "."
	}
	for _, kv := range [][2]string{{"Service", s.Service}, {"Product", s.Product}, {"Version", s.Version}} {
		if kv[1] != "" {
			desc += "\n\n" + kv[0] + ": " + kv[1] + "."
		}
	}
	return genericFinding{
		Title:            title,
		Severity:         "Info",
		Description:      desc,
		Impact:           "An open service is part of the attack surface.",
		Date:             s.LastSeen.UTC().Format("2006-01-02"),
		UniqueIDFromTool: "asi:" + h.Address + ":" + s.Protocol + "/" + strconv.Itoa(s.Port),
		VulnIDFromTool:   serviceVulnID,
		DynamicFinding:   true,
		Endpoints:        []genericEndpoint{ep},
	}
}

func finding(h inventory.ExportHost, s inventory.ExportService, f inventory.Finding, label string) genericFinding {
	hostPort, where, ep := location(h, s)
	name := f.Name
	if name == "" {
		name = f.SignatureID
	}
	desc := fmt.Sprintf("%s found by ASI on %s.\n\nSignature: %s (kind %s).", label, where, f.SignatureID, f.Kind)
	impact := fmt.Sprintf("Confidence %d/100.", f.Confidence)
	if f.Version != "" {
		impact += " Version " + f.Version + "."
	}
	severity := "Info"
	if f.Kind == "outdated" {
		severity = "Low"
		if f.Version != "" {
			desc += "\n\nDetected version: " + f.Version + "."
		}
	}
	if f.Evidence != "" {
		desc += "\n\nEvidence: " + f.Evidence
	}
	return genericFinding{
		Title:            fmt.Sprintf("%s: %s on %s/%s", label, name, hostPort, s.Protocol),
		Severity:         severity,
		Description:      desc,
		Impact:           impact,
		Date:             s.LastSeen.UTC().Format("2006-01-02"),
		UniqueIDFromTool: UniqueID(h.Address, s.Protocol, s.Port, f.SignatureID),
		VulnIDFromTool:   f.SignatureID,
		DynamicFinding:   true,
		Endpoints:        []genericEndpoint{ep},
	}
}
