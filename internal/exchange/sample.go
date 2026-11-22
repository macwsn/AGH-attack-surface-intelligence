package exchange

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"asi/internal/inventory"
	"asi/internal/probe"
)

type CSVColumn struct {
	Name    string
	Meaning string
}

var CSVColumns = []CSVColumn{
	{"address", "Required. IPv4 or IPv6 address of the host; rows with the same address form one host."},
	{"hostnames", "Host names separated by semicolons."},
	{"status", "active, unstable or inactive; rows that are not active only add hosts or services that are new."},
	{"port", "Service port 1-65535; leave empty for a row that only lists the host."},
	{"protocol", "tcp or udp; empty means tcp."},
	{"service", "Service name, such as http or ssh."},
	{"product", "Product behind the port, such as nginx."},
	{"version", "Version of the product."},
	{"scheme", "http or https for a web service."},
	{"status_code", "HTTP status code of the response for /."},
	{"title", "HTML title of the response for /."},
	{"technologies", "Technologies separated by semicolons, each name or name:version."},
	{"findings", "Signature ids separated by semicolons."},
	{"tags", "Tags of the host separated by semicolons."},
	{"notes", "Notes on the host."},
	{"first_seen", "Written by the export; ignored on import."},
	{"last_seen", "Written by the export; ignored on import."},
}

func knownColumn(name string) bool {
	for _, c := range CSVColumns {
		if c.Name == name {
			return true
		}
	}
	return false
}

func WriteJSON(w io.Writer, exp inventory.Export) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(exp); err != nil {
		return fmt.Errorf("write json export: %w", err)
	}
	return nil
}

var sampleTime = time.Date(2026, 1, 5, 9, 30, 0, 0, time.UTC)

func SampleExport() inventory.Export {
	svc := func(port int, service, product, version string, h *probe.HTTP) inventory.ExportService {
		return inventory.ExportService{Port: port, Protocol: "tcp", State: "open", Status: inventory.StatusActive, Service: service,
			Product: product, Version: version, FirstSeen: sampleTime, LastSeen: sampleTime, Stability: 1, HTTP: h,
			Technologies: []inventory.Technology{}, Findings: []inventory.Finding{}}
	}
	host := func(addr string, names, tags []string, notes string, services ...inventory.ExportService) inventory.ExportHost {
		if services == nil {
			services = []inventory.ExportService{}
		}
		return inventory.ExportHost{Address: addr, Hostnames: names, Status: inventory.StatusActive, FirstSeen: sampleTime,
			LastSeen: sampleTime, Stability: 1, Tags: tags, Notes: notes, Services: services}
	}
	web := svc(443, "https", "nginx", "1.24.0", &probe.HTTP{Scheme: "https", StatusCode: 200, Title: "Example intranet"})
	web.Technologies = []inventory.Technology{{Name: "nginx", Version: "1.24.0", Source: SourceImported}}
	return inventory.Export{Schema: inventory.ExportSchema, GeneratedAt: sampleTime, Run: "sample", Hosts: []inventory.ExportHost{
		host("192.0.2.10", []string{"intranet.example.org"}, []string{"web", "dmz"}, "Replace these rows with your hosts.",
			svc(80, "http", "nginx", "1.24.0", &probe.HTTP{Scheme: "http", StatusCode: 301, Title: "Moved"}), web),
		host("192.0.2.11", []string{}, []string{"ssh"}, "", svc(22, "ssh", "OpenSSH", "9.6", nil)),
		host("192.0.2.12", []string{"printer.example.org"}, []string{}, "A host without known services."),
	}}
}

func Sample(format string) ([]byte, error) {
	var buf bytes.Buffer
	var err error
	switch format {
	case "csv":
		err = WriteCSV(&buf, SampleExport())
	case "json":
		err = WriteJSON(&buf, SampleExport())
	default:
		return nil, fmt.Errorf("sample: unknown format %q", format)
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
