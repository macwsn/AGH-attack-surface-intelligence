package exchange

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"asi/internal/inventory"
)

var CSVHeader = []string{
	"address", "hostnames", "status", "port", "protocol", "service", "product", "version",
	"scheme", "status_code", "title", "technologies", "findings", "tags", "first_seen", "last_seen",
}

func WriteCSV(w io.Writer, exp inventory.Export) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVHeader); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}
	for _, h := range exp.Hosts {
		base := []string{h.Address, strings.Join(h.Hostnames, ";"), string(h.Status)}
		tags := strings.Join(h.Tags, ";")
		if len(h.Services) == 0 {
			row := append(append([]string{}, base...), "", "", "", "", "", "", "", "", "", "", tags, formatTime(h.FirstSeen), formatTime(h.LastSeen))
			if err := cw.Write(NeutralizeRow(row)); err != nil {
				return fmt.Errorf("write csv row for %s: %w", h.Address, err)
			}
			continue
		}
		for _, s := range h.Services {
			var scheme, code, title string
			if s.HTTP != nil {
				scheme, title = s.HTTP.Scheme, s.HTTP.Title
				if s.HTTP.StatusCode != 0 {
					code = strconv.Itoa(s.HTTP.StatusCode)
				}
			}
			techs := make([]string, 0, len(s.Technologies))
			for _, t := range s.Technologies {
				if t.Version != "" {
					techs = append(techs, t.Name+":"+t.Version)
				} else {
					techs = append(techs, t.Name)
				}
			}
			finds := make([]string, 0, len(s.Findings))
			for _, f := range s.Findings {
				finds = append(finds, f.SignatureID)
			}
			row := append(append([]string{}, base...),
				strconv.Itoa(s.Port), s.Protocol, s.Service, s.Product, s.Version,
				scheme, code, title, strings.Join(techs, ";"), strings.Join(finds, ";"), tags,
				formatTime(s.FirstSeen), formatTime(s.LastSeen))
			if err := cw.Write(NeutralizeRow(row)); err != nil {
				return fmt.Errorf("write csv row for %s:%d: %w", h.Address, s.Port, err)
			}
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flush csv: %w", err)
	}
	return nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func NeutralizeRow(row []string) []string {
	for i, c := range row {
		row[i] = neutralize(c)
	}
	return row
}
