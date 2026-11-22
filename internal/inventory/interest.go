package inventory

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"asi/internal/detect"
)

const (
	ReasonAdminPanel        = "admin-panel"
	ReasonStaging           = "staging"
	ReasonIoT               = "iot"
	ReasonInterestingHeader = "interesting-header"
	ReasonInterestingCookie = "interesting-cookie"
	ReasonNew               = "new"
	ReasonRecent            = "recent"
	ReasonSelfSigned        = "self-signed"
	ReasonExpiringCert      = "expiring-cert"
	ReasonOutdated          = "outdated"

	RecentWindow       = 7 * 24 * time.Hour
	CertExpiringWindow = 30 * 24 * time.Hour
	MaxInterestScore   = 100
)

type InterestWeights map[string]int

var DefaultInterestWeights = InterestWeights{
	ReasonAdminPanel:        30,
	ReasonStaging:           20,
	ReasonIoT:               25,
	ReasonInterestingHeader: 10,
	ReasonInterestingCookie: 10,
	ReasonNew:               20,
	ReasonRecent:            10,
	ReasonSelfSigned:        10,
	ReasonExpiringCert:      10,
	ReasonOutdated:          15,
}

var reasonOrder = []string{
	ReasonAdminPanel, ReasonStaging, ReasonIoT, ReasonInterestingHeader, ReasonInterestingCookie,
	ReasonNew, ReasonRecent, ReasonSelfSigned, ReasonExpiringCert, ReasonOutdated,
}

var reasonLabels = map[string]string{
	ReasonAdminPanel:        "Admin panel",
	ReasonStaging:           "Staging environment",
	ReasonIoT:               "IoT device",
	ReasonInterestingHeader: "Notable header",
	ReasonInterestingCookie: "Notable cookie",
	ReasonNew:               "First seen in this run",
	ReasonRecent:            "First seen in the last 7 days",
	ReasonSelfSigned:        "Self-signed certificate",
	ReasonExpiringCert:      "Certificate expires within 30 days or has expired",
	ReasonOutdated:          "Outdated version",
}

type Reason struct {
	Code   string `json:"code"`
	Label  string `json:"label"`
	Points int    `json:"points"`
}

func ParseInterestWeights(spec string) (InterestWeights, error) {
	w := InterestWeights{}
	for k, v := range DefaultInterestWeights {
		w[k] = v
	}
	if strings.TrimSpace(spec) == "" {
		return w, nil
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		key, value, ok := strings.Cut(part, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("%q is not key=points", part)
		}
		if _, known := DefaultInterestWeights[key]; !known {
			return nil, fmt.Errorf("unknown key %q (known: %s)", key, strings.Join(reasonOrder, ", "))
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n < 0 || n > MaxInterestScore {
			return nil, fmt.Errorf("%s: %q is not a number from 0 to %d", key, value, MaxInterestScore)
		}
		w[key] = n
	}
	return w, nil
}

func Score(h ExportHost, at time.Time, weights InterestWeights) (int, []Reason) {
	if weights == nil {
		weights = DefaultInterestWeights
	}
	hit := map[string][]string{}
	add := func(code, where string) {
		if !slices.Contains(hit[code], where) {
			hit[code] = append(hit[code], where)
		}
	}
	switch {
	case !h.FirstSeen.IsZero() && !at.IsZero() && !h.FirstSeen.Before(at):
		add(ReasonNew, "")
	case !h.FirstSeen.IsZero() && !at.IsZero() && at.Sub(h.FirstSeen) <= RecentWindow:
		add(ReasonRecent, "")
	}
	for _, s := range h.Services {
		if s.Status == StatusInactive {
			continue
		}
		where := fmt.Sprintf("%d/%s", s.Port, s.Protocol)
		for _, f := range s.Findings {
			if _, ok := reasonLabels[f.Kind]; ok && f.Kind != ReasonNew && f.Kind != ReasonRecent {
				add(f.Kind, where)
			}
		}
		if s.HTTP != nil && s.HTTP.TLS != nil {
			if s.HTTP.TLS.SelfSigned {
				add(ReasonSelfSigned, where)
			}
			if exp, err := time.Parse(time.RFC3339, s.HTTP.TLS.NotAfter); err == nil && exp.Sub(at) <= CertExpiringWindow {
				add(ReasonExpiringCert, where)
			}
		}
		if detect.IsOutdated(s.Product, s.Version) {
			add(ReasonOutdated, where)
		}
		for _, t := range s.Technologies {
			if detect.IsOutdated(t.Name, t.Version) {
				add(ReasonOutdated, where)
			}
		}
	}
	total := 0
	reasons := []Reason{}
	for _, code := range reasonOrder {
		where, ok := hit[code]
		if !ok || weights[code] <= 0 {
			continue
		}
		label := reasonLabels[code]
		if places := slices.DeleteFunc(slices.Clone(where), func(p string) bool { return p == "" }); len(places) > 0 {
			label += " on " + strings.Join(places, ", ")
		}
		reasons = append(reasons, Reason{Code: code, Label: label, Points: weights[code]})
		total += weights[code]
	}
	if total > MaxInterestScore {
		total = MaxInterestScore
	}
	return total, reasons
}
