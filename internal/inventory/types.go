package inventory

import (
	"time"

	"asi/internal/probe"
)

type Status string

const (
	StatusActive   Status = "active"
	StatusUnstable Status = "unstable"
	StatusInactive Status = "inactive"
)

type RunStatus string

const (
	RunRunning   RunStatus = "running"
	RunPaused    RunStatus = "paused"
	RunCompleted RunStatus = "completed"
	RunFailed    RunStatus = "failed"
)

type RunSettings struct {
	Targets       []string `json:"targets"`
	Excludes      []string `json:"excludes"`
	Ports         []int    `json:"ports"`
	SignaturesDir string   `json:"signatures_dir,omitempty"`
	MaxRate       int      `json:"max_rate"`
	Workers       int      `json:"workers"`
	GroupSize     int      `json:"group_size,omitempty"`
}

type RunSpec struct {
	Name          string
	InactiveAfter int
	Settings      RunSettings
}

type Run struct {
	ID            int64
	Name          string
	InactiveAfter int
	StartedAt     time.Time
	FinishedAt    *time.Time
	Status        RunStatus
	Settings      RunSettings
	AddressTotal  int
}

type GroupResult struct {
	Index     int
	Addresses []string
	Hosts     []HostResult
	Duration  time.Duration
}

type GroupInfo struct {
	Index        int
	Addresses    []string
	AddressCount int
	HostsFound   int
	Duration     time.Duration
	CompletedAt  time.Time
}

type FailedGroup struct {
	Index     int
	Addresses []string
	Reason    string
	FailedAt  time.Time
}

type HostResult struct {
	Address   string
	Hostnames []string
	Services  []ServiceResult
}

type ServiceResult struct {
	Port         int
	Protocol     string
	State        string
	Service      string
	Product      string
	Version      string
	HTTP         *probe.HTTP
	Technologies []Technology
	Findings     []Finding
}

type Technology struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Version    string `json:"version"`
	Confidence int    `json:"confidence"`
	Source     string `json:"source"`
}

type Finding struct {
	SignatureID string `json:"signature_id"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Confidence  int    `json:"confidence"`
	Evidence    string `json:"evidence"`
}

type HostUserFields struct {
	Tags           []string
	Notes          string
	DisplayName    string
	Owner          string
	Criticality    string
	StatusOverride string
}

type Export struct {
	Schema      string       `json:"schema"`
	GeneratedAt time.Time    `json:"generated_at"`
	Run         string       `json:"run"`
	Hosts       []ExportHost `json:"hosts"`
}

type ExportHost struct {
	Address        string          `json:"address"`
	Hostnames      []string        `json:"hostnames"`
	Status         Status          `json:"status"`
	FirstSeen      time.Time       `json:"first_seen"`
	LastSeen       time.Time       `json:"last_seen"`
	MissedRuns     int             `json:"missed_runs"`
	Stability      float64         `json:"stability"`
	InterestScore  int             `json:"interest_score"`
	Tags           []string        `json:"tags"`
	Notes          string          `json:"notes"`
	DisplayName    string          `json:"display_name,omitempty"`
	Owner          string          `json:"owner,omitempty"`
	Criticality    string          `json:"criticality,omitempty"`
	StatusOverride string          `json:"status_override,omitempty"`
	Services       []ExportService `json:"services"`
}

type ExportService struct {
	Port         int          `json:"port"`
	Protocol     string       `json:"protocol"`
	State        string       `json:"state"`
	Status       Status       `json:"status"`
	Service      string       `json:"service"`
	Product      string       `json:"product"`
	Version      string       `json:"version"`
	FirstSeen    time.Time    `json:"first_seen"`
	LastSeen     time.Time    `json:"last_seen"`
	MissedRuns   int          `json:"missed_runs"`
	Stability    float64      `json:"stability"`
	HTTP         *probe.HTTP  `json:"http"`
	Technologies []Technology `json:"technologies"`
	Findings     []Finding    `json:"findings"`
}
