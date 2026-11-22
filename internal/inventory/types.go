package inventory

import (
	"time"

	"asi/internal/detect"
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

	StalledLabel = "stalled (process gone)"
)

const (
	ModeFull    = "full"
	ModeRecheck = "recheck"
)

type RunSource string

const (
	SourceScan   RunSource = "scan"
	SourceImport RunSource = "import"
	SourceManual RunSource = "manual"
)

type RunSettings struct {
	Targets          []string `json:"targets"`
	Excludes         []string `json:"excludes"`
	Ports            []int    `json:"ports"`
	SignaturesDir    string   `json:"signatures_dir,omitempty"`
	MaxRate          int      `json:"max_rate"`
	Workers          int      `json:"workers"`
	GroupSize        int      `json:"group_size,omitempty"`
	Mode             string   `json:"mode,omitempty"`
	Hosts            []string `json:"hosts,omitempty"`
	HTTPTimeoutMS    int      `json:"http_timeout_ms,omitempty"`
	NoAdaptive       bool     `json:"no_adaptive,omitempty"`
	ServiceDetection string   `json:"service_detection,omitempty"`
	MaxWork          uint64   `json:"max_work,omitempty"`
	VolatileHeaders  []string `json:"volatile_headers,omitempty"`
}

func (s RunSettings) RunMode() string {
	if s.Mode == "" {
		return ModeFull
	}
	return s.Mode
}

func (s RunSettings) Recheck() bool {
	return s.RunMode() == ModeRecheck
}

func ValidMode(m string) bool {
	return m == "" || m == ModeFull || m == ModeRecheck
}

type RunSpec struct {
	Name          string
	InactiveAfter int
	Settings      RunSettings
	Source        RunSource
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
	Packets       int
	InFlight      int
	Source        RunSource
	DefinitionID  int64
	Stalled       bool
}

type GroupResult struct {
	Index        int
	Addresses    []string
	Hosts        []HostResult
	Duration     time.Duration
	CoveredPorts map[string][]int
}

type KnownService struct {
	Address  string
	Port     int
	Protocol string
	Service  string
	HTTP     bool
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

type RateSample struct {
	Minute     time.Time
	Configured int
	Effective  int
	Sent       int
	Packets    int
}

func (s RateSample) PerSecond() float64 { return float64(s.Sent) / 60 }

func (s RateSample) PacketsPerSecond() float64 { return float64(s.Packets) / 60 }

type HostResult struct {
	Address   string
	Hostnames []string
	Services  []ServiceResult
	Notes     []string
}

type ServiceResult struct {
	Port         int
	Protocol     string
	State        string
	Service      string
	Product      string
	Version      string
	HTTP         *probe.HTTP
	Body         []byte
	Technologies []Technology
	Findings     []Finding
}

func (s *ServiceResult) Detect(set *detect.Set, stored *probe.HTTP, stated bool) {
	in := detect.Service{Service: s.Service, Product: s.Product, Version: s.Version, HTTP: stored, Stated: stated}
	for _, t := range s.Technologies {
		in.Technologies = append(in.Technologies, detect.Technology(t))
	}
	for _, f := range s.Findings {
		in.Findings = append(in.Findings, detect.Finding(f))
	}
	res := set.DetectService(in)
	s.Technologies, s.Findings = nil, nil
	for _, t := range res.Technologies {
		s.Technologies = append(s.Technologies, Technology(t))
	}
	for _, f := range res.Findings {
		s.Findings = append(s.Findings, Finding(f))
	}
}

type Technology struct {
	Name          string `json:"name"`
	Category      string `json:"category"`
	Version       string `json:"version"`
	Confidence    int    `json:"confidence"`
	ConfidenceRaw *int   `json:"confidence_raw,omitempty"`
	Source        string `json:"source"`
}

type Finding struct {
	SignatureID string `json:"signature_id"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Confidence  int    `json:"confidence"`
	Evidence    string `json:"evidence"`
	Source      string `json:"source,omitempty"`
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
	Schema          string       `json:"schema"`
	GeneratedAt     time.Time    `json:"generated_at"`
	Run             string       `json:"run"`
	Hosts           []ExportHost `json:"hosts"`
	VolatileHeaders []string     `json:"-"`
	Source          RunSource    `json:"-"`
	RunStartedAt    time.Time    `json:"-"`
}

type ExportHost struct {
	Address        string              `json:"address"`
	Hostnames      []string            `json:"hostnames"`
	Status         Status              `json:"status"`
	FirstSeen      time.Time           `json:"first_seen"`
	LastSeen       time.Time           `json:"last_seen"`
	MissedRuns     int                 `json:"missed_runs"`
	Stability      float64             `json:"stability"`
	InterestScore  int                 `json:"interest_score"`
	Tags           []string            `json:"tags"`
	Notes          string              `json:"notes"`
	DisplayName    string              `json:"display_name,omitempty"`
	Owner          string              `json:"owner,omitempty"`
	Criticality    string              `json:"criticality,omitempty"`
	StatusOverride string              `json:"status_override,omitempty"`
	Services       []ExportService     `json:"services"`
	Availability   *ExportAvailability `json:"availability,omitempty"`
	LastCovered    time.Time           `json:"-"`
	ScanCovered    bool                `json:"-"`
	NotInRun       bool                `json:"-"`
}

type ExportAvailability struct {
	Hours      []float64 `json:"hours"`
	Samples    int       `json:"samples"`
	Periodic   bool      `json:"periodic"`
	UsualHours []int     `json:"usual_hours"`
	Expected   string    `json:"expected,omitempty"`
}

type ExportService struct {
	Port         int             `json:"port"`
	Protocol     string          `json:"protocol"`
	State        string          `json:"state"`
	Status       Status          `json:"status"`
	Service      string          `json:"service"`
	Product      string          `json:"product"`
	Version      string          `json:"version"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
	MissedRuns   int             `json:"missed_runs"`
	Stability    float64         `json:"stability"`
	HTTP         *probe.HTTP     `json:"http"`
	Technologies []Technology    `json:"technologies"`
	Findings     []Finding       `json:"findings"`
	Volatile     []VolatileField `json:"volatile,omitempty"`
	NotInRun     bool            `json:"-"`
}
