package handlers

import (
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Agent is an XDR endpoint agent record for the demo store.
type Agent struct {
	ID       string    `json:"id"`
	Hostname string    `json:"hostname"`
	OS       string    `json:"os"`
	Version  string    `json:"version"`
	Status   string    `json:"status"`
	LastSeen time.Time `json:"last_seen"`
}

// Playbook is a SOAR playbook summary for the demo store.
type Playbook struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	Tags        []string `json:"tags"`
	Status      string   `json:"status,omitempty"`
}

// DemoStore is an in-memory store for local demos (not for production).
type DemoStore struct {
	mu        sync.RWMutex
	alerts    map[string]Alert
	events    map[string]Event
	cases     map[string]Case
	rules     map[string]Rule
	agents    map[string]Agent
	playbooks map[string]Playbook
}

var store = newDemoStore()

func newDemoStore() *DemoStore {
	s := &DemoStore{
		alerts:    make(map[string]Alert),
		events:    make(map[string]Event),
		cases:     make(map[string]Case),
		rules:     make(map[string]Rule),
		agents:    make(map[string]Agent),
		playbooks: make(map[string]Playbook),
	}
	now := time.Now().UTC()
	s.seedAlerts(now)
	s.seedEvents(now)
	s.seedCases(now)
	s.seedRules(now)
	s.seedAgents(now)
	s.seedPlaybooks()
	return s
}

func (s *DemoStore) seedAlerts(now time.Time) {
	seeds := []Alert{
		{
			ID: "alt-ssh-001", RuleID: "ssh-brute-force", RuleName: "SSH Brute Force Attack",
			Description: "Multiple failed SSH logins from a single source IP",
			Severity: "high", SeverityScore: 80, Status: "open",
			MitreTactic: "Credential Access", MitreTechnique: "T1110",
			SourceIP: "203.0.113.45", DestinationIP: "10.0.1.22", HostName: "bastion-01", UserName: "root",
			MatchCount: 42, Timestamp: now.Add(-12 * time.Minute), FirstSeen: now.Add(-25 * time.Minute), LastSeen: now.Add(-2 * time.Minute),
			Tags: []string{"ssh", "bruteforce", "sigma"},
		},
		{
			ID: "alt-scan-002", RuleID: "port-scan", RuleName: "Port Scan Detected",
			Description: "Sequential connection attempts across many destination ports",
			Severity: "medium", SeverityScore: 55, Status: "open",
			MitreTactic: "Discovery", MitreTechnique: "T1046",
			SourceIP: "198.51.100.10", DestinationIP: "10.0.2.15", HostName: "fw-edge-01",
			MatchCount: 128, Timestamp: now.Add(-45 * time.Minute), FirstSeen: now.Add(-50 * time.Minute), LastSeen: now.Add(-40 * time.Minute),
			Tags: []string{"network", "recon"},
		},
		{
			ID: "alt-ps-003", RuleID: "powershell-encoded", RuleName: "Encoded PowerShell Command",
			Description: "Suspicious encoded PowerShell invocation on an endpoint",
			Severity: "critical", SeverityScore: 95, Status: "acknowledged",
			MitreTactic: "Execution", MitreTechnique: "T1059.001",
			SourceIP: "10.0.3.88", HostName: "ws-finance-14", UserName: "jdoe", ProcessName: "powershell.exe",
			MatchCount: 1, Timestamp: now.Add(-2 * time.Hour), FirstSeen: now.Add(-2 * time.Hour), LastSeen: now.Add(-2 * time.Hour),
			AssignedTo: "analyst", Tags: []string{"endpoint", "powershell", "malware"},
		},
		{
			ID: "alt-dns-004", RuleID: "dns-exfiltration", RuleName: "Suspicious DNS Tunneling",
			Description: "High-entropy DNS queries consistent with tunneling",
			Severity: "high", SeverityScore: 78, Status: "open",
			MitreTactic: "Exfiltration", MitreTechnique: "T1048",
			SourceIP: "10.0.5.21", HostName: "dev-laptop-09", UserName: "asmith",
			MatchCount: 64, Timestamp: now.Add(-8 * time.Minute), FirstSeen: now.Add(-20 * time.Minute), LastSeen: now.Add(-1 * time.Minute),
			Tags: []string{"dns", "exfil"},
		},
		{
			ID: "alt-rdp-005", RuleID: "lateral-movement-rdp", RuleName: "Lateral Movement via RDP",
			Description: "Unusual RDP authentication to domain controller",
			Severity: "medium", SeverityScore: 60, Status: "open",
			MitreTactic: "Lateral Movement", MitreTechnique: "T1021.001",
			SourceIP: "10.0.2.15", DestinationIP: "10.0.1.10", HostName: "dc-01", UserName: "svc_backup",
			MatchCount: 3, Timestamp: now.Add(-33 * time.Minute), FirstSeen: now.Add(-40 * time.Minute), LastSeen: now.Add(-30 * time.Minute),
			Tags: []string{"rdp", "lateral"},
		},
	}
	for _, a := range seeds {
		s.alerts[a.ID] = a
	}
}

func (s *DemoStore) seedEvents(now time.Time) {
	samples := []Event{
		{ID: "evt-1000", Timestamp: now.Add(-3 * time.Minute), SourceType: "syslog", Category: "authentication", Action: "ssh_login_failed", Severity: "high", SeverityScore: 70, SourceIP: "203.0.113.45", SourcePort: 51234, DestinationIP: "10.0.1.22", DestinationPort: 22, HostName: "bastion-01", UserName: "root", NetworkTransport: "tcp"},
		{ID: "evt-1001", Timestamp: now.Add(-6 * time.Minute), SourceType: "network", Category: "network", Action: "port_scan", Severity: "medium", SeverityScore: 50, SourceIP: "198.51.100.10", DestinationIP: "10.0.2.15", HostName: "fw-edge-01", NetworkTransport: "tcp"},
		{ID: "evt-1002", Timestamp: now.Add(-9 * time.Minute), SourceType: "endpoint", Category: "process", Action: "powershell_encoded", Severity: "critical", SeverityScore: 90, SourceIP: "10.0.3.88", HostName: "ws-finance-14", UserName: "jdoe", ProcessName: "powershell.exe"},
		{ID: "evt-1003", Timestamp: now.Add(-12 * time.Minute), SourceType: "endpoint", Category: "dns", Action: "suspicious_query", Severity: "high", SeverityScore: 75, SourceIP: "10.0.5.21", HostName: "dev-laptop-09", UserName: "asmith"},
		{ID: "evt-1004", Timestamp: now.Add(-15 * time.Minute), SourceType: "winlog", Category: "authentication", Action: "rdp_login", Severity: "medium", SeverityScore: 55, SourceIP: "10.0.2.15", DestinationIP: "10.0.1.10", DestinationPort: 3389, HostName: "dc-01", UserName: "svc_backup"},
		{ID: "evt-1005", Timestamp: now.Add(-18 * time.Minute), SourceType: "endpoint", Category: "file", Action: "sensitive_file_access", Severity: "low", SeverityScore: 30, SourceIP: "10.0.8.44", HostName: "fileserver-02", UserName: "backup"},
		{ID: "evt-1006", Timestamp: now.Add(-21 * time.Minute), SourceType: "network", Category: "network", Action: "egress_spike", Severity: "medium", SeverityScore: 45, SourceIP: "10.0.5.21", DestinationIP: "93.184.216.34", HostName: "proxy-01", NetworkBytes: 85000000},
		{ID: "evt-1007", Timestamp: now.Add(-24 * time.Minute), SourceType: "endpoint", Category: "process", Action: "rare_binary", Severity: "high", SeverityScore: 72, SourceIP: "10.0.9.3", HostName: "build-agent-2", ProcessName: "runner.tmp"},
	}
	for _, e := range samples {
		s.events[e.ID] = e
	}
}

func (s *DemoStore) seedCases(now time.Time) {
	seeds := []Case{
		{ID: "CASE-1042", Title: "Suspected credential stuffing on bastion", Description: "Correlated SSH failures and alert alt-ssh-001", Severity: "high", Status: "investigating", AssignedTo: "analyst", AlertIDs: []string{"alt-ssh-001"}, CreatedBy: "admin", CreatedAt: now.Add(-2 * time.Hour), UpdatedAt: now.Add(-18 * time.Minute), Tags: []string{"ssh", "bruteforce"}},
		{ID: "CASE-1041", Title: "Encoded PowerShell on finance workstation", Description: "Endpoint detection linked to alt-ps-003", Severity: "critical", Status: "open", AssignedTo: "admin", AlertIDs: []string{"alt-ps-003"}, CreatedBy: "admin", CreatedAt: now.Add(-3 * time.Hour), UpdatedAt: now.Add(-1 * time.Hour), Tags: []string{"endpoint", "malware"}},
		{ID: "CASE-1038", Title: "Outbound DNS anomaly cluster", Description: "Possible tunneling via alt-dns-004", Severity: "medium", Status: "contained", AssignedTo: "analyst", AlertIDs: []string{"alt-dns-004"}, CreatedBy: "analyst", CreatedAt: now.Add(-8 * time.Hour), UpdatedAt: now.Add(-5 * time.Hour), Tags: []string{"dns", "exfil"}},
	}
	for _, c := range seeds {
		s.cases[c.ID] = c
	}
}

func (s *DemoStore) seedRules(now time.Time) {
	seeds := []Rule{
		{ID: "ssh-brute-force", Name: "SSH Brute Force Attack", Description: "Failed SSH logins over threshold", Type: "sigma", Severity: "high", SeverityScore: 80, Status: "active", TimeWindowMs: 300000, Threshold: 10, AggregationField: "source.ip", MitreTactic: "Credential Access", MitreTechnique: "T1110", Tags: []string{"ssh"}, CreatedBy: "system", CreatedAt: now.Add(-720 * time.Hour).Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339)},
		{ID: "port-scan", Name: "Port Scan Detected", Description: "Many destination ports from one source", Type: "sigma", Severity: "medium", SeverityScore: 55, Status: "active", TimeWindowMs: 120000, Threshold: 50, AggregationField: "source.ip", MitreTactic: "Discovery", MitreTechnique: "T1046", Tags: []string{"network"}, CreatedBy: "system", CreatedAt: now.Add(-720 * time.Hour).Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339)},
		{ID: "powershell-encoded", Name: "Encoded PowerShell Command", Description: "Encoded command line on endpoints", Type: "sigma", Severity: "critical", SeverityScore: 95, Status: "active", TimeWindowMs: 60000, Threshold: 1, MitreTactic: "Execution", MitreTechnique: "T1059.001", Tags: []string{"endpoint"}, CreatedBy: "system", CreatedAt: now.Add(-720 * time.Hour).Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339)},
		{ID: "dns-exfiltration", Name: "Suspicious DNS Tunneling", Description: "High-entropy DNS queries", Type: "sigma", Severity: "high", SeverityScore: 78, Status: "active", TimeWindowMs: 600000, Threshold: 20, AggregationField: "source.ip", MitreTactic: "Exfiltration", MitreTechnique: "T1048", Tags: []string{"dns"}, CreatedBy: "system", CreatedAt: now.Add(-720 * time.Hour).Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339)},
		{ID: "lateral-movement-rdp", Name: "Lateral Movement via RDP", Description: "Unusual RDP to sensitive hosts", Type: "sigma", Severity: "medium", SeverityScore: 60, Status: "active", TimeWindowMs: 900000, Threshold: 3, MitreTactic: "Lateral Movement", MitreTechnique: "T1021.001", Tags: []string{"rdp"}, CreatedBy: "system", CreatedAt: now.Add(-720 * time.Hour).Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339)},
		{ID: "c2-beacon", Name: "C2 Beacon Pattern", Description: "Periodic outbound beacons", Type: "sigma", Severity: "critical", SeverityScore: 92, Status: "active", TimeWindowMs: 3600000, Threshold: 5, MitreTactic: "Command and Control", MitreTechnique: "T1071", Tags: []string{"c2"}, CreatedBy: "system", CreatedAt: now.Add(-720 * time.Hour).Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339)},
	}
	for _, r := range seeds {
		s.rules[r.ID] = r
	}
}

func (s *DemoStore) seedAgents(now time.Time) {
	seeds := []Agent{
		{ID: "ag-01", Hostname: "bastion-01", OS: "Linux", Version: "1.0.4", Status: "active", LastSeen: now.Add(-30 * time.Second)},
		{ID: "ag-02", Hostname: "ws-finance-14", OS: "Windows", Version: "1.0.4", Status: "active", LastSeen: now.Add(-45 * time.Second)},
		{ID: "ag-03", Hostname: "dc-01", OS: "Windows", Version: "1.0.3", Status: "active", LastSeen: now.Add(-20 * time.Second)},
		{ID: "ag-04", Hostname: "dev-laptop-09", OS: "macOS", Version: "1.0.4", Status: "active", LastSeen: now.Add(-90 * time.Second)},
		{ID: "ag-05", Hostname: "build-agent-2", OS: "Linux", Version: "1.0.2", Status: "isolated", LastSeen: now.Add(-2 * time.Minute)},
		{ID: "ag-06", Hostname: "fileserver-02", OS: "Linux", Version: "1.0.4", Status: "active", LastSeen: now.Add(-15 * time.Second)},
	}
	for _, a := range seeds {
		s.agents[a.ID] = a
	}
}

func (s *DemoStore) seedPlaybooks() {
	seeds := []Playbook{
		{ID: "isolate-compromised-host", Name: "Isolate Compromised Host", Description: "Block traffic, collect evidence, open ticket", Enabled: true, Tags: []string{"host-isolation", "forensics"}},
		{ID: "investigate-phishing", Name: "Investigate Phishing", Description: "Enrich indicators and notify SOC", Enabled: true, Tags: []string{"phishing", "email"}},
	}
	for _, p := range seeds {
		s.playbooks[p.ID] = p
	}
}

// --- Alerts ---

func (s *DemoStore) listAlerts() []Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Alert, 0, len(s.alerts))
	for _, a := range s.alerts {
		out = append(out, a)
	}
	return out
}

func (s *DemoStore) getAlert(id string) (Alert, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.alerts[id]
	return a, ok
}

func (s *DemoStore) createAlert(a Alert) Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.ID == "" {
		a.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	if a.Timestamp.IsZero() {
		a.Timestamp = now
	}
	if a.FirstSeen.IsZero() {
		a.FirstSeen = now
	}
	if a.LastSeen.IsZero() {
		a.LastSeen = now
	}
	if a.Status == "" {
		a.Status = "open"
	}
	s.alerts[a.ID] = a
	return a
}

func (s *DemoStore) updateAlert(id string, mut func(*Alert)) (Alert, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.alerts[id]
	if !ok {
		return Alert{}, false
	}
	mut(&a)
	s.alerts[id] = a
	return a, true
}

func (s *DemoStore) deleteAlert(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.alerts[id]; !ok {
		return false
	}
	delete(s.alerts, id)
	return true
}

// --- Events ---

func (s *DemoStore) listEvents() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Event, 0, len(s.events))
	for _, e := range s.events {
		out = append(out, e)
	}
	return out
}

func (s *DemoStore) getEvent(id string) (Event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.events[id]
	return e, ok
}

func (s *DemoStore) searchEvents(q string, category string, limit int) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	q = strings.ToLower(strings.TrimSpace(q))
	category = strings.ToLower(strings.TrimSpace(category))
	out := make([]Event, 0)
	for _, e := range s.events {
		if category != "" && category != "all" && strings.ToLower(e.Category) != category {
			continue
		}
		if q != "" {
			blob := strings.ToLower(e.ID + e.Action + e.Category + e.HostName + e.SourceIP + e.UserName + e.ProcessName)
			if !strings.Contains(blob, q) {
				continue
			}
		}
		out = append(out, e)
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *DemoStore) aggregateByField(field string) []map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counts := map[string]int{}
	for _, e := range s.events {
		key := "unknown"
		switch field {
		case "category":
			key = e.Category
		case "severity":
			key = e.Severity
		case "source_type":
			key = e.SourceType
		case "host_name":
			key = e.HostName
		default:
			key = e.Category
		}
		if key == "" {
			key = "unknown"
		}
		counts[key]++
	}
	buckets := make([]map[string]interface{}, 0, len(counts))
	for k, v := range counts {
		buckets = append(buckets, map[string]interface{}{"key": k, "count": v})
	}
	return buckets
}

// --- Cases ---

func (s *DemoStore) listCases() []Case {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Case, 0, len(s.cases))
	for _, c := range s.cases {
		out = append(out, c)
	}
	return out
}

func (s *DemoStore) getCase(id string) (Case, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.cases[id]
	return c, ok
}

func (s *DemoStore) createCase(c Case) Case {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.ID == "" {
		c.ID = "CASE-" + uuid.New().String()[:8]
	}
	now := time.Now().UTC()
	if c.Status == "" {
		c.Status = "open"
	}
	c.CreatedAt = now
	c.UpdatedAt = now
	s.cases[c.ID] = c
	return c
}

func (s *DemoStore) updateCase(id string, mut func(*Case)) (Case, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cases[id]
	if !ok {
		return Case{}, false
	}
	mut(&c)
	c.UpdatedAt = time.Now().UTC()
	s.cases[id] = c
	return c, true
}

// --- Rules ---

func (s *DemoStore) listRules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Rule, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, r)
	}
	return out
}

func (s *DemoStore) getRule(id string) (Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[id]
	return r, ok
}

// --- Agents ---

func (s *DemoStore) listAgents() []Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Agent, 0, len(s.agents))
	for _, a := range s.agents {
		out = append(out, a)
	}
	return out
}

func (s *DemoStore) getAgent(id string) (Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	return a, ok
}

func (s *DemoStore) setAgentStatus(id, status string) (Agent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return Agent{}, false
	}
	a.Status = status
	a.LastSeen = time.Now().UTC()
	s.agents[id] = a
	return a, true
}

// --- Playbooks ---

func (s *DemoStore) listPlaybooks() []Playbook {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Playbook, 0, len(s.playbooks))
	for _, p := range s.playbooks {
		out = append(out, p)
	}
	return out
}

func (s *DemoStore) getPlaybook(id string) (Playbook, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.playbooks[id]
	return p, ok
}

func (s *DemoStore) executePlaybook(id string) (Playbook, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.playbooks[id]
	if !ok {
		return Playbook{}, false
	}
	p.Status = "executing"
	s.playbooks[id] = p
	return p, true
}
