package kubernetes

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"

    "go.uber.org/zap"
)

// K8sAuditConnector ingests Kubernetes audit logs
type K8sAuditConnector struct {
    logger    *zap.Logger
    apiServer string
    token     string
    caCert    []byte
    client    *http.Client
}

// K8sAuditConfig holds K8s audit connector configuration
type K8sAuditConfig struct {
    APIServer string
    Token     string
    CACert    []byte
}

// NewK8sAuditConnector creates a new K8s audit connector
func NewK8sAuditConnector(cfg K8sAuditConfig, logger *zap.Logger) (*K8sAuditConnector, error) {
    return &K8sAuditConnector{
        logger:    logger,
        apiServer: cfg.APIServer,
        token:     cfg.Token,
        caCert:    cfg.CACert,
        client:    &http.Client{Timeout: 30 * time.Second},
    }, nil
}

// K8sAuditEvent represents a Kubernetes audit event
type K8sAuditEvent struct {
    Kind       string                 `json:"kind"`
    APIVersion string                 `json:"apiVersion"`
    Level      string                 `json:"level"`
    AuditID    string                 `json:"auditID"`
    Stage      string                 `json:"stage"`
    RequestURI string                 `json:"requestURI"`
    Verb       string                 `json:"verb"`
    User       K8sAuditUser           `json:"user"`
    SourceIP   string                 `json:"sourceIPs"`
    ObjectRef  map[string]interface{} `json:"objectRef,omitempty"`
    Response   map[string]interface{} `json:"responseStatus,omitempty"`
    EventTime  time.Time              `json:"eventTime"`
}

type K8sAuditUser struct {
    Username string                 `json:"username"`
    UID      string                 `json:"uid"`
    Groups   []string               `json:"groups"`
    Extra    map[string]interface{} `json:"extra,omitempty"`
}

// FetchAuditLogs fetches K8s audit logs
func (k *K8sAuditConnector) FetchAuditLogs(ctx context.Context) ([]K8sAuditEvent, error) {
    k.logger.Info("Fetching Kubernetes audit logs")

    // In production, would:
    // 1. Connect to K8s API server audit endpoint
    // 2. Or read from audit log files
    // 3. Or consume from webhook backend

    events := []K8sAuditEvent{}
    return events, nil
}

// NormalizeEvent converts K8s audit event to ECS format
func (k *K8sAuditConnector) NormalizeEvent(event K8sAuditEvent) map[string]interface{} {
    ecs := map[string]interface{}{
        "@timestamp":      event.EventTime,
        "event.category":  "cloud",
        "event.type":      "info",
        "event.action":    event.Verb,
        "event.module":    "kubernetes",
        "event.dataset":   "kubernetes.audit",
        "kubernetes.audit.id":     event.AuditID,
        "kubernetes.audit.stage":  event.Stage,
        "kubernetes.audit.level":  event.Level,
        "url.path":       event.RequestURI,
        "user.name":      event.User.Username,
        "user.id":        event.User.UID,
    }

    if len(event.User.Groups) > 0 {
        ecs["user.group"] = event.User.Groups
    }

    if event.SourceIP != "" {
        ecs["source.ip"] = event.SourceIP
    }

    if event.ObjectRef != nil {
        ecs["kubernetes.object_ref"] = event.ObjectRef
    }

    if event.Response != nil {
        ecs["kubernetes.response"] = event.Response
    }

    return ecs
}

// StartWatch starts watching audit events via HTTP stream
func (k *K8sAuditConnector) StartWatch(ctx context.Context, eventChan chan<- K8sAuditEvent) error {
    // In production, would establish HTTP stream to audit webhook
    return nil
}

// ParseAuditLine parses a single audit log line
func ParseAuditLine(line string) (*K8sAuditEvent, error) {
    var event K8sAuditEvent
    if err := json.Unmarshal([]byte(line), &event); err != nil {
        return nil, fmt.Errorf("failed to parse audit line: %w", err)
    }
    return &event, nil
}

// ReadAuditStream reads audit events from an io.Reader
func ReadAuditStream(reader io.Reader, eventChan chan<- K8sAuditEvent) error {
    decoder := json.NewDecoder(reader)
    for {
        var event K8sAuditEvent
        if err := decoder.Decode(&event); err != nil {
            if err == io.EOF {
                return nil
            }
            return fmt.Errorf("failed to decode audit event: %w", err)
        }
        eventChan <- event
    }
}
