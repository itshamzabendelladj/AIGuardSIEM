package gcp

import (
    "context"
    "go.uber.org/zap"
)

// GCPConnector ingests GCP Security Command Center findings
type GCPConnector struct {
    logger     *zap.Logger
    projectID  string
    orgID      string
}

// GCPConfig holds GCP connector configuration
type GCPConfig struct {
    ProjectID string
    OrgID     string
}

// NewGCPConnector creates a new GCP connector
func NewGCPConnector(cfg GCPConfig, logger *zap.Logger) (*GCPConnector, error) {
    return &GCPConnector{
        logger:    logger,
        projectID: cfg.ProjectID,
        orgID:     cfg.OrgID,
    }, nil
}

// FetchSCCFindings fetches Security Command Center findings
func (g *GCPConnector) FetchSCCFindings(ctx context.Context) ([]map[string]interface{}, error) {
    g.logger.Info("Fetching GCP SCC findings")
    return []map[string]interface{}{}, nil
}

// FetchAuditLogs fetches GCP Cloud Audit logs
func (g *GCPConnector) FetchAuditLogs(ctx context.Context) ([]map[string]interface{}, error) {
    g.logger.Info("Fetching GCP audit logs")
    return []map[string]interface{}{}, nil
}

// NormalizeFinding converts GCP finding to ECS format
func (g *GCPConnector) NormalizeFinding(finding map[string]interface{}) map[string]interface{} {
    return map[string]interface{}{
        "event.module":  "gcp_scc",
        "event.dataset": "gcp.scc",
        "cloud.provider": "gcp",
        "raw":           finding,
    }
}
