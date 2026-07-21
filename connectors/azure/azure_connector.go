package azure

import (
    "context"
    "fmt"
    "time"

    "go.uber.org/zap"
)

// AzureConnector ingests Azure Sentinel and Defender findings
type AzureConnector struct {
    logger       *zap.Logger
    tenantID     string
    clientID     string
    clientSecret string
    workspaceID  string
}

// AzureConfig holds Azure connector configuration
type AzureConfig struct {
    TenantID     string
    ClientID     string
    ClientSecret string
    WorkspaceID  string
}

// NewAzureConnector creates a new Azure connector
func NewAzureConnector(cfg AzureConfig, logger *zap.Logger) (*AzureConnector, error) {
    return &AzureConnector{
        logger:       logger,
        tenantID:     cfg.TenantID,
        clientID:     cfg.ClientID,
        clientSecret: cfg.ClientSecret,
        workspaceID:  cfg.WorkspaceID,
    }, nil
}

// FetchSentinelAlerts fetches Azure Sentinel alerts
func (a *AzureConnector) FetchSentinelAlerts(ctx context.Context) ([]map[string]interface{}, error) {
    a.logger.Info("Fetching Azure Sentinel alerts")
    // In production, would use Azure SDK to query Log Analytics
    return []map[string]interface{}{}, nil
}

// FetchDefenderFindings fetches Microsoft Defender for Cloud findings
func (a *AzureConnector) FetchDefenderFindings(ctx context.Context) ([]map[string]interface{}, error) {
    a.logger.Info("Fetching Defender for Cloud findings")
    return []map[string]interface{}{}, nil
}

// NormalizeAlert converts Azure alert to ECS format
func (a *AzureConnector) NormalizeAlert(alert map[string]interface{}) map[string]interface{} {
    return map[string]interface{}{
        "event.module":  "azure_sentinel",
        "event.dataset": "azure.sentinel",
        "cloud.provider": "azure",
        "raw":           alert,
    }
}
