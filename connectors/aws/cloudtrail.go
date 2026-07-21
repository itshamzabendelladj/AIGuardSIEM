package aws

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
    "github.com/aws/aws-sdk-go-v2/service/guardduty"
    "github.com/aws/aws-sdk-go-v2/service/securityhub"
    "go.uber.org/zap"
)

// CloudTrailConnector ingests AWS CloudTrail events
type CloudTrailConnector struct {
    client    *cloudtrail.Client
    logger    *zap.Logger
    s3Bucket  string
    s3Prefix  string
    lastProcessed time.Time
}

// CloudTrailConfig holds CloudTrail connector configuration
type CloudTrailConfig struct {
    Region    string
    S3Bucket  string
    S3Prefix  string
    AccessKey string
    SecretKey string
}

// NewCloudTrailConnector creates a new CloudTrail connector
func NewCloudTrailConnector(cfg CloudTrailConfig, logger *zap.Logger) (*CloudTrailConnector, error) {
    ctx := context.Background()

    awsCfg, err := config.LoadDefaultConfig(ctx,
        config.WithRegion(cfg.Region),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to load AWS config: %w", err)
    }

    return &CloudTrailConnector{
        client:    cloudtrail.NewFromConfig(awsCfg),
        logger:    logger,
        s3Bucket:  cfg.S3Bucket,
        s3Prefix:  cfg.S3Prefix,
        lastProcessed: time.Now().Add(-24 * time.Hour),
    }, nil
}

// CloudTrailEvent represents a normalized CloudTrail event
type CloudTrailEvent struct {
    EventVersion      string                 `json:"eventVersion"`
    EventTime         time.Time              `json:"eventTime"`
    EventSource       string                 `json:"eventSource"`
    EventName         string                 `json:"eventName"`
    AWSRegion         string                 `json:"awsRegion"`
    SourceIP          string                 `json:"sourceIPAddress"`
    UserIdentity      map[string]interface{} `json:"userIdentity"`
    RequestParameters map[string]interface{} `json:"requestParameters"`
    ResponseElements  map[string]interface{} `json:"responseElements"`
    Resources         []map[string]interface{} `json:"resources"`
    ErrorCode         string                 `json:"errorCode,omitempty"`
    ErrorMessage      string                 `json:"errorMessage,omitempty"`
}

// FetchEvents fetches new CloudTrail events since last processed time
func (c *CloudTrailConnector) FetchEvents(ctx context.Context) ([]CloudTrailEvent, error) {
    c.logger.Info("Fetching CloudTrail events",
        zap.Time("since", c.lastProcessed))

    // In production, would:
    // 1. List S3 objects in CloudTrail bucket
    // 2. Download and decompress log files
    // 3. Parse JSON log format
    // 4. Filter by timestamp

    events := []CloudTrailEvent{}
    c.lastProcessed = time.Now()

    return events, nil
}

// NormalizeEvent converts a CloudTrail event to ECS format
func (c *CloudTrailConnector) NormalizeEvent(event CloudTrailEvent) map[string]interface{} {
    ecs := map[string]interface{}{
        "@timestamp":       event.EventTime,
        "event.category":   "cloud",
        "event.type":       "info",
        "event.action":     event.EventName,
        "event.module":     "aws_cloudtrail",
        "event.dataset":    "aws.cloudtrail",
        "cloud.provider":   "aws",
        "cloud.region":     event.AWSRegion,
        "source.ip":        event.SourceIP,
        "event.source":     event.EventSource,
    }

    // Extract user identity
    if userIdentity, ok := event.UserIdentity["arn"].(string); ok {
        ecs["user.id"] = userIdentity
    }
    if userType, ok := event.UserIdentity["type"].(string); ok {
        ecs["user.type"] = userType
    }
    if userName, ok := event.UserIdentity["userName"].(string); ok {
        ecs["user.name"] = userName
    }

    // Set severity based on event
    if event.ErrorCode != "" {
        ecs["event.outcome"] = "failure"
    } else {
        ecs["event.outcome"] = "success"
    }

    // Add raw event data
    if len(event.RequestParameters) > 0 {
        ecs["aws.cloudtrail.request_parameters"] = event.RequestParameters
    }
    if len(event.ResponseElements) > 0 {
        ecs["aws.cloudtrail.response_elements"] = event.ResponseElements
    }

    return ecs
}

// GuardDutyConnector ingests AWS GuardDuty findings
type GuardDutyConnector struct {
    client    *guardduty.Client
    logger    *zap.Logger
    detectorID string
}

// GuardDutyConfig holds GuardDuty connector configuration
type GuardDutyConfig struct {
    Region     string
    DetectorID string
}

// NewGuardDutyConnector creates a new GuardDuty connector
func NewGuardDutyConnector(cfg GuardDutyConfig, logger *zap.Logger) (*GuardDutyConnector, error) {
    ctx := context.Background()
    awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
    if err != nil {
        return nil, fmt.Errorf("failed to load AWS config: %w", err)
    }

    return &GuardDutyConnector{
        client:    guardduty.NewFromConfig(awsCfg),
        logger:    logger,
        detectorID: cfg.DetectorID,
    }, nil
}

// FetchFindings fetches new GuardDuty findings
func (g *GuardDutyConnector) FetchFindings(ctx context.Context) ([]map[string]interface{}, error) {
    g.logger.Info("Fetching GuardDuty findings")

    // In production, would call ListFindings and GetFindings APIs
    findings := []map[string]interface{}{}
    return findings, nil
}

// SecurityHubConnector ingests AWS Security Hub findings
type SecurityHubConnector struct {
    client *securityhub.Client
    logger *zap.Logger
}

// NewSecurityHubConnector creates a new Security Hub connector
func NewSecurityHubConnector(region string, logger *zap.Logger) (*SecurityHubConnector, error) {
    ctx := context.Background()
    awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
    if err != nil {
        return nil, fmt.Errorf("failed to load AWS config: %w", err)
    }

    return &SecurityHubConnector{
        client: securityhub.NewFromConfig(awsCfg),
        logger: logger,
    }, nil
}

// FetchFindings fetches Security Hub findings
func (s *SecurityHubConnector) FetchFindings(ctx context.Context) ([]map[string]interface{}, error) {
    s.logger.Info("Fetching Security Hub findings")
    findings := []map[string]interface{}{}
    return findings, nil
}

// MarshalFindings serializes findings to JSON
func MarshalFindings(findings []map[string]interface{}) (string, error) {
    data, err := json.Marshal(findings)
    if err != nil {
        return "", fmt.Errorf("failed to marshal findings: %w", err)
    }
    return string(data), nil
}
