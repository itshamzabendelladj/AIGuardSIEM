package handlers

import (
    "net/http"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
)

// Alert represents a security alert
type Alert struct {
    ID              string            `json:"id"`
    RuleID          string            `json:"rule_id"`
    RuleName        string            `json:"rule_name"`
    Description     string            `json:"description"`
    Severity        string            `json:"severity"`
    SeverityScore   int               `json:"severity_score"`
    Status          string            `json:"status"`
    MitreTactic     string            `json:"mitre_tactic"`
    MitreTechnique  string            `json:"mitre_technique"`
    SourceIP        string            `json:"source_ip"`
    DestinationIP   string            `json:"destination_ip"`
    HostName        string            `json:"host_name"`
    UserName        string            `json:"user_name"`
    ProcessName     string            `json:"process_name"`
    Action          string            `json:"action"`
    AggregationKey  string            `json:"aggregation_key"`
    MatchCount      int               `json:"match_count"`
    Timestamp       time.Time         `json:"timestamp"`
    FirstSeen       time.Time         `json:"first_seen"`
    LastSeen        time.Time         `json:"last_seen"`
    Tags            []string          `json:"tags"`
    Notes           string            `json:"notes"`
    AssignedTo      string            `json:"assigned_to"`
    CustomFields    map[string]string `json:"custom_fields,omitempty"`
}

// AlertQuery holds query parameters for listing alerts
type AlertQuery struct {
    Severity   string `form:"severity"`
    Status     string `form:"status"`
    RuleID     string `form:"rule_id"`
    SourceIP   string `form:"source_ip"`
    HostName   string `form:"host_name"`
    StartTime  string `form:"start_time"`
    EndTime    string `form:"end_time"`
    Limit      int    `form:"limit,default:50"`
    Offset     int    `form:"offset,default:0"`
    SortBy     string `form:"sort_by,default:timestamp"`
    SortOrder  string `form:"sort_order,default:desc"`
}

// ListAlerts returns a paginated list of alerts
func ListAlerts(c *gin.Context) {
    var query AlertQuery
    if err := c.ShouldBindQuery(&query); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    if query.Limit <= 0 || query.Limit > 1000 {
        query.Limit = 50
    }

    // In production, query from storage layer
    alerts := []Alert{}
    total := 0

    c.JSON(http.StatusOK, gin.H{
        "alerts": alerts,
        "total":  total,
        "limit":  query.Limit,
        "offset": query.Offset,
    })
}

// GetAlert returns a single alert by ID
func GetAlert(c *gin.Context) {
    id := c.Param("id")
    if id == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "alert ID required"})
        return
    }

    // In production, fetch from storage
    alert := Alert{
        ID: id,
    }

    c.JSON(http.StatusOK, alert)
}

// CreateAlert creates a new alert
func CreateAlert(c *gin.Context) {
    var alert Alert
    if err := c.ShouldBindJSON(&alert); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    alert.ID = uuid.New().String()
    alert.Timestamp = time.Now()
    alert.Status = "open"

    // In production, store in database and publish to Kafka
    c.JSON(http.StatusCreated, alert)
}

// UpdateAlert updates an existing alert
func UpdateAlert(c *gin.Context) {
    id := c.Param("id")
    var alert Alert
    if err := c.ShouldBindJSON(&alert); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    alert.ID = id
    c.JSON(http.StatusOK, alert)
}

// DeleteAlert deletes an alert
func DeleteAlert(c *gin.Context) {
    id := c.Param("id")
    // In production, delete from storage
    c.JSON(http.StatusOK, gin.H{"id": id, "deleted": true})
}

// AcknowledgeAlert marks an alert as acknowledged
func AcknowledgeAlert(c *gin.Context) {
    id := c.Param("id")
    user := c.GetString("user_id")

    // In production, update alert status
    c.JSON(http.StatusOK, gin.H{
        "id":            id,
        "status":        "acknowledged",
        "acknowledged_by": user,
        "acknowledged_at": time.Now(),
    })
}

// ResolveAlert marks an alert as resolved
func ResolveAlert(c *gin.Context) {
    id := c.Param("id")
    user := c.GetString("user_id")

    var body struct {
        Resolution string `json:"resolution"`
        Notes      string `json:"notes"`
    }
    if err := c.ShouldBindJSON(&body); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "id":          id,
        "status":      "resolved",
        "resolved_by": user,
        "resolved_at": time.Now(),
        "resolution":  body.Resolution,
        "notes":       body.Notes,
    })
}

// StreamAlerts streams real-time alerts via WebSocket
func StreamAlerts(c *gin.Context) {
    // WebSocket implementation for real-time alert streaming
    c.JSON(http.StatusOK, gin.H{"message": "WebSocket endpoint for real-time alerts"})
}
