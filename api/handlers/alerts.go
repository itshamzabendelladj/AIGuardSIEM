package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Alert represents a security alert
type Alert struct {
	ID             string            `json:"id"`
	RuleID         string            `json:"rule_id"`
	RuleName       string            `json:"rule_name"`
	Description    string            `json:"description"`
	Severity       string            `json:"severity"`
	SeverityScore  int               `json:"severity_score"`
	Status         string            `json:"status"`
	MitreTactic    string            `json:"mitre_tactic"`
	MitreTechnique string            `json:"mitre_technique"`
	SourceIP       string            `json:"source_ip"`
	DestinationIP  string            `json:"destination_ip"`
	HostName       string            `json:"host_name"`
	UserName       string            `json:"user_name"`
	ProcessName    string            `json:"process_name"`
	Action         string            `json:"action"`
	AggregationKey string            `json:"aggregation_key"`
	MatchCount     int               `json:"match_count"`
	Timestamp      time.Time         `json:"timestamp"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
	Tags           []string          `json:"tags"`
	Notes          string            `json:"notes"`
	AssignedTo     string            `json:"assigned_to"`
	CustomFields   map[string]string `json:"custom_fields,omitempty"`
}

// AlertQuery holds query parameters for listing alerts
type AlertQuery struct {
	Severity  string `form:"severity"`
	Status    string `form:"status"`
	RuleID    string `form:"rule_id"`
	SourceIP  string `form:"source_ip"`
	HostName  string `form:"host_name"`
	StartTime string `form:"start_time"`
	EndTime   string `form:"end_time"`
	Limit     int    `form:"limit,default:50"`
	Offset    int    `form:"offset,default:0"`
	SortBy    string `form:"sort_by,default:timestamp"`
	SortOrder string `form:"sort_order,default:desc"`
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
	if query.Offset < 0 {
		query.Offset = 0
	}

	filtered := make([]Alert, 0)
	for _, a := range store.listAlerts() {
		if query.Severity != "" && !strings.EqualFold(a.Severity, query.Severity) {
			continue
		}
		if query.Status != "" && !strings.EqualFold(a.Status, query.Status) {
			continue
		}
		if query.RuleID != "" && a.RuleID != query.RuleID {
			continue
		}
		if query.SourceIP != "" && a.SourceIP != query.SourceIP {
			continue
		}
		if query.HostName != "" && !strings.EqualFold(a.HostName, query.HostName) {
			continue
		}
		filtered = append(filtered, a)
	}

	total := len(filtered)
	start := query.Offset
	if start > total {
		start = total
	}
	end := start + query.Limit
	if end > total {
		end = total
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": filtered[start:end],
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

	alert, ok := store.getAlert(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		return
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
	created := store.createAlert(alert)
	c.JSON(http.StatusCreated, created)
}

// UpdateAlert updates an existing alert
func UpdateAlert(c *gin.Context) {
	id := c.Param("id")
	var incoming Alert
	if err := c.ShouldBindJSON(&incoming); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updated, ok := store.updateAlert(id, func(a *Alert) {
		if incoming.RuleName != "" {
			a.RuleName = incoming.RuleName
		}
		if incoming.Description != "" {
			a.Description = incoming.Description
		}
		if incoming.Severity != "" {
			a.Severity = incoming.Severity
		}
		if incoming.SeverityScore != 0 {
			a.SeverityScore = incoming.SeverityScore
		}
		if incoming.Status != "" {
			a.Status = incoming.Status
		}
		if incoming.Notes != "" {
			a.Notes = incoming.Notes
		}
		if incoming.AssignedTo != "" {
			a.AssignedTo = incoming.AssignedTo
		}
		if incoming.Tags != nil {
			a.Tags = incoming.Tags
		}
		a.LastSeen = time.Now().UTC()
	})
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		return
	}

	c.JSON(http.StatusOK, updated)
}

// DeleteAlert deletes an alert
func DeleteAlert(c *gin.Context) {
	id := c.Param("id")
	if !store.deleteAlert(id) {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "deleted": true})
}

// AcknowledgeAlert marks an alert as acknowledged
func AcknowledgeAlert(c *gin.Context) {
	id := c.Param("id")
	user := c.GetString("user_id")

	updated, ok := store.updateAlert(id, func(a *Alert) {
		a.Status = "acknowledged"
		a.AssignedTo = user
		a.LastSeen = time.Now().UTC()
	})
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":              updated.ID,
		"status":          updated.Status,
		"acknowledged_by": user,
		"acknowledged_at": time.Now().UTC(),
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

	updated, ok := store.updateAlert(id, func(a *Alert) {
		a.Status = "resolved"
		if body.Notes != "" {
			a.Notes = body.Notes
		}
		a.AssignedTo = user
		a.LastSeen = time.Now().UTC()
	})
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":          updated.ID,
		"status":      updated.Status,
		"resolved_by": user,
		"resolved_at": time.Now().UTC(),
		"resolution":  body.Resolution,
		"notes":       body.Notes,
	})
}

// StreamAlerts streams real-time alerts via WebSocket
func StreamAlerts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "WebSocket endpoint for real-time alerts (coming soon)"})
}
