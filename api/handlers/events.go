package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// Event represents a normalized security event
type Event struct {
	ID               string                 `json:"id"`
	Timestamp        time.Time              `json:"timestamp"`
	SourceType       string                 `json:"source_type"`
	Category         string                 `json:"category"`
	Type             string                 `json:"type"`
	Action           string                 `json:"action"`
	Severity         string                 `json:"severity"`
	SeverityScore    int                    `json:"severity_score"`
	SourceIP         string                 `json:"source_ip"`
	SourcePort       int                    `json:"source_port"`
	DestinationIP    string                 `json:"destination_ip"`
	DestinationPort  int                    `json:"destination_port"`
	HostName         string                 `json:"host_name"`
	UserName         string                 `json:"user_name"`
	ProcessName      string                 `json:"process_name"`
	NetworkTransport string                 `json:"network_transport"`
	NetworkProtocol  string                 `json:"network_protocol"`
	NetworkBytes     int64                  `json:"network_bytes"`
	NetworkPackets   int64                  `json:"network_packets"`
	CustomFields     map[string]interface{} `json:"custom_fields,omitempty"`
}

// SearchQuery holds search parameters
type SearchQuery struct {
	Query     string            `json:"query"`
	StartTime string            `json:"start_time"`
	EndTime   string            `json:"end_time"`
	Fields    []string          `json:"fields"`
	Filters   map[string]string `json:"filters"`
	Limit     int               `json:"limit"`
	Offset    int               `json:"offset"`
	SortBy    string            `json:"sort_by"`
	SortOrder string            `json:"sort_order"`
}

// ListEvents returns a paginated list of events
func ListEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	category := c.Query("category")
	q := c.Query("q")
	events := store.searchEvents(q, category, 0)
	total := len(events)
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	c.JSON(http.StatusOK, gin.H{
		"events": events[start:end],
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetEvent returns a single event by ID
func GetEvent(c *gin.Context) {
	id := c.Param("id")
	event, ok := store.getEvent(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
		return
	}
	c.JSON(http.StatusOK, event)
}

// SearchEvents searches events with a query
func SearchEvents(c *gin.Context) {
	var query SearchQuery
	if err := c.ShouldBindJSON(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if query.Limit <= 0 || query.Limit > 10000 {
		query.Limit = 100
	}

	category := ""
	if query.Filters != nil {
		category = query.Filters["category"]
	}
	results := store.searchEvents(query.Query, category, query.Limit)
	c.JSON(http.StatusOK, gin.H{
		"results":    results,
		"total":      len(results),
		"query_time": "1ms",
	})
}

// AggregateEvents performs aggregations on events
func AggregateEvents(c *gin.Context) {
	var body struct {
		Field     string            `json:"field"`
		StartTime string            `json:"start_time"`
		EndTime   string            `json:"end_time"`
		Interval  string            `json:"interval"`
		Filters   map[string]string `json:"filters"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Field == "" {
		body.Field = "category"
	}

	buckets := store.aggregateByField(body.Field)
	total := 0
	for _, b := range buckets {
		if n, ok := b["count"].(int); ok {
			total += n
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"field":   body.Field,
		"buckets": buckets,
		"total":   total,
	})
}
