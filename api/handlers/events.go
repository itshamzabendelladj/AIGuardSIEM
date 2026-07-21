package handlers

import (
    "net/http"
    "time"

    "github.com/gin-gonic/gin"
)

// Event represents a normalized security event
type Event struct {
    ID              string                 `json:"id"`
    Timestamp       time.Time              `json:"timestamp"`
    SourceType      string                 `json:"source_type"`
    Category        string                 `json:"category"`
    Type            string                 `json:"type"`
    Action          string                 `json:"action"`
    Severity        string                 `json:"severity"`
    SeverityScore   int                    `json:"severity_score"`
    SourceIP        string                 `json:"source_ip"`
    SourcePort      int                    `json:"source_port"`
    DestinationIP   string                 `json:"destination_ip"`
    DestinationPort int                    `json:"destination_port"`
    HostName        string                 `json:"host_name"`
    UserName        string                 `json:"user_name"`
    ProcessName     string                 `json:"process_name"`
    NetworkTransport string               `json:"network_transport"`
    NetworkProtocol string                 `json:"network_protocol"`
    NetworkBytes    int64                  `json:"network_bytes"`
    NetworkPackets  int64                  `json:"network_packets"`
    CustomFields    map[string]interface{} `json:"custom_fields,omitempty"`
}

// SearchQuery holds search parameters
type SearchQuery struct {
    Query    string `json:"query"`
    StartTime string `json:"start_time"`
    EndTime   string `json:"end_time"`
    Fields    []string `json:"fields"`
    Filters   map[string]string `json:"filters"`
    Limit     int    `json:"limit"`
    Offset    int    `json:"offset"`
    SortBy    string `json:"sort_by"`
    SortOrder string `json:"sort_order"`
}

// ListEvents returns a paginated list of events
func ListEvents(c *gin.Context) {
    limit := 50
    offset := 0

    events := []Event{}
    c.JSON(http.StatusOK, gin.H{
        "events": events,
        "total":  0,
        "limit":  limit,
        "offset": offset,
    })
}

// GetEvent returns a single event by ID
func GetEvent(c *gin.Context) {
    id := c.Param("id")
    c.JSON(http.StatusOK, Event{ID: id})
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

    // In production, query from storage layer (ClickHouse, Druid, or LSM)
    results := []Event{}
    c.JSON(http.StatusOK, gin.H{
        "results":    results,
        "total":      0,
        "query_time": "0ms",
    })
}

// AggregateEvents performs aggregations on events
func AggregateEvents(c *gin.Context) {
    var body struct {
        Field     string `json:"field"`
        StartTime string `json:"start_time"`
        EndTime   string `json:"end_time"`
        Interval  string `json:"interval"`
        Filters   map[string]string `json:"filters"`
    }
    if err := c.ShouldBindJSON(&body); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "field":    body.Field,
        "buckets":  []map[string]interface{}{},
        "total":    0,
    })
}
