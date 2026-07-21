package handlers

import (
    "net/http"
    "time"
    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
)

// Case represents an incident response case
type Case struct {
    ID          string     `json:"id"`
    Title       string     `json:"title"`
    Description string     `json:"description"`
    Severity    string     `json:"severity"`
    Status      string     `json:"status"`
    AssignedTo  string     `json:"assigned_to"`
    Tags        []string   `json:"tags"`
    AlertIDs    []string   `json:"alert_ids"`
    CreatedBy   string     `json:"created_by"`
    CreatedAt   time.Time  `json:"created_at"`
    UpdatedAt   time.Time  `json:"updated_at"`
    ClosedAt    *time.Time `json:"closed_at,omitempty"`
}

func ListCases(c *gin.Context) {
    cases := []Case{}
    c.JSON(http.StatusOK, gin.H{"cases": cases, "total": 0})
}

func GetCase(c *gin.Context) {
    id := c.Param("id")
    c.JSON(http.StatusOK, Case{ID: id})
}

func CreateCase(c *gin.Context) {
    var newCase Case
    if err := c.ShouldBindJSON(&newCase); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    newCase.ID = uuid.New().String()
    newCase.Status = "open"
    newCase.CreatedAt = time.Now()
    c.JSON(http.StatusCreated, newCase)
}

func UpdateCase(c *gin.Context) {
    id := c.Param("id")
    var updateCase Case
    if err := c.ShouldBindJSON(&updateCase); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    updateCase.ID = id
    updateCase.UpdatedAt = time.Now()
    c.JSON(http.StatusOK, updateCase)
}

func AssignCase(c *gin.Context) {
    id := c.Param("id")
    var body struct{ Assignee string `json:"assignee"` }
    if err := c.ShouldBindJSON(&body); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"id": id, "assigned_to": body.Assignee})
}

func CloseCase(c *gin.Context) {
    id := c.Param("id")
    var body struct {
        Resolution string `json:"resolution"`
        Notes      string `json:"notes"`
    }
    if err := c.ShouldBindJSON(&body); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    now := time.Now()
    c.JSON(http.StatusOK, gin.H{"id": id, "status": "closed", "closed_at": now})
}

func GetCaseTimeline(c *gin.Context) {
    id := c.Param("id")
    c.JSON(http.StatusOK, gin.H{
        "case_id":  id,
        "timeline": []map[string]interface{}{},
    })
}
