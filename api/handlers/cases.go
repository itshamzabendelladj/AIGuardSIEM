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
	cases := store.listCases()
	c.JSON(http.StatusOK, gin.H{"cases": cases, "total": len(cases)})
}

func GetCase(c *gin.Context) {
	id := c.Param("id")
	item, ok := store.getCase(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	c.JSON(http.StatusOK, item)
}

func CreateCase(c *gin.Context) {
	var newCase Case
	if err := c.ShouldBindJSON(&newCase); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if newCase.ID == "" {
		newCase.ID = "CASE-" + uuid.New().String()[:8]
	}
	if user, exists := c.Get("user_id"); exists {
		if s, ok := user.(string); ok && newCase.CreatedBy == "" {
			newCase.CreatedBy = s
		}
	}
	created := store.createCase(newCase)
	c.JSON(http.StatusCreated, created)
}

func UpdateCase(c *gin.Context) {
	id := c.Param("id")
	var updateCase Case
	if err := c.ShouldBindJSON(&updateCase); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updated, ok := store.updateCase(id, func(item *Case) {
		if updateCase.Title != "" {
			item.Title = updateCase.Title
		}
		if updateCase.Description != "" {
			item.Description = updateCase.Description
		}
		if updateCase.Severity != "" {
			item.Severity = updateCase.Severity
		}
		if updateCase.Status != "" {
			item.Status = updateCase.Status
		}
		if updateCase.AssignedTo != "" {
			item.AssignedTo = updateCase.AssignedTo
		}
		if updateCase.Tags != nil {
			item.Tags = updateCase.Tags
		}
		if updateCase.AlertIDs != nil {
			item.AlertIDs = updateCase.AlertIDs
		}
	})
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	c.JSON(http.StatusOK, updated)
}

func AssignCase(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Assignee string `json:"assignee"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updated, ok := store.updateCase(id, func(item *Case) {
		item.AssignedTo = body.Assignee
		if item.Status == "open" {
			item.Status = "investigating"
		}
	})
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": updated.ID, "assigned_to": updated.AssignedTo, "status": updated.Status})
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
	now := time.Now().UTC()
	updated, ok := store.updateCase(id, func(item *Case) {
		item.Status = "closed"
		item.ClosedAt = &now
		if body.Notes != "" {
			item.Description = item.Description + "\n[closed] " + body.Notes
		}
	})
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":         updated.ID,
		"status":     updated.Status,
		"closed_at":  now,
		"resolution": body.Resolution,
	})
}

func GetCaseTimeline(c *gin.Context) {
	id := c.Param("id")
	item, ok := store.getCase(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	timeline := []map[string]interface{}{
		{"at": item.CreatedAt, "event": "case_created", "by": item.CreatedBy},
		{"at": item.UpdatedAt, "event": "case_updated", "status": item.Status},
	}
	for _, alertID := range item.AlertIDs {
		timeline = append(timeline, map[string]interface{}{
			"at": item.CreatedAt, "event": "alert_linked", "alert_id": alertID,
		})
	}
	c.JSON(http.StatusOK, gin.H{"case_id": id, "timeline": timeline})
}
