package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Rule represents a detection rule
type Rule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	Type             string          `json:"type"`
	Severity         string          `json:"severity"`
	SeverityScore    int             `json:"severity_score"`
	Status           string          `json:"status"`
	Conditions       []RuleCondition `json:"conditions"`
	TimeWindowMs     int64           `json:"time_window_ms"`
	Threshold        int             `json:"threshold"`
	AggregationField string          `json:"aggregation_field"`
	Action           string          `json:"action"`
	MitreTactic      string          `json:"mitre_tactic"`
	MitreTechnique   string          `json:"mitre_technique"`
	Tags             []string        `json:"tags"`
	CreatedBy        string          `json:"created_by"`
	CreatedAt        string          `json:"created_at"`
	UpdatedAt        string          `json:"updated_at"`
}

type RuleCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

func ListRules(c *gin.Context) {
	rules := store.listRules()
	c.JSON(http.StatusOK, gin.H{"rules": rules, "total": len(rules)})
}

func GetRule(c *gin.Context) {
	id := c.Param("id")
	rule, ok := store.getRule(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

func CreateRule(c *gin.Context) {
	var rule Rule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rule.ID = uuid.New().String()
	rule.Status = "active"
	now := time.Now().UTC().Format(time.RFC3339)
	rule.CreatedAt = now
	rule.UpdatedAt = now
	c.JSON(http.StatusCreated, rule)
}

func UpdateRule(c *gin.Context) {
	id := c.Param("id")
	var rule Rule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	existing, ok := store.getRule(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	rule.ID = id
	if rule.CreatedAt == "" {
		rule.CreatedAt = existing.CreatedAt
	}
	rule.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	c.JSON(http.StatusOK, rule)
}

func DeleteRule(c *gin.Context) {
	id := c.Param("id")
	if _, ok := store.getRule(id); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "deleted": true})
}

func ReloadRules(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "reloaded",
		"message": "Rules reload completed from demo store / sigma catalog",
		"total":   len(store.listRules()),
	})
}
