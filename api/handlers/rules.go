package handlers

import (
    "net/http"
    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
)

// Rule represents a detection rule
type Rule struct {
    ID              string            `json:"id"`
    Name            string            `json:"name"`
    Description     string            `json:"description"`
    Type            string            `json:"type"`
    Severity        string            `json:"severity"`
    SeverityScore   int               `json:"severity_score"`
    Status          string            `json:"status"`
    Conditions      []RuleCondition   `json:"conditions"`
    TimeWindowMs    int64             `json:"time_window_ms"`
    Threshold       int               `json:"threshold"`
    AggregationField string          `json:"aggregation_field"`
    Action          string            `json:"action"`
    MitreTactic     string            `json:"mitre_tactic"`
    MitreTechnique  string            `json:"mitre_technique"`
    Tags            []string          `json:"tags"`
    CreatedBy       string            `json:"created_by"`
    CreatedAt       string            `json:"created_at"`
    UpdatedAt       string            `json:"updated_at"`
}

type RuleCondition struct {
    Field string `json:"field"`
    Op    string `json:"op"`
    Value string `json:"value"`
}

func ListRules(c *gin.Context) {
    rules := []Rule{}
    c.JSON(http.StatusOK, gin.H{"rules": rules, "total": 0})
}

func GetRule(c *gin.Context) {
    id := c.Param("id")
    c.JSON(http.StatusOK, Rule{ID: id})
}

func CreateRule(c *gin.Context) {
    var rule Rule
    if err := c.ShouldBindJSON(&rule); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    rule.ID = uuid.New().String()
    rule.Status = "active"
    c.JSON(http.StatusCreated, rule)
}

func UpdateRule(c *gin.Context) {
    id := c.Param("id")
    var rule Rule
    if err := c.ShouldBindJSON(&rule); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    rule.ID = id
    c.JSON(http.StatusOK, rule)
}

func DeleteRule(c *gin.Context) {
    id := c.Param("id")
    c.JSON(http.StatusOK, gin.H{"id": id, "deleted": true})
}

func ReloadRules(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"status": "reloading", "message": "Rules reload initiated"})
}
