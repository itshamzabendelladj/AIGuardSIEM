package handlers

import (
	"net/http"
	"time"

	"github.com/aiguard/siem-xdr/services/orchestrator"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Demo users for local development only.
var demoUsers = map[string]struct {
	Password string
	Roles    []string
}{
	"admin":   {Password: "admin", Roles: []string{"Admin"}},
	"analyst": {Password: "analyst", Roles: []string{"Analyst"}},
}

func issueToken(jwtSecret, username string, roles []string, ttl time.Duration) (string, int64, error) {
	expiresIn := int64(ttl.Seconds())
	claims := jwt.MapClaims{
		"sub":   username,
		"roles": roles,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(ttl).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(jwtSecret))
	return signed, expiresIn, err
}

// Health check
func HealthCheck(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
        "status":   "healthy",
        "service":  "aiguard-api-gateway",
        "version":  "1.0.0",
    })
}

// Readiness check
func ReadinessCheck(orch *orchestrator.Orchestrator) gin.HandlerFunc {
    return func(c *gin.Context) {
        if orch == nil || !orch.IsReady() {
            c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready"})
            return
        }
        c.JSON(http.StatusOK, gin.H{"status": "ready"})
    }
}

// Login issues a real JWT for demo users (admin/admin, analyst/analyst).
func Login(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		user, ok := demoUsers[body.Username]
		if !ok || user.Password != body.Password {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
			return
		}

		token, expiresIn, err := issueToken(jwtSecret, body.Username, user.Roles, time.Hour)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":      token,
			"token_type": "Bearer",
			"expires_in": expiresIn,
			"user": gin.H{
				"username": body.Username,
				"roles":    user.Roles,
			},
		})
	}
}

func RefreshToken(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, _ := c.Get("user_id")
		rolesVal, _ := c.Get("roles")

		userStr, _ := username.(string)
		if userStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing user"})
			return
		}

		roles := []string{"Viewer"}
		switch v := rolesVal.(type) {
		case []string:
			if len(v) > 0 {
				roles = v
			}
		case []interface{}:
			roles = make([]string, 0, len(v))
			for _, r := range v {
				if s, ok := r.(string); ok {
					roles = append(roles, s)
				}
			}
		}

		token, expiresIn, err := issueToken(jwtSecret, userStr, roles, time.Hour)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":      token,
			"token_type": "Bearer",
			"expires_in": expiresIn,
		})
	}
}

func Logout(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"status": "logged out"})
}

// Dashboards
func ListDashboards(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"dashboards": []interface{}{}})
}

func GetDashboard(c *gin.Context) {
    id := c.Param("id")
    c.JSON(http.StatusOK, gin.H{"id": id})
}

func CreateDashboard(c *gin.Context) {
    var dashboard map[string]interface{}
    if err := c.ShouldBindJSON(&dashboard); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusCreated, dashboard)
}

func UpdateDashboard(c *gin.Context) {
    id := c.Param("id")
    var dashboard map[string]interface{}
    c.ShouldBindJSON(&dashboard)
    dashboard["id"] = id
    c.JSON(http.StatusOK, dashboard)
}

func DeleteDashboard(c *gin.Context) {
    id := c.Param("id")
    c.JSON(http.StatusOK, gin.H{"id": id, "deleted": true})
}

// Threat Intelligence
func ListIndicators(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"indicators": []interface{}{}, "total": 0})
}

func CreateIndicator(c *gin.Context) {
    var indicator map[string]interface{}
    c.ShouldBindJSON(&indicator)
    c.JSON(http.StatusCreated, indicator)
}

func ListThreatFeeds(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"feeds": []interface{}{}})
}

func CreateThreatFeed(c *gin.Context) {
    var feed map[string]interface{}
    c.ShouldBindJSON(&feed)
    c.JSON(http.StatusCreated, feed)
}

// Agents
func ListAgents(c *gin.Context) {
	agents := store.listAgents()
	c.JSON(http.StatusOK, gin.H{"agents": agents, "total": len(agents)})
}

func GetAgent(c *gin.Context) {
	id := c.Param("id")
	agent, ok := store.getAgent(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	c.JSON(http.StatusOK, agent)
}

func IsolateAgent(c *gin.Context) {
	id := c.Param("id")
	agent, ok := store.setAgentStatus(id, "isolated")
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": agent.ID, "status": agent.Status, "hostname": agent.Hostname})
}

func UnisolateAgent(c *gin.Context) {
	id := c.Param("id")
	agent, ok := store.setAgentStatus(id, "active")
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": agent.ID, "status": agent.Status, "hostname": agent.Hostname})
}

func GetAgentActions(c *gin.Context) {
	id := c.Param("id")
	if _, ok := store.getAgent(id); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"agent_id": id,
		"actions": []map[string]string{
			{"action": "isolate_host", "status": "available"},
			{"action": "collect_evidence", "status": "available"},
			{"action": "kill_process", "status": "available"},
		},
	})
}

// Cloud
func ListCloudAccounts(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"accounts": []interface{}{}})
}

func AddCloudAccount(c *gin.Context) {
    var account map[string]interface{}
    c.ShouldBindJSON(&account)
    c.JSON(http.StatusCreated, account)
}

func GetCloudFindings(c *gin.Context) {
    id := c.Param("id")
    c.JSON(http.StatusOK, gin.H{"account_id": id, "findings": []interface{}{}})
}

// Playbooks
func ListPlaybooks(c *gin.Context) {
	playbooks := store.listPlaybooks()
	c.JSON(http.StatusOK, gin.H{"playbooks": playbooks, "total": len(playbooks)})
}

func GetPlaybook(c *gin.Context) {
	id := c.Param("id")
	pb, ok := store.getPlaybook(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "playbook not found"})
		return
	}
	c.JSON(http.StatusOK, pb)
}

func CreatePlaybook(c *gin.Context) {
	var playbook Playbook
	if err := c.ShouldBindJSON(&playbook); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if playbook.ID == "" {
		playbook.ID = "pb-" + uuid.New().String()[:8]
	}
	playbook.Enabled = true
	c.JSON(http.StatusCreated, playbook)
}

func ExecutePlaybook(c *gin.Context) {
	id := c.Param("id")
	pb, ok := store.executePlaybook(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "playbook not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"playbook_id": pb.ID,
		"name":        pb.Name,
		"status":      pb.Status,
		"started_at":  time.Now().UTC(),
	})
}

// Users
func ListUsers(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"users": []interface{}{}, "total": 0})
}

func CreateUser(c *gin.Context) {
    var user map[string]interface{}
    c.ShouldBindJSON(&user)
    c.JSON(http.StatusCreated, user)
}

func UpdateUser(c *gin.Context) {
    id := c.Param("id")
    var user map[string]interface{}
    c.ShouldBindJSON(&user)
    user["id"] = id
    c.JSON(http.StatusOK, user)
}

func DeleteUser(c *gin.Context) {
    id := c.Param("id")
    c.JSON(http.StatusOK, gin.H{"id": id, "deleted": true})
}

func GetUserRoles(c *gin.Context) {
    id := c.Param("id")
    c.JSON(http.StatusOK, gin.H{"user_id": id, "roles": []string{}})
}

func AssignUserRoles(c *gin.Context) {
    id := c.Param("id")
    var body struct{ Roles []string `json:"roles"` }
    c.ShouldBindJSON(&body)
    c.JSON(http.StatusOK, gin.H{"user_id": id, "roles": body.Roles})
}

// System
func GetSystemStatus(orch *orchestrator.Orchestrator) gin.HandlerFunc {
    return func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "status":   "operational",
            "services": orch.GetServiceStatus(),
        })
    }
}

func ListServices(orch *orchestrator.Orchestrator) gin.HandlerFunc {
    return func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"services": orch.ListServices()})
    }
}

func RestartService(orch *orchestrator.Orchestrator) gin.HandlerFunc {
    return func(c *gin.Context) {
        name := c.Param("name")
        if err := orch.RestartService(name); err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }
        c.JSON(http.StatusOK, gin.H{"service": name, "status": "restarting"})
    }
}

func GetSystemConfig(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"config": map[string]interface{}{}})
}

func UpdateSystemConfig(c *gin.Context) {
    var config map[string]interface{}
    c.ShouldBindJSON(&config)
    c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func GetAuditLog(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"audit_log": []interface{}{}, "total": 0})
}
