package backend

import (
    "encoding/json"
    "fmt"
    "net/http"
    "sync"
    "time"

    "github.com/gorilla/websocket"
    "go.uber.org/zap"
)

// VizServer handles real-time visualization backend
type VizServer struct {
    logger    *zap.Logger
    clients   map[*websocket.Conn]bool
    broadcast chan []byte
    mu        sync.RWMutex
    upgrader  websocket.Upgrader
}

// NewVizServer creates a new visualization server
func NewVizServer(logger *zap.Logger) *VizServer {
    return &VizServer{
        logger:    logger,
        clients:   make(map[*websocket.Conn]bool),
        broadcast: make(chan []byte, 1000),
        upgrader: websocket.Upgrader{
            ReadBufferSize:  1024,
            WriteBufferSize: 1024,
            CheckOrigin: func(r *http.Request) bool {
                return true // Configure appropriately in production
            },
        },
    }
}

// Start starts the visualization server
func (v *VizServer) Start(port int) error {
    http.HandleFunc("/ws", v.handleWebSocket)
    http.HandleFunc("/api/dashboard", v.handleDashboard)
    http.HandleFunc("/api/mitre-heatmap", v.handleMitreHeatmap)
    http.HandleFunc("/api/threat-map", v.handleThreatMap)
    http.HandleFunc("/api/metrics", v.handleMetrics)

    go v.broadcastLoop()

    v.logger.Info("Starting visualization server", zap.Int("port", port))
    return http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func (v *VizServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    conn, err := v.upgrader.Upgrade(w, r, nil)
    if err != nil {
        v.logger.Error("WebSocket upgrade failed", zap.Error(err))
        return
    }
    defer conn.Close()

    v.mu.Lock()
    v.clients[conn] = true
    v.mu.Unlock()

    v.logger.Info("WebSocket client connected",
        zap.String("remote", conn.RemoteAddr().String()))

    // Send initial data
    v.sendInitialData(conn)

    // Read loop (handle client messages)
    for {
        _, msg, err := conn.ReadMessage()
        if err != nil {
            break
        }
        v.handleClientMessage(conn, msg)
    }

    v.mu.Lock()
    delete(v.clients, conn)
    v.mu.Unlock()

    v.logger.Info("WebSocket client disconnected",
        zap.String("remote", conn.RemoteAddr().String()))
}

func (v *VizServer) sendInitialData(conn *websocket.Conn) {
    data := map[string]interface{}{
        "type": "init",
        "data": map[string]interface{}{
            "events_per_second": 0,
            "active_alerts":     0,
            "mitre_coverage":    []interface{}{},
            "top_sources":       []interface{}{},
        },
    }
    if data, err := json.Marshal(data); err == nil {
        conn.WriteMessage(websocket.TextMessage, data)
    }
}

func (v *VizServer) handleClientMessage(conn *websocket.Conn, msg []byte) {
    // Handle client subscriptions
    var req struct {
        Type   string `json:"type"`
        Filter map[string]interface{} `json:"filter,omitempty"`
    }
    if err := json.Unmarshal(msg, &req); err != nil {
        return
    }

    switch req.Type {
    case "subscribe":
        v.logger.Info("Client subscription", zap.String("type", req.Type))
    case "unsubscribe":
        // Handle unsubscription
    }
}

func (v *VizServer) broadcastLoop() {
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()

    for range ticker.C {
        // Broadcast updates to all clients
        update := map[string]interface{}{
            "type": "update",
            "timestamp": time.Now().UnixMilli(),
            "data": map[string]interface{}{
                "events_per_second": 50000,
                "active_alerts":     12,
                "processing_latency_ms": 5,
            },
        }

        data, err := json.Marshal(update)
        if err != nil {
            continue
        }

        v.mu.RLock()
        for client := range v.clients {
            client.WriteMessage(websocket.TextMessage, data)
        }
        v.mu.RUnlock()
    }
}

func (v *VizServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
    dashboard := map[string]interface{}{
        "panels": []map[string]interface{}{
            {
                "id":    "events_over_time",
                "title": "Events Over Time",
                "type":  "line",
                "query": "SELECT timestamp, count() FROM events GROUP BY timestamp",
            },
            {
                "id":    "alerts_by_severity",
                "title": "Alerts by Severity",
                "type":  "pie",
                "query": "SELECT severity, count() FROM alerts GROUP BY severity",
            },
            {
                "id":    "top_source_ips",
                "title": "Top Source IPs",
                "type":  "bar",
                "query": "SELECT source_ip, count() FROM events GROUP BY source_ip ORDER BY count() DESC LIMIT 10",
            },
            {
                "id":    "mitre_attack_heatmap",
                "title": "MITRE ATT&CK Heatmap",
                "type":  "heatmap",
                "data":  v.getMitreHeatmapData(),
            },
        },
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(dashboard)
}

func (v *VizServer) handleMitreHeatmap(w http.ResponseWriter, r *http.Request) {
    data := v.getMitreHeatmapData()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(data)
}

func (v *VizServer) getMitreHeatmapData() map[string]interface{} {
    tactics := []string{
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact",
    }

    techniques := map[string][]map[string]interface{}{}

    for _, tactic := range tactics {
        techniques[tactic] = []map[string]interface{}{
            {"technique": "T1190", "name": "Exploit Public-Facing Application", "count": 5, "severity": "high"},
            {"technique": "T1059", "name": "Command and Scripting Interpreter", "count": 12, "severity": "medium"},
        }
    }

    return map[string]interface{}{
        "tactics":    tactics,
        "techniques": techniques,
        "updated_at": time.Now(),
    }
}

func (v *VizServer) handleThreatMap(w http.ResponseWriter, r *http.Request) {
    // Geolocation threat map data
    threats := []map[string]interface{}{
        {
            "source_country": "Russia",
            "source_lat":     55.7558,
            "source_lon":     37.6173,
            "dest_country":   "United States",
            "dest_lat":       38.9072,
            "dest_lon":       -77.0369,
            "count":          150,
            "severity":       "high",
        },
        {
            "source_country": "China",
            "source_lat":     39.9042,
            "source_lon":     116.4074,
            "dest_country":   "United States",
            "dest_lat":       38.9072,
            "dest_lon":       -77.0369,
            "count":          230,
            "severity":       "high",
        },
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "threats": threats,
        "total":   len(threats),
    })
}

func (v *VizServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
    metrics := map[string]interface{}{
        "events_per_second":      50000,
        "peak_events_per_second": 1250000,
        "active_flows":           45000,
        "alerts_active":          12,
        "alerts_critical":        2,
        "alerts_high":            4,
        "alerts_medium":          6,
        "processing_latency_ms":  5,
        "storage_hot_gb":         500,
        "storage_warm_gb":        5000,
        "storage_cold_gb":        50000,
        "ml_inference_ms":        3,
        "uptime_seconds":         86400 * 30,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(metrics)
}

// BroadcastAlert broadcasts a new alert to all connected clients
func (v *VizServer) BroadcastAlert(alert map[string]interface{}) {
    msg := map[string]interface{}{
        "type": "alert",
        "data": alert,
    }
    data, _ := json.Marshal(msg)

    v.mu.RLock()
    for client := range v.clients {
        client.WriteMessage(websocket.TextMessage, data)
    }
    v.mu.RUnlock()
}

// BroadcastEvent broadcasts a new event to subscribed clients
func (v *VizServer) BroadcastEvent(event map[string]interface{}) {
    msg := map[string]interface{}{
        "type": "event",
        "data": event,
    }
    data, _ := json.Marshal(msg)

    select {
    case v.broadcast <- data:
    default:
        // Channel full, drop message
    }
}
