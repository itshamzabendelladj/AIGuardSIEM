package orchestrator

import (
    "context"
    "fmt"
    "sync"
    "time"

    "go.uber.org/zap"
)

// Config holds orchestrator configuration
type Config struct {
    EtcdEndpoints   []string
    ConsulEndpoint  string
    HealthCheckInterval int
    AutoScaleEnabled   bool
}

// ServiceInfo represents a registered service
type ServiceInfo struct {
    Name      string            `json:"name"`
    Host      string            `json:"host"`
    Port      int               `json:"port"`
    Status    string            `json:"status"`
    Health    string            `json:"health"`
    Metadata  map[string]string `json:"metadata"`
    LastSeen  time.Time         `json:"last_seen"`
    Instances int               `json:"instances"`
}

// Orchestrator manages service discovery, health monitoring, and auto-scaling
type Orchestrator struct {
    config     Config
    logger     *zap.Logger
    services   map[string]*ServiceInfo
    mu         sync.RWMutex
    ready      bool
    ctx        context.Context
    cancel     context.CancelFunc
    wg         sync.WaitGroup
}

// NewOrchestrator creates a new service orchestrator
func NewOrchestrator(config Config, logger *zap.Logger) (*Orchestrator, error) {
    ctx, cancel := context.WithCancel(context.Background())

    o := &Orchestrator{
        config:   config,
        logger:   logger,
        services: make(map[string]*ServiceInfo),
        ctx:      ctx,
        cancel:   cancel,
    }

    // Register default services
    o.registerDefaultServices()

    return o, nil
}

func (o *Orchestrator) registerDefaultServices() {
    defaults := []ServiceInfo{
        {Name: "syslog-collector", Port: 514, Status: "registered", Health: "unknown"},
        {Name: "pcap-collector", Port: 2055, Status: "registered", Health: "unknown"},
        {Name: "netflow-collector", Port: 2055, Status: "registered", Health: "unknown"},
        {Name: "stream-processor", Port: 9090, Status: "registered", Health: "unknown"},
        {Name: "rule-engine", Port: 9091, Status: "registered", Health: "unknown"},
        {Name: "ml-inference", Port: 9092, Status: "registered", Health: "unknown"},
        {Name: "storage-hot", Port: 9093, Status: "registered", Health: "unknown"},
        {Name: "storage-warm", Port: 9094, Status: "registered", Health: "unknown"},
        {Name: "api-gateway", Port: 8080, Status: "registered", Health: "unknown"},
        {Name: "ueba-engine", Port: 9095, Status: "registered", Health: "unknown"},
        {Name: "soar-engine", Port: 9096, Status: "registered", Health: "unknown"},
    }

    for _, svc := range defaults {
        s := svc
        s.LastSeen = time.Now()
        o.services[s.Name] = &s
    }
}

// Start starts the orchestrator
func (o *Orchestrator) Start() error {
    o.logger.Info("Starting orchestrator")

    // Start health check loop
    o.wg.Add(1)
    go o.healthCheckLoop()

    // Start auto-scaling loop
    if o.config.AutoScaleEnabled {
        o.wg.Add(1)
        go o.autoScaleLoop()
    }

    o.ready = true
    o.logger.Info("Orchestrator started")
    return nil
}

// Stop stops the orchestrator
func (o *Orchestrator) Stop() {
    o.logger.Info("Stopping orchestrator")
    o.cancel()
    o.wg.Wait()
    o.ready = false
    o.logger.Info("Orchestrator stopped")
}

// IsReady checks if the orchestrator is ready
func (o *Orchestrator) IsReady() bool {
    return o.ready
}

// ListServices returns all registered services
func (o *Orchestrator) ListServices() []*ServiceInfo {
    o.mu.RLock()
    defer o.mu.RUnlock()

    result := make([]*ServiceInfo, 0, len(o.services))
    for _, svc := range o.services {
        result = append(result, svc)
    }
    return result
}

// GetServiceStatus returns status of all services
func (o *Orchestrator) GetServiceStatus() map[string]string {
    o.mu.RLock()
    defer o.mu.RUnlock()

    result := make(map[string]string)
    for name, svc := range o.services {
        result[name] = svc.Health
    }
    return result
}

// RestartService restarts a specific service
func (o *Orchestrator) RestartService(name string) error {
    o.mu.Lock()
    defer o.mu.Unlock()

    svc, ok := o.services[name]
    if !ok {
        return fmt.Errorf("service %s not found", name)
    }

    svc.Status = "restarting"
    o.logger.Info("Restarting service", zap.String("service", name))

    // In production, would trigger K8s deployment restart
    // or send restart signal to service

    return nil
}

// RegisterService registers a new service
func (o *Orchestrator) RegisterService(svc ServiceInfo) {
    o.mu.Lock()
    defer o.mu.Unlock()

    svc.LastSeen = time.Now()
    svc.Status = "registered"
    o.services[svc.Name] = &svc
    o.logger.Info("Service registered", zap.String("service", svc.Name))
}

// DeregisterService removes a service
func (o *Orchestrator) DeregisterService(name string) {
    o.mu.Lock()
    defer o.mu.Unlock()

    delete(o.services, name)
    o.logger.Info("Service deregistered", zap.String("service", name))
}

func (o *Orchestrator) healthCheckLoop() {
    defer o.wg.Done()

    interval := time.Duration(o.config.HealthCheckInterval) * time.Second
    if interval == 0 {
        interval = 30 * time.Second
    }

    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-o.ctx.Done():
            return
        case <-ticker.C:
            o.performHealthChecks()
        }
    }
}

func (o *Orchestrator) performHealthChecks() {
    o.mu.Lock()
    defer o.mu.Unlock()

    for name, svc := range o.services {
        // In production, would make HTTP/gRPC health check calls
        // For now, just update last seen
        svc.LastSeen = time.Now()

        // Mark unhealthy if not seen in 90 seconds
        if time.Since(svc.LastSeen) > 90*time.Second {
            svc.Health = "unhealthy"
            o.logger.Warn("Service unhealthy", zap.String("service", name))
        } else {
            svc.Health = "healthy"
        }
    }
}

func (o *Orchestrator) autoScaleLoop() {
    defer o.wg.Done()

    ticker := time.NewTicker(60 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-o.ctx.Done():
            return
        case <-ticker.C:
            o.evaluateScaling()
        }
    }
}

func (o *Orchestrator) evaluateScaling() {
    o.mu.RLock()
    defer o.mu.RUnlock()

    // In production, would evaluate metrics and scale services
    // using Kubernetes HPA or custom scaling logic
    for name, svc := range o.services {
        if svc.Health == "unhealthy" {
            o.logger.Info("Auto-scaling: considering scale-up for unhealthy service",
                zap.String("service", name))
        }
    }
}
