package gateway

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/aiguard/siem-xdr/api/handlers"
    "github.com/aiguard/siem-xdr/api/middleware"
    "github.com/aiguard/siem-xdr/services/orchestrator"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "go.uber.org/zap"
)

// ServerConfig holds API gateway configuration
type ServerConfig struct {
    Port            int
    GRPCPort        int
    LogLevel        string
    JWTSecret       string
    AllowedOrigins  []string
    RateLimitPerMin int
    TLSCertFile     string
    TLSKeyFile      string
    EnableTLS       bool
}

// Server is the main API gateway
type Server struct {
    config      ServerConfig
    router      *gin.Engine
    orchestrator *orchestrator.Orchestrator
    logger      *zap.Logger
    httpServer  *http.Server
}

// NewServer creates a new API gateway server
func NewServer(config ServerConfig) (*Server, error) {
    // Initialize logger
    var logger *zap.Logger
    var err error
    if config.LogLevel == "debug" {
        logger, err = zap.NewDevelopment()
    } else {
        logger, err = zap.NewProduction()
    }
    if err != nil {
        return nil, fmt.Errorf("failed to create logger: %w", err)
    }

    // Initialize orchestrator
    orch, err := orchestrator.NewOrchestrator(orchestrator.Config{
        EtcdEndpoints: []string{"http://localhost:2379"},
    }, logger)
    if err != nil {
        return nil, fmt.Errorf("failed to create orchestrator: %w", err)
    }

    // Set gin mode
    if config.LogLevel != "debug" {
        gin.SetMode(gin.ReleaseMode)
    }

    router := gin.New()

    server := &Server{
        config:       config,
        router:       router,
        orchestrator: orch,
        logger:       logger,
    }

    server.setupRoutes()

    return server, nil
}

func (s *Server) setupRoutes() {
    // Middleware
    s.router.Use(middleware.RequestID())
    s.router.Use(middleware.Logger(s.logger))
    s.router.Use(middleware.Recovery(s.logger))
    s.router.Use(middleware.CORS(s.config.AllowedOrigins))
    s.router.Use(middleware.RateLimiter(s.config.RateLimitPerMin))

    // Health check
    s.router.GET("/health", handlers.HealthCheck)
    s.router.GET("/ready", handlers.ReadinessCheck(s.orchestrator))

    // Metrics endpoint
    s.router.GET("/metrics", gin.WrapH(promhttp.Handler()))

    // API v1 routes
    v1 := s.router.Group("/api/v1")
    {
        // Authentication
        auth := v1.Group("/auth")
        {
            auth.POST("/login", handlers.Login(s.config.JWTSecret))
            auth.POST("/refresh", handlers.RefreshToken(s.config.JWTSecret))
            auth.POST("/logout", middleware.Auth(s.config.JWTSecret), handlers.Logout)
        }

        // Protected routes
        protected := v1.Group("")
        protected.Use(middleware.Auth(s.config.JWTSecret))
        {
            // Alerts
            alerts := protected.Group("/alerts")
            {
                alerts.GET("", handlers.ListAlerts)
                alerts.GET("/:id", handlers.GetAlert)
                alerts.POST("", handlers.CreateAlert)
                alerts.PUT("/:id", handlers.UpdateAlert)
                alerts.DELETE("/:id", handlers.DeleteAlert)
                alerts.POST("/:id/acknowledge", handlers.AcknowledgeAlert)
                alerts.POST("/:id/resolve", handlers.ResolveAlert)
                alerts.GET("/stream", handlers.StreamAlerts)
            }

            // Events
            events := protected.Group("/events")
            {
                events.GET("", handlers.ListEvents)
                events.GET("/:id", handlers.GetEvent)
                events.POST("/search", handlers.SearchEvents)
                events.POST("/aggregate", handlers.AggregateEvents)
            }

            // Rules
            rules := protected.Group("/rules")
            {
                rules.GET("", handlers.ListRules)
                rules.GET("/:id", handlers.GetRule)
                rules.POST("", handlers.CreateRule)
                rules.PUT("/:id", handlers.UpdateRule)
                rules.DELETE("/:id", handlers.DeleteRule)
                rules.POST("/reload", handlers.ReloadRules)
            }

            // Cases (Incident Response)
            cases := protected.Group("/cases")
            {
                cases.GET("", handlers.ListCases)
                cases.GET("/:id", handlers.GetCase)
                cases.POST("", handlers.CreateCase)
                cases.PUT("/:id", handlers.UpdateCase)
                cases.POST("/:id/assign", handlers.AssignCase)
                cases.POST("/:id/close", handlers.CloseCase)
                cases.GET("/:id/timeline", handlers.GetCaseTimeline)
            }

            // Dashboards
            dashboards := protected.Group("/dashboards")
            {
                dashboards.GET("", handlers.ListDashboards)
                dashboards.GET("/:id", handlers.GetDashboard)
                dashboards.POST("", handlers.CreateDashboard)
                dashboards.PUT("/:id", handlers.UpdateDashboard)
                dashboards.DELETE("/:id", handlers.DeleteDashboard)
            }

            // Threat Intelligence
            threatIntel := protected.Group("/threat-intel")
            {
                threatIntel.GET("/indicators", handlers.ListIndicators)
                threatIntel.POST("/indicators", handlers.CreateIndicator)
                threatIntel.GET("/feeds", handlers.ListThreatFeeds)
                threatIntel.POST("/feeds", handlers.CreateThreatFeed)
            }

            // Agents
            agents := protected.Group("/agents")
            {
                agents.GET("", handlers.ListAgents)
                agents.GET("/:id", handlers.GetAgent)
                agents.POST("/:id/isolate", handlers.IsolateAgent)
                agents.POST("/:id/unisolate", handlers.UnisolateAgent)
                agents.GET("/:id/actions", handlers.GetAgentActions)
            }

            // Cloud connectors
            cloud := protected.Group("/cloud")
            {
                cloud.GET("/accounts", handlers.ListCloudAccounts)
                cloud.POST("/accounts", handlers.AddCloudAccount)
                cloud.GET("/accounts/:id/findings", handlers.GetCloudFindings)
            }

            // Playbooks (SOAR)
            playbooks := protected.Group("/playbooks")
            {
                playbooks.GET("", handlers.ListPlaybooks)
                playbooks.GET("/:id", handlers.GetPlaybook)
                playbooks.POST("", handlers.CreatePlaybook)
                playbooks.POST("/:id/execute", handlers.ExecutePlaybook)
            }

            // Users and RBAC
            users := protected.Group("/users")
            {
                users.GET("", handlers.ListUsers)
                users.POST("", handlers.CreateUser)
                users.PUT("/:id", handlers.UpdateUser)
                users.DELETE("/:id", handlers.DeleteUser)
                users.GET("/:id/roles", handlers.GetUserRoles)
                users.PUT("/:id/roles", handlers.AssignUserRoles)
            }

            // System
            system := protected.Group("/system")
            {
                system.GET("/status", handlers.GetSystemStatus(s.orchestrator))
                system.GET("/services", handlers.ListServices(s.orchestrator))
                system.POST("/services/:name/restart", handlers.RestartService(s.orchestrator))
                system.GET("/config", handlers.GetSystemConfig)
                system.PUT("/config", handlers.UpdateSystemConfig)
                system.GET("/audit-log", handlers.GetAuditLog)
            }
        }
    }

    s.logger.Info("Routes configured")
}

// Start starts the API gateway server
func (s *Server) Start() error {
    s.httpServer = &http.Server{
        Addr:         fmt.Sprintf(":%d", s.config.Port),
        Handler:      s.router,
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    // Start orchestrator
    if err := s.orchestrator.Start(); err != nil {
        return fmt.Errorf("failed to start orchestrator: %w", err)
    }

    // Handle graceful shutdown
    go func() {
        sigChan := make(chan os.Signal, 1)
        signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
        <-sigChan

        s.logger.Info("Shutting down API gateway...")

        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()

        s.orchestrator.Stop()
        s.httpServer.Shutdown(ctx)
    }()

    s.logger.Info("Starting AIGuardSIEM API Gateway", zap.Int("port", s.config.Port))

    if s.config.EnableTLS {
        return s.httpServer.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
    }
    return s.httpServer.ListenAndServe()
}

// Stop stops the server
func (s *Server) Stop() {
    if s.httpServer != nil {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        s.httpServer.Shutdown(ctx)
    }
    if s.orchestrator != nil {
        s.orchestrator.Stop()
    }
    s.logger.Sync()
}
