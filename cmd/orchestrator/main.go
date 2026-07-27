package main

import (
    "fmt"
    "os"
    "strings"

    "github.com/aiguard/siem-xdr/services/orchestrator"
    "go.uber.org/zap"
)

func main() {
    logger, _ := zap.NewProduction()
    defer logger.Sync()

    etcdEndpoints := strings.Split(getEnv("AIGUARD_ETCD_ENDPOINTS", "localhost:2379"), ",")

    config := orchestrator.Config{
        EtcdEndpoints:       etcdEndpoints,
        HealthCheckInterval: 30,
        AutoScaleEnabled:    true,
    }

    orch, err := orchestrator.NewOrchestrator(config, logger)
    if err != nil {
        logger.Fatal("Failed to create orchestrator", zap.Error(err))
    }

    if err := orch.Start(); err != nil {
        logger.Fatal("Failed to start orchestrator", zap.Error(err))
    }

    fmt.Println("AIGuardSIEM Orchestrator running. Press Ctrl+C to stop.")
    select {} // Block forever
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}
