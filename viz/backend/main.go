package main

import (
    "fmt"
    "os"

    "github.com/aiguard/siem-xdr/viz/backend"
    "go.uber.org/zap"
)

func main() {
    logger, _ := zap.NewProduction()
    defer logger.Sync()

    port := 8051
    if p := os.Getenv("VIZ_PORT"); p != "" {
        fmt.Sscanf(p, "%d", &port)
    }

    server := backend.NewVizServer(logger)
    if err := server.Start(port); err != nil {
        logger.Fatal("Visualization server failed", zap.Error(err))
    }
}
