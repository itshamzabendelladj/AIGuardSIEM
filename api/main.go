package main

import (
    "fmt"
    "os"

    "github.com/aiguard/siem-xdr/api/gateway"
    "go.uber.org/zap"
)

func main() {
    config := gateway.ServerConfig{
        Port:            getEnvInt("AIGUARD_API_PORT", 8080),
        GRPCPort:        getEnvInt("AIGUARD_GRPC_PORT", 9090),
        LogLevel:        getEnv("AIGUARD_LOG_LEVEL", "info"),
        JWTSecret:       getEnv("AIGUARD_JWT_SECRET", "dev-secret"),
        AllowedOrigins:  []string{"*"},
        RateLimitPerMin: 1000,
        EnableTLS:       getEnv("AIGUARD_ENABLE_TLS", "false") == "true",
        TLSCertFile:     getEnv("AIGUARD_TLS_CERT", ""),
        TLSKeyFile:      getEnv("AIGUARD_TLS_KEY", ""),
    }

    server, err := gateway.NewServer(config)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to create server: %v\n", err)
        os.Exit(1)
    }

    if err := server.Start(); err != nil {
        zap.L().Error("Server failed", zap.Error(err))
        os.Exit(1)
    }
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
    if value := os.Getenv(key); value != "" {
        var i int
        if _, err := fmt.Sscanf(value, "%d", &i); err == nil {
            return i
        }
    }
    return defaultValue
}
