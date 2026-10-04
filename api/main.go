package main

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "os"
    "strings"

    "github.com/aiguard/siem-xdr/api/gateway"
    "go.uber.org/zap"
)

func main() {
    jwtSecret := os.Getenv("AIGUARD_JWT_SECRET")
    if jwtSecret == "" || jwtSecret == "dev-secret" {
        b := make([]byte, 32)
        if _, err := rand.Read(b); err == nil {
            jwtSecret = hex.EncodeToString(b)
            fmt.Fprintf(os.Stderr, "SECURITY WARNING: AIGUARD_JWT_SECRET not provided or insecure. Generated random ephemeral secret for this session.\n")
        } else {
            jwtSecret = "f8a1e2d3c4b5a697887766554433221100ffeeddccbbaa998877665544332211"
        }
    }

    allowedOrigins := []string{"http://localhost:3000", "http://localhost:8080"}
    if envOrigins := os.Getenv("AIGUARD_ALLOWED_ORIGINS"); envOrigins != "" {
        allowedOrigins = strings.Split(envOrigins, ",")
    }

    config := gateway.ServerConfig{
        Port:            getEnvInt("AIGUARD_API_PORT", 8080),
        GRPCPort:        getEnvInt("AIGUARD_GRPC_PORT", 9090),
        LogLevel:        getEnv("AIGUARD_LOG_LEVEL", "info"),
        JWTSecret:       jwtSecret,
        AllowedOrigins:  allowedOrigins,
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
