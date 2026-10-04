package middleware

import (
    "fmt"
    "net/http"
    "sync"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "go.uber.org/zap"
)

type clientRateLimit struct {
    count     int
    expiresAt time.Time
}

var (
    rateLimitMu sync.Mutex
    rateLimitMap = make(map[string]*clientRateLimit)
)

// RequestID adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
    return func(c *gin.Context) {
        requestID := c.GetHeader("X-Request-ID")
        if requestID == "" {
            requestID = uuid.New().String()
        }
        c.Set("request_id", requestID)
        c.Header("X-Request-ID", requestID)
        c.Next()
    }
}

// Logger logs each request
func Logger(logger *zap.Logger) gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        path := c.Request.URL.Path
        method := c.Request.Method

        c.Next()

        latency := time.Since(start)
        status := c.Writer.Status()
        size := c.Writer.Size()

        logger.Info("HTTP request",
            zap.String("method", method),
            zap.String("path", path),
            zap.Int("status", status),
            zap.Int("size", size),
            zap.Duration("latency", latency),
            zap.String("ip", c.ClientIP()),
            zap.String("request_id", c.GetString("request_id")),
        )
    }
}

// Recovery recovers from panics
func Recovery(logger *zap.Logger) gin.HandlerFunc {
    return func(c *gin.Context) {
        defer func() {
            if err := recover(); err != nil {
                logger.Error("Panic recovered",
                    zap.Any("error", err),
                    zap.String("path", c.Request.URL.Path),
                    zap.String("request_id", c.GetString("request_id")),
                )
                c.JSON(500, gin.H{"error": "Internal server error"})
                c.Abort()
            }
        }()
        c.Next()
    }
}

// CORS handles Cross-Origin Resource Sharing
func CORS(allowedOrigins []string) gin.HandlerFunc {
    return func(c *gin.Context) {
        origin := c.Request.Header.Get("Origin")
        allowed := false

        for _, o := range allowedOrigins {
            if o == "*" || o == origin {
                allowed = true
                break
            }
        }

        if allowed {
            c.Header("Access-Control-Allow-Origin", origin)
            c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
            c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Request-ID")
            c.Header("Access-Control-Max-Age", "86400")
        }

        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }

        c.Next()
    }
}

// RateLimiter implements per-IP in-memory rate limiting to protect against DoS and brute-force
func RateLimiter(requestsPerMinute int) gin.HandlerFunc {
    if requestsPerMinute <= 0 {
        requestsPerMinute = 1000
    }
    return func(c *gin.Context) {
        clientIP := c.ClientIP()
        now := time.Now()

        rateLimitMu.Lock()
        entry, exists := rateLimitMap[clientIP]
        if !exists || now.After(entry.expiresAt) {
            rateLimitMap[clientIP] = &clientRateLimit{
                count:     1,
                expiresAt: now.Add(time.Minute),
            }
            rateLimitMu.Unlock()
            c.Next()
            return
        }

        entry.count++
        if entry.count > requestsPerMinute {
            rateLimitMu.Unlock()
            c.Header("Retry-After", "60")
            c.JSON(http.StatusTooManyRequests, gin.H{
                "error": "Rate limit exceeded. Please slow down.",
            })
            c.Abort()
            return
        }
        rateLimitMu.Unlock()

        c.Next()
    }
}

// AuditLog logs security-relevant API actions
func AuditLog() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Log security-relevant actions
        method := c.Request.Method
        path := c.Request.URL.Path

        if method != "GET" {
            fmt.Printf("AUDIT: %s %s by user %s\n", method, path, c.GetString("user_id"))
        }

        c.Next()
    }
}
