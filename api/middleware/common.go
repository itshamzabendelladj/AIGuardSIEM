package middleware

import (
    "fmt"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"
    "go.uber.org/zap"
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

// RateLimiter implements Redis-based rate limiting per IP
func RateLimiter(redisClient *redis.Client, requestsPerMinute int) gin.HandlerFunc {
    return func(c *gin.Context) {
        if redisClient == nil {
            // Fallback if Redis is not configured
            c.Next()
            return
        }

        ip := c.ClientIP()
        key := fmt.Sprintf("rate_limit:%s", ip)
        ctx := c.Request.Context()

        // Increment the counter
        count, err := redisClient.Incr(ctx, key).Result()
        if err != nil {
            // Fallback to allowing request if Redis fails
            c.Next()
            return
        }

        // Set expiry on first request in the window
        if count == 1 {
            redisClient.Expire(ctx, key, time.Minute)
        }

        if int(count) > requestsPerMinute {
            c.AbortWithStatusJSON(429, gin.H{"error": "Too many requests"})
            return
        }

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
