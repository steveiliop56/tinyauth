package middleware

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

var (
	loggerSkipPathsPrefix = []string{
		"GET /api/health",
		"HEAD /api/health",
		"GET /favicon.ico",
	}
)

type ZerologMiddleware struct{}

func NewZerologMiddleware() *ZerologMiddleware {
	return &ZerologMiddleware{}
}

func (m *ZerologMiddleware) Init() error {
	return nil
}

func (m *ZerologMiddleware) logPath(path string) bool {
	for _, prefix := range loggerSkipPathsPrefix {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	return true
}

func (m *ZerologMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tStart := time.Now()

		c.Next()

		code := c.Writer.Status()
		address := c.Request.RemoteAddr
		clientIP := c.ClientIP()
		method := c.Request.Method
		path := c.Request.URL.Path

		latency := time.Since(tStart).String()

		// logPath check if the path should be logged normally or with debug
		if m.logPath(method + " " + path) {
			switch {
			case code >= 200 && code < 300:
				log.Info().Str("method", method).Str("path", path).Str("address", address).Str("clientIp", clientIP).Int("status", code).Str("latency", latency).Msg("Request")
			case code >= 300 && code < 400:
				log.Warn().Str("method", method).Str("path", path).Str("address", address).Str("clientIp", clientIP).Int("status", code).Str("latency", latency).Msg("Request")
			case code >= 400:
				log.Error().Str("method", method).Str("path", path).Str("address", address).Str("clientIp", clientIP).Int("status", code).Str("latency", latency).Msg("Request")
			}
		} else {
			log.Debug().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
		}
	}
}
