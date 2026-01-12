package tlog

import "github.com/gin-gonic/gin"

// functions here use CallerSkipFrame to ensure correct caller info is logged

func AuditLoginSuccess(c *gin.Context, username, provider string) {
	Audit.Info().
		CallerSkipFrame(1).
		Str("event", "login").
		Str("result", "success").
		Str("username", username).
		Str("provider", provider).
		Str("ip", c.ClientIP()).
		Send()
}

func AuditLoginFailure(c *gin.Context, username, provider string, reason string) {
	Audit.Warn().
		CallerSkipFrame(1).
		Str("event", "login").
		Str("result", "failure").
		Str("username", username).
		Str("provider", provider).
		Str("ip", c.ClientIP()).
		Send()
}

func AuditLogout(c *gin.Context, username, provider string) {
	Audit.Info().
		CallerSkipFrame(1).
		Str("event", "logout").
		Str("result", "success").
		Str("username", username).
		Str("provider", provider).
		Str("ip", c.ClientIP()).
		Send()
}
