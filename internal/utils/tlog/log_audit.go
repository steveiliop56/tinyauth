package tlog

import "github.com/gin-gonic/gin"

func AuditLoginSuccess(c *gin.Context, username, provider string) {
	Audit.Info().
		Str("event", "login").
		Str("result", "success").
		Str("username", username).
		Str("provider", provider).
		Str("ip", c.ClientIP()).
		Send()
}

func AuditLoginFailure(c *gin.Context, username, provider string) {
	Audit.Warn().
		Str("event", "login").
		Str("result", "failure").
		Str("username", username).
		Str("provider", provider).
		Str("ip", c.ClientIP()).
		Send()
}

func AuditLogout(c *gin.Context, username, provider string) {
	Audit.Info().
		Str("event", "logout").
		Str("result", "success").
		Str("username", username).
		Str("provider", provider).
		Str("ip", c.ClientIP()).
		Send()
}
