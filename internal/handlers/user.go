package handlers

import (
	"fmt"
	"strings"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
)

func (h *Handlers) LoginHandler(c *gin.Context) {
	var login types.LoginRequest

	err := c.BindJSON(&login)
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind JSON")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	log.Debug().Msg("Got login request")

	clientIP := c.ClientIP()

	// Create an identifier for rate limiting (username or IP if username doesn't exist yet)
	rateIdentifier := login.Username
	if rateIdentifier == "" {
		rateIdentifier = clientIP
	}

	// Check if the account is locked due to too many failed attempts
	locked, remainingTime := h.Auth.IsAccountLocked(rateIdentifier)
	if locked {
		log.Warn().Str("identifier", rateIdentifier).Int("remaining_seconds", remainingTime).Msg("Account is locked due to too many failed login attempts")
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", remainingTime),
		})
		return
	}

	// Search for a user based on username
	log.Debug().Interface("username", login.Username).Msg("Searching for user")

	userSearch := h.Auth.SearchUser(login.Username)

	// User does not exist
	if userSearch.Type == "" {
		log.Debug().Str("username", login.Username).Msg("User not found")
		// Record failed login attempt
		h.Auth.RecordLoginAttempt(rateIdentifier, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Debug().Msg("Got user")

	// Check if password is correct
	if !h.Auth.VerifyUser(userSearch, login.Password) {
		log.Debug().Str("username", login.Username).Msg("Password incorrect")
		// Record failed login attempt
		h.Auth.RecordLoginAttempt(rateIdentifier, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Debug().Msg("Password correct, checking totp")

	// Record successful login attempt (will reset failed attempt counter)
	h.Auth.RecordLoginAttempt(rateIdentifier, true)

	// Check if user is using TOTP
	if userSearch.Type == "local" {
		// Get local user
		localUser := h.Auth.GetLocalUser(login.Username)

		// Check if TOTP is enabled
		if localUser.TotpSecret != "" {
			log.Debug().Msg("Totp enabled")

			// Set totp pending cookie
			h.Auth.CreateSessionCookie(c, &types.SessionCookie{
				Username:    login.Username,
				Name:        utils.Capitalize(login.Username),
				Email:       fmt.Sprintf("%s@%s", strings.ToLower(login.Username), h.Config.Domain),
				Provider:    "username",
				TotpPending: true,
			})

			// Return totp required
			c.JSON(200, gin.H{
				"status":      200,
				"message":     "Waiting for totp",
				"totpPending": true,
			})
			return
		}
	}

	// Create session cookie with username as provider
	h.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username: login.Username,
		Name:     utils.Capitalize(login.Username),
		Email:    fmt.Sprintf("%s@%s", strings.ToLower(login.Username), h.Config.Domain),
		Provider: "username",
	})

	// Return logged in
	c.JSON(200, gin.H{
		"status":      200,
		"message":     "Logged in",
		"totpPending": false,
	})
}

func (h *Handlers) TOTPHandler(c *gin.Context) {
	var totpReq types.TotpRequest

	err := c.BindJSON(&totpReq)
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind JSON")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	log.Debug().Msg("Checking totp")

	// Get user context
	userContextValue, exists := c.Get("context")

	if !exists {
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	userContext, ok := userContextValue.(*types.UserContext)

	if !ok {
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	// Check if we have a user
	if userContext.Username == "" {
		log.Debug().Msg("No user context")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	// Get user
	user := h.Auth.GetLocalUser(userContext.Username)

	// Check if totp is correct
	ok = totp.Validate(totpReq.Code, user.TotpSecret)

	if !ok {
		log.Debug().Msg("Totp incorrect")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Debug().Msg("Totp correct")

	// Create session cookie with username as provider
	h.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username: user.Username,
		Name:     utils.Capitalize(user.Username),
		Email:    fmt.Sprintf("%s@%s", strings.ToLower(user.Username), h.Config.Domain),
		Provider: "username",
	})

	// Return logged in
	c.JSON(200, gin.H{
		"status":  200,
		"message": "Logged in",
	})
}

func (h *Handlers) LogoutHandler(c *gin.Context) {
	log.Debug().Msg("Cleaning up redirect cookie")

	h.Auth.DeleteSessionCookie(c)

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Logged out",
	})
}
