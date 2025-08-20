package handlers

import (
	"tinyauth/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (h *Handlers) AppContextHandler(c *gin.Context) {
	log.Debug().Msg("Getting app context")

	// Get configured providers
	configuredProviders := h.Providers.GetConfiguredProviders()

	// We have username/password configured so add it to our providers
	if h.Auth.UserAuthConfigured() {
		configuredProviders = append(configuredProviders, "username")
	}

	// Return app context
	appContext := types.AppContext{
		Status:                200,
		Message:               "OK",
		ConfiguredProviders:   configuredProviders,
		DisableContinue:       h.Config.DisableContinue,
		Title:                 h.Config.Title,
		GenericName:           h.Config.GenericName,
		Domain:                h.Config.Domain,
		ForgotPasswordMessage: h.Config.ForgotPasswordMessage,
		BackgroundImage:       h.Config.BackgroundImage,
		OAuthAutoRedirect:     h.Config.OAuthAutoRedirect,
	}
	c.JSON(200, appContext)
}

func (h *Handlers) UserContextHandler(c *gin.Context) {
	log.Debug().Msg("Getting user context")

	// Create user context using hooks
	userContext := h.Hooks.UseUserContext(c)

	userContextResponse := types.UserContextResponse{
		Status:      200,
		IsLoggedIn:  userContext.IsLoggedIn,
		Username:    userContext.Username,
		Name:        userContext.Name,
		Email:       userContext.Email,
		Provider:    userContext.Provider,
		Oauth:       userContext.OAuth,
		TotpPending: userContext.TotpPending,
	}

	// If we are not logged in we set the status to 401 else we set it to 200
	if !userContext.IsLoggedIn {
		log.Debug().Msg("Unauthorized")
		userContextResponse.Message = "Unauthorized"
	} else {
		log.Debug().Interface("userContext", userContext).Msg("Authenticated")
		userContextResponse.Message = "Authenticated"
	}

	c.JSON(200, userContextResponse)
}
