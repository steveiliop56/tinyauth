package auth

import (
	"slices"
	"strings"
	"tinyauth/internal/docker"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

func NewAuth(docker *docker.Docker, userList types.Users, oauthWhitelist []string) *Auth {
	return &Auth{
		Docker:         docker,
		Users:          userList,
		OAuthWhitelist: oauthWhitelist,
	}
}

type Auth struct {
	Users          types.Users
	Docker         *docker.Docker
	OAuthWhitelist []string
}

func (auth *Auth) GetUser(username string) *types.User {
	for _, user := range auth.Users {
		if user.Username == username {
			return &user
		}
	}
	return nil
}

func (auth *Auth) CheckPassword(user types.User, password string) bool {
	hashedPasswordErr := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	return hashedPasswordErr == nil
}

func (auth *Auth) EmailWhitelisted(emailSrc string) bool {
	if len(auth.OAuthWhitelist) == 0 {
		return true
	}
	for _, email := range auth.OAuthWhitelist {
		if email == emailSrc {
			return true
		}
	}
	return false
}

func (auth *Auth) CreateSessionCookie(c *gin.Context, data *types.SessionCookie) {
	log.Debug().Msg("Creating session cookie")
	sessions := sessions.Default(c)
	log.Debug().Msg("Setting session cookie")
	sessions.Set("username", data.Username)
	sessions.Set("provider", data.Provider)
	sessions.Save()
}

func (auth *Auth) DeleteSessionCookie(c *gin.Context) {
	log.Debug().Msg("Deleting session cookie")
	sessions := sessions.Default(c)
	sessions.Clear()
	sessions.Save()
}

func (auth *Auth) GetSessionCookie(c *gin.Context) (types.SessionCookie, error) {
	log.Debug().Msg("Getting session cookie")
	sessions := sessions.Default(c)

	cookieUsername := sessions.Get("username")
	cookieProvider := sessions.Get("provider")

	username, usernameOk := cookieUsername.(string)
	provider, providerOk := cookieProvider.(string)

	log.Debug().Str("username", username).Str("provider", provider).Msg("Parsed cookie")

	if !usernameOk || !providerOk {
		log.Warn().Msg("Session cookie invalid")
		return types.SessionCookie{}, nil
	}

	return types.SessionCookie{
		Username: username,
		Provider: provider,
	}, nil
}

func (auth *Auth) UserAuthConfigured() bool {
	return len(auth.Users) > 0
}

func (auth *Auth) ResourceAllowed(context types.UserContext, host string) (bool, error) {
	appId := strings.Split(host, ".")[0]
	containers, containersErr := auth.Docker.GetContainers()

	if containersErr != nil {
		return false, containersErr
	}

	log.Debug().Msg("Got containers")

	for _, container := range containers {
		inspect, inspectErr := auth.Docker.InspectContainer(container.ID)

		if inspectErr != nil {
			return false, inspectErr
		}

		containerName := strings.Split(inspect.Name, "/")[1]

		if containerName == appId {
			log.Debug().Str("container", containerName).Msg("Found container")

			labels := utils.GetTinyauthLabels(inspect.Config.Labels)

			log.Debug().Msg("Got labels")

			if context.OAuth && len(labels.OAuthWhitelist) != 0 {
				log.Debug().Msg("Checking OAuth whitelist")
				if slices.Contains(labels.OAuthWhitelist, context.Username) {
					return true, nil
				}
				return false, nil
			}

			if len(labels.Users) != 0 {
				log.Debug().Msg("Checking users")
				if slices.Contains(labels.Users, context.Username) {
					return true, nil
				}
				return false, nil
			}
		}

	}

	log.Debug().Msg("No matching container found, allowing access")

	return true, nil
}
