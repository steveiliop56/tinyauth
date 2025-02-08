package auth

import (
	"slices"
	"strings"
	"time"
	"tinyauth/internal/docker"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

func NewAuth(docker *docker.Docker, userList types.Users, oauthWhitelist []string, sessionExpiry int) *Auth {
	return &Auth{
		Docker:         docker,
		Users:          userList,
		OAuthWhitelist: oauthWhitelist,
		SessionExpiry:  sessionExpiry,
	}
}

type Auth struct {
	Users          types.Users
	Docker         *docker.Docker
	OAuthWhitelist []string
	SessionExpiry  int
}

func (auth *Auth) GetUser(username string) *types.User {
	// Loop through users and return the user if the username matches
	for _, user := range auth.Users {
		if user.Username == username {
			return &user
		}
	}
	return nil
}

func (auth *Auth) CheckPassword(user types.User, password string) bool {
	// Compare the hashed password with the password provided
	return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) == nil
}

func (auth *Auth) EmailWhitelisted(emailSrc string) bool {
	// If the whitelist is empty, allow all emails
	if len(auth.OAuthWhitelist) == 0 {
		return true
	}

	// Loop through the whitelist and return true if the email matches
	for _, email := range auth.OAuthWhitelist {
		if email == emailSrc {
			return true
		}
	}

	// If no emails match, return false
	return false
}

func (auth *Auth) CreateSessionCookie(c *gin.Context, data *types.SessionCookie) {
	log.Debug().Msg("Creating session cookie")

	// Get session
	sessions := sessions.Default(c)

	log.Debug().Msg("Setting session cookie")

	// Set data
	sessions.Set("username", data.Username)
	sessions.Set("provider", data.Provider)
	sessions.Set("expiry", time.Now().Add(time.Duration(auth.SessionExpiry)*time.Second).Unix())

	// Save session
	sessions.Save()
}

func (auth *Auth) DeleteSessionCookie(c *gin.Context) {
	log.Debug().Msg("Deleting session cookie")

	// Get session
	sessions := sessions.Default(c)

	// Clear session
	sessions.Clear()

	// Save session
	sessions.Save()
}

func (auth *Auth) GetSessionCookie(c *gin.Context) types.SessionCookie {
	log.Debug().Msg("Getting session cookie")

	// Get session
	sessions := sessions.Default(c)

	// Get data
	cookieUsername := sessions.Get("username")
	cookieProvider := sessions.Get("provider")
	cookieExpiry := sessions.Get("expiry")

	// Convert interfaces to correct types
	username, usernameOk := cookieUsername.(string)
	provider, providerOk := cookieProvider.(string)
	expiry, expiryOk := cookieExpiry.(int64)

	// Check if the cookie is invalid
	if !usernameOk || !providerOk || !expiryOk {
		log.Warn().Msg("Session cookie invalid")
		return types.SessionCookie{}
	}

	// Check if the cookie has expired
	if time.Now().Unix() > expiry {
		log.Warn().Msg("Session cookie expired")

		// If it has, delete it
		auth.DeleteSessionCookie(c)

		// Return empty cookie
		return types.SessionCookie{}
	}

	log.Debug().Str("username", username).Str("provider", provider).Int64("expiry", expiry).Msg("Parsed cookie")

	// Return the cookie
	return types.SessionCookie{
		Username: username,
		Provider: provider,
	}
}

func (auth *Auth) UserAuthConfigured() bool {
	// If there are users, return true
	return len(auth.Users) > 0
}

func (auth *Auth) ResourceAllowed(context types.UserContext, host string) (bool, error) {
	// Check if we have access to the Docker API
	isConnected := auth.Docker.DockerConnected()

	// If we don't have access, it is assumed that the user has access
	if !isConnected {
		log.Debug().Msg("Docker not connected, allowing access")
		return true, nil
	}

	// Get the app ID from the host
	appId := strings.Split(host, ".")[0]

	// Get the containers
	containers, containersErr := auth.Docker.GetContainers()

	// If there is an error, return false
	if containersErr != nil {
		return false, containersErr
	}

	log.Debug().Msg("Got containers")

	// Loop through the containers
	for _, container := range containers {
		// Inspect the container
		inspect, inspectErr := auth.Docker.InspectContainer(container.ID)

		// If there is an error, return false
		if inspectErr != nil {
			return false, inspectErr
		}

		// Get the container name (for some reason it is /name)
		containerName := strings.Split(inspect.Name, "/")[1]

		// There is a container with the same name as the app ID
		if containerName == appId {
			log.Debug().Str("container", containerName).Msg("Found container")

			// Get only the tinyauth labels in a struct
			labels := utils.GetTinyauthLabels(inspect.Config.Labels)

			log.Debug().Msg("Got labels")

			// If the container has an oauth whitelist, check if the user is in it
			if context.OAuth && len(labels.OAuthWhitelist) != 0 {
				log.Debug().Msg("Checking OAuth whitelist")
				if slices.Contains(labels.OAuthWhitelist, context.Username) {
					return true, nil
				}
				return false, nil
			}

			// If the container has users, check if the user is in it
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

	// If no matching container is found, allow access
	return true, nil
}

func (auth *Auth) GetBasicAuth(c *gin.Context) types.User {
	// Get the Authorization header
	header := c.GetHeader("Authorization")

	// If the header is empty, return an empty user
	if header == "" {
		return types.User{}
	}

	// Split the header
	headerSplit := strings.Split(header, " ")

	if len(headerSplit) != 2 {
		return types.User{}
	}

	// Check if the header is Basic
	if headerSplit[0] != "Basic" {
		return types.User{}
	}

	// Split the credentials
	credentials := strings.Split(headerSplit[1], ":")

	// If the credentials are not in the correct format, return an empty user
	if len(credentials) != 2 {
		return types.User{}
	}

	// Return the user
	return types.User{
		Username: credentials[0],
		Password: credentials[1],
	}
}
