package docker

import (
	"context"
	"strings"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	container "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/rs/zerolog/log"
)

func NewDocker() *Docker {
	return &Docker{}
}

type Docker struct {
	Client  *client.Client
	Context context.Context
}

func (docker *Docker) Init() error {
	// Create a new docker client
	client, err := client.NewClientWithOpts(client.FromEnv)

	// Check if there was an error
	if err != nil {
		return err
	}

	// Set the context and api client
	docker.Context = context.Background()
	docker.Client = client

	// Done
	return nil
}

func (docker *Docker) GetContainers() ([]container.Summary, error) {
	// Get the list of containers
	containers, err := docker.Client.ContainerList(docker.Context, container.ListOptions{})

	// Check if there was an error
	if err != nil {
		return nil, err
	}

	// Return the containers
	return containers, nil
}

func (docker *Docker) InspectContainer(containerId string) (container.InspectResponse, error) {
	// Inspect the container
	inspect, err := docker.Client.ContainerInspect(docker.Context, containerId)

	// Check if there was an error
	if err != nil {
		return container.InspectResponse{}, err
	}

	// Return the inspect
	return inspect, nil
}

func (docker *Docker) DockerConnected() bool {
	// Ping the docker client if there is an error it is not connected
	_, err := docker.Client.Ping(docker.Context)
	return err == nil
}

func (docker *Docker) GetLabels(appId string) (types.TinyauthLabels, error) {
	// Check if we have access to the Docker API
	isConnected := docker.DockerConnected()

	// If we don't have access, return an empty struct
	if !isConnected {
		log.Debug().Msg("Docker not connected, returning empty labels")
		return types.TinyauthLabels{}, nil
	}

	// Get the containers
	containers, err := docker.GetContainers()

	// If there is an error, return false
	if err != nil {
		return types.TinyauthLabels{}, err
	}

	log.Debug().Msg("Got containers")

	// Loop through the containers
	for _, container := range containers {
		// Inspect the container
		inspect, err := docker.InspectContainer(container.ID)

		// If there is an error, return false
		if err != nil {
			return types.TinyauthLabels{}, err
		}

		// Get the container name (for some reason it is /name)
		containerName := strings.TrimPrefix(inspect.Name, "/")

		// There is a container with the same name as the app ID
		if containerName == appId {
			log.Debug().Str("container", containerName).Msg("Found container")

			// Get only the tinyauth labels in a struct
			labels := utils.GetTinyauthLabels(inspect.Config.Labels)

			log.Debug().Msg("Got labels")

			// Return labels
			return labels, nil
		}

	}

	log.Debug().Msg("No matching container found, returning empty labels")

	// If no matching container is found, return empty labels
	return types.TinyauthLabels{}, nil
}
