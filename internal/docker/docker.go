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

type Docker struct {
	Client  *client.Client
	Context context.Context
}

func NewDocker() (*Docker, error) {
	// Create a new docker client
	client, err := client.NewClientWithOpts(client.FromEnv)

	// Check if there was an error
	if err != nil {
		return nil, err
	}

	// Create the context
	ctx := context.Background()

	// Negotiate API version
	client.NegotiateAPIVersion(ctx)

	return &Docker{
		Client:  client,
		Context: ctx,
	}, nil
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

func (docker *Docker) GetLabels(id string, domain string) (types.Labels, error) {
	// Check if we have access to the Docker API
	isConnected := docker.DockerConnected()

	// If we don't have access, return an empty struct
	if !isConnected {
		log.Debug().Msg("Docker not connected, returning empty labels")
		return types.Labels{}, nil
	}

	// Get the containers
	log.Debug().Msg("Getting containers")

	containers, err := docker.GetContainers()

	// If there is an error, return false
	if err != nil {
		log.Error().Err(err).Msg("Error getting containers")
		return types.Labels{}, err
	}

	// Loop through the containers
	for _, container := range containers {
		// Inspect the container
		inspect, err := docker.InspectContainer(container.ID)

		// Check if there was an error
		if err != nil {
			log.Warn().Str("id", container.ID).Err(err).Msg("Error inspecting container, skipping")
			continue
		}

		// Get the labels
		log.Debug().Str("id", inspect.ID).Msg("Getting labels for container")

		labels, err := utils.GetLabels(inspect.Config.Labels)

		// Check if there was an error
		if err != nil {
			log.Warn().Str("id", container.ID).Err(err).Msg("Error getting container labels, skipping")
			continue
		}

		// Check if the labels match the id or the domain
		if strings.TrimPrefix(inspect.Name, "/") == id || labels.Domain == domain {
			log.Debug().Str("id", inspect.ID).Msg("Found matching container")
			return labels, nil
		}
	}

	log.Debug().Msg("No matching container found, returning empty labels")

	// If no matching container is found, return empty labels
	return types.Labels{}, nil
}
