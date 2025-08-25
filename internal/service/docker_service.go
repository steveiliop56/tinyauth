package service

import (
	"context"
	"strings"
	"tinyauth/internal/config"
	"tinyauth/internal/utils"

	container "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/rs/zerolog/log"
)

type DockerService struct {
	Client  *client.Client
	Context context.Context
}

func NewDockerService() *DockerService {
	return &DockerService{}
}

func (docker *DockerService) Init() error {
	client, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}

	ctx := context.Background()
	client.NegotiateAPIVersion(ctx)
	return nil
}

func (docker *DockerService) GetContainers() ([]container.Summary, error) {
	containers, err := docker.Client.ContainerList(docker.Context, container.ListOptions{})
	if err != nil {
		return nil, err
	}
	return containers, nil
}

func (docker *DockerService) InspectContainer(containerId string) (container.InspectResponse, error) {
	inspect, err := docker.Client.ContainerInspect(docker.Context, containerId)
	if err != nil {
		return container.InspectResponse{}, err
	}
	return inspect, nil
}

func (docker *DockerService) DockerConnected() bool {
	_, err := docker.Client.Ping(docker.Context)
	return err == nil
}

func (docker *DockerService) GetLabels(app string, domain string) (config.Labels, error) {
	isConnected := docker.DockerConnected()

	if !isConnected {
		log.Debug().Msg("Docker not connected, returning empty labels")
		return config.Labels{}, nil
	}

	log.Debug().Msg("Getting containers")

	containers, err := docker.GetContainers()
	if err != nil {
		log.Error().Err(err).Msg("Error getting containers")
		return config.Labels{}, err
	}

	for _, container := range containers {
		inspect, err := docker.InspectContainer(container.ID)
		if err != nil {
			log.Warn().Str("id", container.ID).Err(err).Msg("Error inspecting container, skipping")
			continue
		}

		log.Debug().Str("id", inspect.ID).Msg("Getting labels for container")

		labels, err := utils.GetLabels(inspect.Config.Labels)
		if err != nil {
			log.Warn().Str("id", container.ID).Err(err).Msg("Error getting container labels, skipping")
			continue
		}

		// Check if the container matches the ID or domain
		for _, lDomain := range labels.Domain {
			if lDomain == domain {
				log.Debug().Str("id", inspect.ID).Msg("Found matching container by domain")
				return labels, nil
			}
		}

		if strings.TrimPrefix(inspect.Name, "/") == app {
			log.Debug().Str("id", inspect.ID).Msg("Found matching container by name")
			return labels, nil
		}
	}

	log.Debug().Msg("No matching container found, returning empty labels")
	return config.Labels{}, nil
}
