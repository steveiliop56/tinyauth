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
	client  *client.Client
	context context.Context
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

	docker.client = client
	docker.context = ctx
	return nil
}

func (docker *DockerService) GetContainers() ([]container.Summary, error) {
	containers, err := docker.client.ContainerList(docker.context, container.ListOptions{})
	if err != nil {
		return nil, err
	}
	return containers, nil
}

func (docker *DockerService) InspectContainer(containerId string) (container.InspectResponse, error) {
	inspect, err := docker.client.ContainerInspect(docker.context, containerId)
	if err != nil {
		return container.InspectResponse{}, err
	}
	return inspect, nil
}

func (docker *DockerService) DockerConnected() bool {
	_, err := docker.client.Ping(docker.context)
	return err == nil
}

func (docker *DockerService) GetLabels(app string, domain string) (config.AppLabels, error) {
	isConnected := docker.DockerConnected()

	if !isConnected {
		log.Debug().Msg("Docker not connected, returning empty labels")
		return config.AppLabels{}, nil
	}

	containers, err := docker.GetContainers()
	if err != nil {
		return config.AppLabels{}, err
	}

	for _, container := range containers {
		inspect, err := docker.InspectContainer(container.ID)
		if err != nil {
			log.Warn().Str("id", container.ID).Err(err).Msg("Error inspecting container, skipping")
			continue
		}

		labels, err := utils.GetLabels(inspect.Config.Labels)
		if err != nil {
			log.Warn().Str("id", container.ID).Err(err).Msg("Error getting container labels, skipping")
			continue
		}

		for appName, appLabels := range labels.Apps {
			if appLabels.Config.Domain == domain {
				log.Debug().Str("id", inspect.ID).Msg("Found matching container by domain")
				return appLabels, nil
			}

			if strings.TrimPrefix(inspect.Name, "/") == appName {
				log.Debug().Str("id", inspect.ID).Msg("Found matching container by app name")
				return appLabels, nil
			}
		}
	}

	log.Debug().Msg("No matching container found, returning empty labels")
	return config.AppLabels{}, nil
}
