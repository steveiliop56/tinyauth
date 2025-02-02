package docker

import (
	"context"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func NewDocker() *Docker {
	return &Docker{}
}

type Docker struct {
	Client  *client.Client
	Context context.Context
}

func (docker *Docker) Init() error {
	apiClient, err := client.NewClientWithOpts(client.FromEnv)

	if err != nil {
		return err
	}

	docker.Context = context.Background()
	docker.Client = apiClient

	return nil
}

func (docker *Docker) GetContainers() ([]types.Container, error) {
	containers, err := docker.Client.ContainerList(docker.Context, container.ListOptions{})

	if err != nil {
		return nil, err
	}

	return containers, nil
}

func (docker *Docker) InspectContainer(containerId string) (types.ContainerJSON, error) {
	inspect, err := docker.Client.ContainerInspect(docker.Context, containerId)

	if err != nil {
		return types.ContainerJSON{}, err
	}

	return inspect, nil
}

func (docker *Docker) DockerConnected() bool {
	_, err := docker.Client.Ping(docker.Context)
	return err == nil
}
