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
	// Create a new docker client
	apiClient, err := client.NewClientWithOpts(client.FromEnv)

	// Check if there was an error
	if err != nil {
		return err
	}

	// Set the context and api client
	docker.Context = context.Background()
	docker.Client = apiClient

	// Done
	return nil
}

func (docker *Docker) GetContainers() ([]types.Container, error) {
	// Get the list of containers
	containers, err := docker.Client.ContainerList(docker.Context, container.ListOptions{})

	// Check if there was an error
	if err != nil {
		return nil, err
	}

	// Return the containers
	return containers, nil
}

func (docker *Docker) InspectContainer(containerId string) (types.ContainerJSON, error) {
	// Inspect the container
	inspect, err := docker.Client.ContainerInspect(docker.Context, containerId)

	// Check if there was an error
	if err != nil {
		return types.ContainerJSON{}, err
	}

	// Return the inspect
	return inspect, nil
}

func (docker *Docker) DockerConnected() bool {
	// Ping the docker client if there is an error it is not connected
	_, err := docker.Client.Ping(docker.Context)
	return err == nil
}
