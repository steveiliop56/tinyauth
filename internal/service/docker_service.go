package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/decoders"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"go.uber.org/dig"

	container "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

var (
	ErrPingFailed = fmt.Errorf("failed to ping docker")
)

type DockerService struct {
	log     *logger.Logger
	client  *client.Client
	context context.Context

	apps map[string]model.App
}

type DockerServiceInput struct {
	dig.In

	Log  *logger.Logger
	Ctx  context.Context
	Ding *ding.Ding
}

func NewDockerService(i DockerServiceInput) (*DockerService, error) {
	service := &DockerService{
		log:     i.Log,
		context: i.Ctx,
		apps:    make(map[string]model.App),
	}

	service.log.App.Debug().Msg("Attempting to connect to Docker")

	if os.Getenv("DOCKER_HOST") == "" {
		cli, err := service.connect()
		if err != nil {
			if errors.Is(err, ErrPingFailed) {
				service.log.App.Debug().Msg("Docker not connected")
				return nil, nil
			}
			return nil, fmt.Errorf("failed to connect to docker: %w", err)
		}
		service.client = cli
	} else {
		exp := backoff.NewExponentialBackOff()
		exp.InitialInterval = 3 * time.Second
		exp.RandomizationFactor = 0.1
		exp.Multiplier = 1.5
		exp.Reset()

		operation := func() (*client.Client, error) {
			if service.client != nil {
				service.client.Close()
			}
			cli, err := service.connect()
			if err != nil {
				return nil, err
			}
			return cli, nil
		}

		cli, err := backoff.Retry(service.context, operation, backoff.WithBackOff(exp), backoff.WithMaxTries(3))

		if err != nil {
			if errors.Is(err, ErrPingFailed) {
				service.log.App.Debug().Msg("Docker not connected after retrying")
				return nil, nil
			}
			return nil, fmt.Errorf("failed to connect to docker after retrying: %w", err)
		}

		service.client = cli
	}

	// initial sync
	err := service.sync()

	if err != nil {
		return nil, fmt.Errorf("failed to do initial sync: %w", err)
	}

	service.log.App.Debug().Msg("Docker connected successfully")

	i.Ding.Go(service.monitor, ding.RingMajor)

	return service, nil
}

func (docker *DockerService) connect() (*client.Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())

	if err != nil {
		return nil, err
	}

	_, err = cli.Ping(docker.context)

	if err != nil {
		return nil, ErrPingFailed
	}

	return cli, nil
}

func (docker *DockerService) getContainers() ([]container.Summary, error) {
	return docker.client.ContainerList(docker.context, container.ListOptions{})
}

func (docker *DockerService) inspectContainer(containerId string) (container.InspectResponse, error) {
	return docker.client.ContainerInspect(docker.context, containerId)
}

func (docker *DockerService) sync() error {
	containers, err := docker.getContainers()
	if err != nil {
		return fmt.Errorf("failed to get containers: %w", err)
	}

	for _, ctr := range containers {
		labels, err := decoders.DecodeLabels[model.Apps](ctr.Labels, "apps")
		if err != nil {
			docker.log.App.Warn().Err(err).Str("container_id", ctr.ID).Msg("Failed to decode container labels, skipping")
			continue
		}
		for app, config := range labels.Apps {
			docker.apps[app] = config
		}
	}

	return nil
}

func (docker *DockerService) syncWithContainer(containerId string) error {
	ctr, err := docker.inspectContainer(containerId)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %w", err)
	}
	labels, err := decoders.DecodeLabels[model.Apps](ctr.Config.Labels, "apps")
	if err != nil {
		return fmt.Errorf("failed to decode container labels: %w", err)
	}
	for app, config := range labels.Apps {
		if !ctr.State.Running {
			delete(docker.apps, app)
			continue
		}
		docker.apps[app] = config
	}
	return nil
}
func (docker *DockerService) syncFromEvent(event events.Message) {
	docker.log.App.Debug().Msgf("Received event: %s", event.Action)

	switch event.Action {
	case events.ActionStart, events.ActionRestart, events.ActionStop, events.ActionKill:
		err := docker.syncWithContainer(event.Actor.ID)
		if err != nil {
			docker.log.App.Error().Err(err).Msg("Failed to update apps from event")
		}
	default:
		docker.log.App.Debug().Msgf("Ignoring event: %s", event.Action)
	}
}

func (docker *DockerService) buildEventsKV() filters.Args {
	vals := []string{"start", "restart", "stop", "kill"}
	kv := make([]filters.KeyValuePair, len(vals))
	for i, v := range vals {
		kv[i] = filters.KeyValuePair{
			Key:   "event",
			Value: v,
		}
	}
	return filters.NewArgs(kv...)
}

func (docker *DockerService) monitor(ctx context.Context) {
	defer docker.client.Close()

	stream, chErr := docker.client.Events(ctx, events.ListOptions{
		Filters: docker.buildEventsKV(),
	})

	for {
		select {
		case <-ctx.Done():
			docker.log.App.Debug().Msg("Shutting down docker monitor")
			return

		case event := <-stream:
			docker.syncFromEvent(event)

		case err := <-chErr:
			if err != nil {
				docker.log.App.Error().Err(err).Msg("Docker event stream failed")
				return
			}
		}
	}
}

func (docker *DockerService) Lookup(locator func(name string, app *model.App)) error {
	for app, config := range docker.apps {
		locator(app, &config)
	}

	return nil
}
