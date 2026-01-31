package service

import (
	"context"
	"errors"
	"net"

	"github.com/steveiliop56/tinyauth/internal/utils/tlog"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tsnet"
)

var ErrNotConfigured = errors.New("tailscale service is not configured")

type TailscaleServiceConfig struct {
	AuthKey  string
	Hostname string
}

type TailscaleService struct {
	config TailscaleServiceConfig
	server *tsnet.Server
	client *local.Client
}

func NewTailscaleService(config TailscaleServiceConfig) *TailscaleService {
	return &TailscaleService{
		config: config,
	}
}

func (service *TailscaleService) Init() error {
	if !service.IsConfigured() {
		return nil
	}

	server := new(tsnet.Server)

	if service.config.AuthKey == "" {
		tlog.App.Info().Msg("Auth key is empty but Tailscale is configured, a login link will appear below so as you can authenticate")
	}

	server.Hostname = service.config.Hostname
	server.AuthKey = service.config.AuthKey

	client, err := server.LocalClient()

	if err != nil {
		return err
	}

	service.client = client
	service.server = server

	return nil
}

func (service *TailscaleService) IsConfigured() bool {
	return service.config.Hostname != ""
}

func (service *TailscaleService) Whois(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	if !service.IsConfigured() {
		return nil, ErrNotConfigured
	}

	return service.client.WhoIs(ctx, remoteAddr)
}

func (service *TailscaleService) CreateListener() (net.Listener, error) {
	if !service.IsConfigured() {
		return nil, ErrNotConfigured
	}

	ln, err := service.server.ListenTLS("tcp", ":443")

	if err != nil {
		return nil, err
	}

	return ln, nil
}
