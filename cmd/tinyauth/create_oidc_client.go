package main

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/steveiliop56/tinyauth/internal/utils"
	"github.com/steveiliop56/tinyauth/internal/utils/tlog"
	"github.com/traefik/paerser/cli"
)

func createOidcClientCmd() *cli.Command {
	return &cli.Command{
		Name:          "create",
		Description:   "Create a new OIDC Client",
		Configuration: nil,
		Resources:     nil,
		AllowArg:      true,
		Run: func(args []string) error {
			tlog.NewSimpleLogger().Init()

			if len(args) == 0 {
				tlog.App.Fatal().Msg("Client name is required. Use tinyauth oidc create <name>")
			}

			clientName := args[0]

			uuid := uuid.New()
			clientId := uuid.String()
			clientSecret := "ta-" + utils.GenerateString(61)

			fmt.Printf("Client Name: %s\n", clientName)
			fmt.Printf("Client ID: %s\n", clientId)
			fmt.Printf("Client Secret: %s\n", clientSecret)
			return nil
		},
	}
}
