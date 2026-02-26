package main

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"github.com/steveiliop56/tinyauth/internal/utils"
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
			if len(args) == 0 {
				return errors.New("client name is required. use tinyauth oidc create <name>")
			}

			clientName := args[0]

			match, err := regexp.MatchString("^[a-zA-Z0-9-]*$", clientName)

			if !match || err != nil {
				return errors.New("client name can only contain alphanumeric characters and hyphens")
			}

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
