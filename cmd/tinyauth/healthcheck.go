package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/steveiliop56/tinyauth/internal/utils"
	"github.com/traefik/paerser/cli"
)

type healthzResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func healthcheckCmd() *cli.Command {
	return &cli.Command{
		Name:          "healthcheck",
		Description:   "Perform a health check",
		Configuration: nil,
		Resources:     nil,
		AllowArg:      true,
		Run: func(args []string) error {
			utils.InitLogger(&utils.LoggerConfig{
				Level: "info",
				Json:  false,
			})

			appUrl := os.Getenv("TINYAUTH_APPURL")

			if len(args) > 0 {
				appUrl = args[0]
			}

			if appUrl == "" {
				return errors.New("TINYAUTH_APPURL is not set and no argument was provided")
			}

			utils.Log.App.Info().Str("app_url", appUrl).Msg("Performing health check")

			client := http.Client{
				Timeout: 30 * time.Second,
			}

			req, err := http.NewRequest("GET", appUrl+"/api/healthz", nil)

			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			resp, err := client.Do(req)

			if err != nil {
				return fmt.Errorf("failed to perform request: %w", err)
			}

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("service is not healthy, got: %s", resp.Status)
			}

			defer resp.Body.Close()

			var healthResp healthzResponse

			body, err := io.ReadAll(resp.Body)

			if err != nil {
				return fmt.Errorf("failed to read response: %w", err)
			}

			err = json.Unmarshal(body, &healthResp)

			if err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			utils.Log.App.Info().Interface("response", healthResp).Msg("Tinyauth is healthy")

			return nil
		},
	}
}
