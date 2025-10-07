package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type healthzResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type healthcheckCmd struct {
	root *cobra.Command
	cmd  *cobra.Command

	viper *viper.Viper
}

func newHealthcheckCmd(root *cobra.Command) *healthcheckCmd {
	return &healthcheckCmd{
		root:  root,
		viper: viper.New(),
	}
}

func (c *healthcheckCmd) Register() {
	c.cmd = &cobra.Command{
		Use:   "healthcheck [app-url]",
		Short: "Perform a health check",
		Long:  `Use the health check endpoint to verify that Tinyauth is running and it's healthy.`,
		Run:   c.run,
	}

	c.viper.AutomaticEnv()

	if c.root != nil {
		c.root.AddCommand(c.cmd)
	}
}

func (c *healthcheckCmd) GetCmd() *cobra.Command {
	return c.cmd
}

func (c *healthcheckCmd) run(cmd *cobra.Command, args []string) {
	log.Logger = log.Level(zerolog.InfoLevel)

	var appUrl string

	port := c.viper.GetString("PORT")
	address := c.viper.GetString("ADDRESS")

	if port == "" {
		port = "3000"
	}

	if address == "" {
		address = "127.0.0.1"
	}

	appUrl = "http://" + address + ":" + port

	if len(args) > 0 {
		appUrl = args[0]
	}

	log.Info().Str("appUrl", appUrl).Msg("Performing health check")

	client := http.Client{}

	req, err := http.NewRequest("GET", appUrl+"/api/healthz", nil)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create request")
	}

	resp, err := client.Do(req)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to perform request")
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatal().Err(errors.New("service is not healthy")).Msgf("Service is not healthy. Status code: %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	var healthResp healthzResponse

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to read response")
	}

	err = json.Unmarshal(body, &healthResp)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to decode response")
	}

	log.Info().Interface("response", healthResp).Msg("Tinyauth is healthy")
}
