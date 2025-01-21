package main

import (
	"os"
	"time"
	"tinyauth/cmd"
	"tinyauth/internal/assets"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Logger
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Timestamp().Logger()
	log.Info().Str("version", assets.Version).Msg("Starting tinyauth")
	
	// Run cmd
	cmd.Execute()
}
