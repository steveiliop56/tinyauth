package main

import (
	"os"
	"time"
	"tinyauth/cmd"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Logger
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Timestamp().Logger().Level(zerolog.FatalLevel)

	// Run cmd
	cmd.Execute()
}
