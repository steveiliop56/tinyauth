package main

import (
	"os"
	"time"
	"tinyauth/cmd"
	"tinyauth/internal/utils"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Logger.With().Caller().Logger()
	if !utils.ShouldLogJSON(os.Environ(), os.Args) {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	}
	cmd.Run()
}
