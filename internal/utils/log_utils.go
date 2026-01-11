package utils

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Loggers struct {
	Audit zerolog.Logger
	HTTP  zerolog.Logger
	App   zerolog.Logger
}

// utils.Log.Access, utils.log.HTTP...
var Log *Loggers

type LoggerConfig struct {
	Level   string
	Json    bool
	Outputs map[string]LoggerOutputConfig
}

type LoggerOutputConfig struct {
	Enabled bool
	Level   string
}

// InitLogger initializes all loggers with the provided configuration
func InitLogger(cfg *LoggerConfig) error {
	if cfg == nil {
		return fmt.Errorf("logger config cannot be nil")
	}

	zerolog.SetGlobalLevel(parseLogLevel(cfg.Level))
	zerolog.TimeFieldFormat = time.RFC3339

	baseLogger := log.With().Timestamp().Caller().Logger()

	if !cfg.Json {
		baseLogger = baseLogger.Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339,
		})
	}

	// set as global logger
	log.Logger = baseLogger

	// create sub-loggers
	Log = &Loggers{
		Audit: createLogger("audit", cfg, baseLogger),
		HTTP:  createLogger("http", cfg, baseLogger),
		App:   createLogger("app", cfg, baseLogger),
	}

	return nil
}

func createLogger(loggerType string, cfg *LoggerConfig, baseLogger zerolog.Logger) zerolog.Logger {
	logCfg, exists := cfg.Outputs[loggerType]
	if !exists {
		logCfg = LoggerOutputConfig{
			Enabled: slices.Contains([]string{"http", "app"}, loggerType),
			Level:   "",
		}
	}

	if !logCfg.Enabled {
		return zerolog.Nop()
	}

	logger := baseLogger.With().Str("component", loggerType).Logger()
	if logCfg.Level != "" { // if log level is overriden
		logger = logger.Level(parseLogLevel(logCfg.Level))
	}
	return logger
}

// parseLogLevel parses a log level string
func parseLogLevel(level string) zerolog.Level {
	if level == "" {
		return zerolog.InfoLevel
	}
	parsedLevel, err := zerolog.ParseLevel(strings.ToLower(level))
	if err != nil {
		log.Warn().Err(err).Str("level", level).Msg("Invalid log level, defaulting to info")
		parsedLevel = zerolog.InfoLevel
	}
	return parsedLevel
}
