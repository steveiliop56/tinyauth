package service

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

type AccessLog struct {
	Provider string
	Username string
	ClientIP string
	Success  bool
	Message  string
}

type AccessLogServiceConfig struct {
	LogFile string
	LogJson bool
}

type AccessLogService struct {
	config *AccessLogServiceConfig
	logger zerolog.Logger
}

func NewAccessLogService(config *AccessLogServiceConfig) *AccessLogService {
	return &AccessLogService{
		config: config,
	}
}

func (als *AccessLogService) Init() error {
	writers := make([]io.Writer, 0)

	if als.config.LogFile != "" {
		// We are not closing the file here since we will keep writing to it until interrupted
		file, err := os.OpenFile(als.config.LogFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0640)
		if err != nil {
			return err
		}
		writter := zerolog.ConsoleWriter(zerolog.ConsoleWriter{Out: file, TimeFormat: time.RFC3339, NoColor: true, PartsOrder: []string{
			"time", "level", "caller", "message",
		}})
		writter.FormatLevel = func(i any) string {
			return strings.ToUpper(fmt.Sprintf("[ %s ]", i))
		}
		writter.FormatCaller = func(i any) string {
			return fmt.Sprintf("%s:", i)
		}
		writter.FormatMessage = func(i any) string {
			return fmt.Sprintf("%s", i)
		}
		writter.FormatFieldName = func(i any) string {
			return fmt.Sprintf("%s=", i)
		}
		writter.FormatFieldValue = func(i any) string {
			return fmt.Sprintf("%s", i)
		}
		writers = append(writers, writter)
	}

	if !als.config.LogJson {
		writter := zerolog.ConsoleWriter(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})
		writers = append(writers, writter)
	} else {
		writers = append(writers, os.Stdout)
	}

	als.logger = zerolog.New(zerolog.MultiLevelWriter(writers...)).With().Caller().Logger()

	return nil
}

func (als *AccessLogService) Log(log AccessLog) {
	var event *zerolog.Event

	if log.Success {
		event = als.logger.Info()
	} else {
		event = als.logger.Warn()
	}

	event = event.
		Str("provider", log.Provider).
		Str("username", log.Username).
		Str("client_ip", log.ClientIP).
		Int64("time", time.Now().Unix()).
		Bool("success", log.Success)

	event.Msg(log.Message)
}
