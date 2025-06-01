package logger

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

var logger zerolog.Logger

// Initialize the logger with custom configurations.
func init() {
	// Customize output format (here we're using ConsoleWriter for human readability)
	logger = zerolog.New(
		zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339},
	).Level(zerolog.InfoLevel).With().Timestamp().Caller().Logger()

	// Default to Info level
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
}

// SetLogLevel sets the global log level based on a string
func SetLogLevel(level string) {
	switch strings.ToLower(level) {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	default:
		// Default to Info level if level is invalid
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		logger.Warn().Msgf("Invalid log level: %s, defaulting to INFO", level)
	}

	logger.Info().Msgf("Log level set to %s", strings.ToUpper(level))
}

// GetLogger returns the configured logger instance.
func GetLogger() zerolog.Logger {
	return logger
}
