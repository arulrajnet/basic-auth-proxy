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
        ).Level(zerolog.TraceLevel).With().Timestamp().Caller().Logger()

        // Read the LOG_LEVEL environment variable
        logLevel := strings.ToLower(os.Getenv("LOG_LEVEL"))

        // Set the logging level based on the environment variable
        switch logLevel {
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
                // Default to Info level if LOG_LEVEL is not set or is invalid
                zerolog.SetGlobalLevel(zerolog.InfoLevel)
                logger.Warn().Msg("Invalid or missing LOG_LEVEL environment variable, defaulting to INFO")
        }
}

// Expose a function to retrieve the logger.
func GetLogger() zerolog.Logger {
        return logger
}
