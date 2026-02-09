package main

import (
	"embed"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	log "github.com/arulrajnet/basic-auth-proxy/pkg/logger"
	"github.com/arulrajnet/basic-auth-proxy/pkg/proxy"
	"github.com/arulrajnet/basic-auth-proxy/pkg/session"
	"github.com/arulrajnet/basic-auth-proxy/pkg/version"
	"github.com/gorilla/mux"
	"github.com/spf13/pflag"
)

//go:embed static/*
var staticFiles embed.FS

var logger = log.GetLogger()

func main() {
	// Define command line flags
	configFile := pflag.StringP("config", "c", "", "path to the configuration file")
	showVersion := pflag.BoolP("version", "v", false, "print version string")
	help := pflag.BoolP("help", "h", false, "show this help message")
	logLevel := pflag.StringP("log-level", "l", "info", "set the log level (trace, debug, info, warn, error, fatal, panic)")

	// Define other flags (viper will read these)
	pflag.StringP("address", "a", "", "address to listen on")
	pflag.IntP("port", "p", 0, "port to listen on")
	pflag.StringP("proxy-prefix", "P", "", "prefix path for the proxy")
	pflag.BoolP("trust-upstream", "t", false, "trust upstream proxy (preserve X-Forwarded-For and X-Real-IP)")
	pflag.StringP("upstream", "u", "", "upstream server URL")
	pflag.StringP("cookie-name", "s", "", "cookie name")
	pflag.StringP("cookie-secret", "S", "", "cookie secret key")
	pflag.StringP("cookie-block", "B", "", "cookie block key (encryption key, must be 32 bytes)")
	pflag.StringP("logo", "L", "", "Path or URL for the login page logo")
	pflag.StringP("template-dir", "T", "", "path to custom login template")
	pflag.StringP("footer-text", "f", "", "footer text for the login page")

	// Parse command line flags
	pflag.Parse()

	// Show help message if requested
	if *help {
		fmt.Fprintf(os.Stderr, "Basic Auth Proxy version %s\n\n", version.VERSION)
		fmt.Fprintf(os.Stderr, "Usage: basic-auth-proxy [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		pflag.PrintDefaults()
		os.Exit(0)
	}

	// Show version if requested
	if *showVersion {
		fmt.Printf("basic-auth-proxy %s (built with %s)\n", version.VERSION, runtime.Version())
		os.Exit(0)
	}

	// Set log level from flag (this will be overridden by config if set there)
	if *logLevel != "" {
		log.SetLogLevel(*logLevel)
	}

	// Load configuration
	cfg, err := proxy.LoadConfig(*configFile)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to load configuration")
		os.Exit(1)
	}

	// Set log level from config
	log.SetLogLevel(cfg.LogLevel)

	// Create session manager
	sessionManager := session.NewSessionManager(cfg.Cookie.SecretKey, cfg.Cookie.BlockKey)

	// Create proxy handler for auth routes (this is the same proxy instance used by middleware)
	proxyHandler := proxy.NewProxy(cfg, sessionManager)
	proxyHandler.SetStaticFiles(staticFiles)

	// Setup router
	r := mux.NewRouter()
	r.Use(proxy.RequestLogger(logger))

	// Add auth routes
	authPrefix := cfg.Proxy.ProxyPrefix
	if authPrefix == "" {
		authPrefix = "/auth"
	}
	authPrefix = strings.TrimSuffix(authPrefix, "/")

	// Auth routes (these bypass session middleware check)
	// r.PathPrefix(authPrefix + "/").Handler(proxyHandler)
	r.PathPrefix("/").Handler(proxyHandler)

	// Create server
	addr := fmt.Sprintf("%s:%d", cfg.Proxy.Address, cfg.Proxy.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  time.Duration(cfg.Proxy.Timeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Proxy.Timeout) * time.Second,
	}

	// Start server
	logger.Info().Str("version", version.VERSION).Msg("Starting Basic Auth Proxy")
	logger.Info().Str("address", addr).Msg("Listening on")
	if err := server.ListenAndServe(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start server")
		os.Exit(1)
	}
}
