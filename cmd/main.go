package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime"

	"github.com/gorilla/mux"
	log "github.com/arulrajnet/basic-auth-proxy/pkg/logger"
	"github.com/arulrajnet/basic-auth-proxy/pkg/proxy"
	"github.com/arulrajnet/basic-auth-proxy/pkg/session"
	"github.com/arulrajnet/basic-auth-proxy/pkg/version"
	"github.com/spf13/pflag"
)

var logger = log.GetLogger()

func main() {
	configFlagSet := pflag.NewFlagSet("basic-auth-proxy", pflag.ContinueOnError)
	configFlagSet.ParseErrorsWhitelist.UnknownFlags = true

	configFile := configFlagSet.String("config", "config.yaml", "path to the configuration file")
	showVersion := configFlagSet.Bool("version", false, "print version string")

	configFlagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("basic-auth-proxy %s (built with %s)\n", version.VERSION, runtime.Version())
		return
	}

	cfg, err := proxy.LoadConfig(*configFile)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to load configuration")
		os.Exit(1)
	}

	sessionManager := session.NewSessionManager(cfg.Session.SecretKey)

	r := mux.NewRouter()

	// Login handler
	r.HandleFunc("/login", proxy.LoginPageHandler(&cfg.LoginPage, sessionManager)).Methods("GET")
	r.HandleFunc("/login", proxy.LoginHandler(cfg, sessionManager)).Methods("POST")

	// Proxy handler
	r.PathPrefix("/").Handler(proxy.NewProxy(cfg, sessionManager))

	logger.Info().Msg("Starting basic-auth-proxy")
	addr := fmt.Sprintf("%s:%d", cfg.Proxy.Address, cfg.Proxy.Port)
	logger.Info().Msgf("Listening on %s", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	if err := server.ListenAndServe(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start server")
		os.Exit(1)
	}
}
