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































}	}		os.Exit(1)		logger.Fatal().Err(err).Msg("Failed to start server")	if err := server.ListenAndServe(); err != nil {	}		Handler: r,		Addr:    addr,	server := &http.Server{	logger.Info().Msgf("Listening on %s", addr)	addr := fmt.Sprintf("%s:%d", cfg.Proxy.Address, cfg.Proxy.Port)	logger.Info().Msg("Starting basic-auth-proxy")	r.PathPrefix("/").Handler(proxy.NewProxy(cfg, sessionManager))	// Proxy handler	r.HandleFunc("/login", proxy.LoginHandler(cfg, sessionManager)).Methods("POST")	r.HandleFunc("/login", proxy.LoginPageHandler(cfg.LoginPage, sessionManager)).Methods("GET")	//  Login handler	r := mux.NewRouter()	sessionManager := session.NewSessionManager(cfg.Session.SecretKey)	}		os.Exit(1)		logger.Fatal().Err(err).Msg("Failed to load configuration")	if err != nil {
