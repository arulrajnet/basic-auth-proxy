package main

import (
    "fmt"
    "net/http"
    "os"
    "runtime"

    log "github.com/arulrajnet/basic-auth-proxy/pkg/logger"
    "github.com/arulrajnet/basic-auth-proxy/pkg/version"
    "github.com/arulrajnet/basic-auth-proxy/pkg"
    "github.com/joho/godotenv"
    "github.com/spf13/pflag"
)

var logger = log.GetLogger()

func main() {
    err := godotenv.Load()
    if err != nil {
        logger.Fatal().Err(err).Msg("Error loading .env file")
    }

    configFlagSet := pflag.NewFlagSet("basic-auth-proxy", pflag.ContinueOnError)

    configFlagSet.ParseErrorsWhitelist.UnknownFlags = true

    showVersion := configFlagSet.Bool("version", false, "print version string")
    configFlagSet.Parse(os.Args[1:])

    if *showVersion {
        fmt.Printf("basic-auth-proxy %s (built with %s)\n", version.VERSION, runtime.Version())
        return
    }

    serverPort := os.Getenv("PORT")
    router := http.NewServeMux()

    router.HandleFunc("/sign_in", pkg.SignInPageHandler)

    logger.Info().Msgf("Listening on port: %s", serverPort)
    err = http.ListenAndServe(fmt.Sprintf("0.0.0.0:%s", serverPort), router)
    if err != nil {
        logger.Fatal().Err(err).Msg("Error starting the server")
    }
}