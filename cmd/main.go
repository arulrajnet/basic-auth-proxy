package main

import (
	"fmt"
	"os"
	"runtime"

	log "github.com/arulrajnet/basic-auth-proxy/pkg/logger"
	"github.com/arulrajnet/basic-auth-proxy/pkg/version"
	"github.com/spf13/pflag"
)

var logger = log.GetLogger()

func main() {
	configFlagSet := pflag.NewFlagSet("basic-auth-proxy", pflag.ContinueOnError)

	configFlagSet.ParseErrorsWhitelist.UnknownFlags = true

	showVersion := configFlagSet.Bool("version", false, "print version string")
	configFlagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("basic-auth-proxy %s (built with %s)\n", version.VERSION, runtime.Version())
		return
	}

}
